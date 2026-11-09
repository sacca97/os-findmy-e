package com.sacca.openfinder.work

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.sacca.openfinder.MainActivity
import com.sacca.openfinder.R
import com.sacca.openfinder.OpenFinderApp
import com.sacca.openfinder.domain.AuthState
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.LocationReport
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * Background report fetch; the periodic interval is configured in OpenFinderApp.
 *
 * Contract: no session or no tags -> quiet success, the period is not
 * worth retrying; authentication failures notify once and never retry (only a human can log in
 * again); network/backend failures retry with backoff up to a few attempts within the window;
 * a 429 is recorded by the shared [Cooldown][com.sacca.openfinder.apple.Cooldown] and never loops.
 * Newest reports land in [LastReports]; strictly-newer sightings raise the location notification,
 * which never shows coordinates in its text.
 */
class FetchWorker(
    appContext: Context,
    params: WorkerParameters,
    private val lastReports: LastReports,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val container = (applicationContext as OpenFinderApp).container
        val backend = container.liveBackend
        Log.i(TAG, "background fetch starting (attempt $runAttemptCount)")

        val auth = runCatching { backend.getAuthState() }.getOrNull()
        if (auth != AuthState.Authenticated) {
            // Only nag when the app is set up (tags imported): a user who never signed in must not
            // receive recurring sign-in notifications for an app they only opened once.
            val hasTags = runCatching { backend.hasAccessories() }.getOrDefault(false)
            Log.i(TAG, "session=$auth, tags=$hasTags -> ${if (hasTags) "notify sign-in" else "quiet success"}")
            if (hasTags) Notifier(applicationContext).loginNeeded()
            return Result.success()
        }
        val hasAccessories = runCatching { backend.hasAccessories() }.getOrDefault(false)
        if (!hasAccessories) { Log.i(TAG, "signed in, no accessories -> quiet success"); return Result.success() }

        container.repository.refresh()
        val state = container.repository.state.value
        when (val error = state.error) {
            null -> {}
            is OpenFinderError.Network, is OpenFinderError.Backend, is OpenFinderError.Throttled -> {
                Log.i(TAG, "fetch failed: ${error::class.simpleName} -> ${if (runAttemptCount < MAX_RETRIES) "retry" else "give up"}")
                return if (runAttemptCount < MAX_RETRIES) Result.retry() else Result.success()
            }
            is OpenFinderError.Authentication -> {
                Log.i(TAG, "session rejected -> notify sign-in")
                Notifier(applicationContext).loginNeeded(); return Result.success()
            }
            // ReportsUnavailable with no report at hand is the quiet "nothing yet" case.
            else -> { Log.i(TAG, "fetch answered: ${error::class.simpleName}"); return Result.success() }
        }

        val named = state.accessories.mapNotNull { a -> a.latestReport?.let { Triple(a.id, a.name, it) } }
        val currentEntries = named.associate { (id, _, r) ->
            id to LastReportEntry(r.latitude, r.longitude, r.observedAt, r.horizontalAccuracyMeters)
        }
        if (currentEntries.isEmpty()) return Result.success()   // keep the previous file; an empty fetch overwrites nothing

        val previous = lastReports.read()
        val freshIds = LastReports.newerThan(previous, currentEntries).keys
        lastReports.write(currentEntries)
        Log.i(TAG, "persisted ${currentEntries.size} accessory report(s), ${freshIds.size} new")
        if (freshIds.isNotEmpty()) {
            Notifier(applicationContext).newLocations(named.filter { it.first in freshIds }.map { it.second to it.third })
        }
        return Result.success()
    }

    companion object {
        /** Historical name kept: renaming would orphan the previously enqueued weekly job. */
        const val WORK_NAME = "findmy-weekly-fetch"
        private const val TAG = "FetchWorker"
        private const val MAX_RETRIES = 3
    }
}

/** Notification channels and the two messages the worker can raise. Lock screen never shows coordinates. */
private class Notifier(private val context: Context) {
    private val manager = NotificationManagerCompat.from(context)

    init {
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_LOCATIONS, "Tag locations", NotificationManager.IMPORTANCE_DEFAULT))
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_STATUS, "Account status", NotificationManager.IMPORTANCE_HIGH))
    }

    fun loginNeeded() = notify(CHANNEL_STATUS, ID_STATUS) {
        setContentTitle(context.getString(R.string.worker_login_title))
        setContentText(context.getString(R.string.worker_login_text))
    }

    /** One notification per refresh run (not per accessory): name + seen time, no coordinates. */
    fun newLocations(reports: List<Pair<String, LocationReport>>) {
        if (reports.isEmpty()) return
        val names = reports.joinToString(", ") { (name, _) -> name }
        val formatter = DateTimeFormatter.ofLocalizedDateTime(java.time.format.FormatStyle.SHORT)
            .withZone(ZoneId.systemDefault())
        val newest = reports.maxByOrNull { it.second.observedAt }!!.second.observedAt
        notify(CHANNEL_LOCATIONS, ID_LOCATION) {
            setContentTitle(context.getString(R.string.worker_location_title))
            setContentText("$names · ${formatter.format(newest)}")
        }
    }

    private fun notify(channel: String, id: Int, configure: NotificationCompat.Builder.() -> Unit) {
        if (Build.VERSION.SDK_INT >= 33 &&
            context.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val intent = PendingIntent.getActivity(
            context, 0,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val builder = NotificationCompat.Builder(context, channel)
            .setSmallIcon(android.R.drawable.ic_menu_mylocation)
            .setContentIntent(intent)
            .setAutoCancel(true)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
        builder.configure()
        runCatching { manager.notify(id, builder.build()) }   // a denied permission or dead channel must not crash the worker
    }

    companion object {
        const val CHANNEL_LOCATIONS = "findmy_location"
        const val CHANNEL_STATUS = "findmy_status"
        private const val ID_STATUS = 1
        private const val ID_LOCATION = 2
    }
}
