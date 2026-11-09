package com.sacca.openfinder

import android.app.Application
import android.content.Context
import android.os.StrictMode
import androidx.work.BackoffPolicy
import androidx.work.Configuration
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.sacca.openfinder.anisette.AssetOrFileImageSource
import com.sacca.openfinder.apple.Cooldown
import com.sacca.openfinder.apple.GsaClient
import com.sacca.openfinder.apple.PrefsCooldownStore
import com.sacca.openfinder.anisette.CoreAdiAnisetteProvider
import com.sacca.openfinder.anisette.MachineStorage
import com.sacca.openfinder.data.OpenFinderRepository
import com.sacca.openfinder.data.RustOpenFinderBackend
import com.sacca.openfinder.security.SecretStore
import com.sacca.openfinder.data.IconStore
import com.sacca.openfinder.data.LocationHistoryStore
import com.sacca.openfinder.apple.reports.SecretStoreBlobs
import com.sacca.openfinder.work.FetchWorker
import com.sacca.openfinder.work.LastReports
import java.io.File
import java.util.concurrent.TimeUnit

/** Manual dependency container. The UI only ever sees the backend through [repository]. */
class AppContainer(context: Context) {
    val machineStorage = MachineStorage(context)
    val coreAdiImage = AssetOrFileImageSource(context)
    val anisette = CoreAdiAnisetteProvider(machineStorage, coreAdiImage)
    /** HTTP 429 is an inconsistency error, not a rate limit (GSA-LOGIN-TRANSPORT.md): it is recorded but never blocks a retry. */
    val cooldown = Cooldown(PrefsCooldownStore(context), minutes = 0)
    fun gsaClient(device: com.sacca.openfinder.apple.GsaDevice) = GsaClient(device, cooldown)
    /** The live backend: the whole Apple-side protocol in the Rust library. [accountSetup] is its setup half (machine, keys). */
    val liveBackend = RustOpenFinderBackend(machineStorage, coreAdiImage, SecretStore(context, "openfinder_machine_key"), cooldown)
    val accountSetup: com.sacca.openfinder.domain.AccountSetup = liveBackend

    val repository = OpenFinderRepository(liveBackend, IconStore(context),
        LocationHistoryStore(SecretStoreBlobs(SecretStore(context, "openfinder_history_key"))),
        LastReports(File(context.filesDir, "reports")))

    /** The background worker's latest-location notification snapshot (app-private JSON). */
    val lastReports by lazy { LastReports(File(context.filesDir, "reports")) }
}

/** Builds workers with the container's dependencies; the default reflective factory cannot. */
private class OpenFinderWorkerFactory(private val container: AppContainer) : androidx.work.WorkerFactory() {
    override fun createWorker(
        appContext: Context,
        workerClassName: String,
        workerParameters: androidx.work.WorkerParameters,
    ) = when (workerClassName) {
        FetchWorker::class.java.name -> FetchWorker(appContext, workerParameters, container.lastReports)
        else -> null   // unknown class: fall back to the default instantiation path
    }
}

class OpenFinderApp : Application(), Configuration.Provider {
    lateinit var container: AppContainer
        private set

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setWorkerFactory(OpenFinderWorkerFactory(container))
            .build()

    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            // Milestone D check, early: report any disk/network work or slow call on the main thread in logcat.
            StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.Builder().detectAll().penaltyLog().build())
        }
        container = AppContainer(this)
        schedulePeriodicFetch()
    }

    /** Collect batches throughout the day; the server may return only the latest few sightings.
     *  WorkManager may defer this under Doze/battery restrictions. This job never connects to BLE.
     *  UPDATE keeps one existing job while migrating the former daily schedule. */
    private fun schedulePeriodicFetch() {
        val request = PeriodicWorkRequestBuilder<FetchWorker>(30, TimeUnit.MINUTES, 5, TimeUnit.MINUTES)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            FetchWorker.WORK_NAME, ExistingPeriodicWorkPolicy.UPDATE, request)
    }
}
