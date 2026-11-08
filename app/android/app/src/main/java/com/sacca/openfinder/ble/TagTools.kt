package com.sacca.openfinder.ble

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.sacca.openfinder.ui.account.AccountViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private const val SCAN_SECONDS = 10
/** Re-query the battery when the stored sample is older than this (the vendor queries on connect too). */
private const val STALE_MS = 12 * 3_600_000L

/** Typed outcomes so the UI never mistakes "not found" for "done" (a bug that shipped once). */
sealed interface TagActionResult {
    data object Ok : TagActionResult
    data class NotFound(val heardAny: Int) : TagActionResult
    data object ConnectFailed : TagActionResult
    data object CommandRejected : TagActionResult
}

/**
 * Own-tag, own-control actions over the vendor protocol round 2 (audit-notes.md, 第六轮): `PL`/`ST`
 * ring frames and the `GVBAT` battery query, both plain FEF2 writes on a verified nearby tag.
 * The rekey frames (`PK`/`UPDATE`/`GETTOKEN`) are deliberately absent from this whole file.
 */
object TagActions {
    private const val TAG = "TagActions"

    /** Rings the verified nearby tag once: a single `PL` frame, the tag stops on its own. */
    suspend fun ring(context: Context, expectedB64: Set<String>): TagActionResult {
        val tag = scanForVerifiedTag(context, expectedB64, seconds = SCAN_SECONDS) ?: run {
            Log.i(TAG, "ring: scan found no expected tag")
            return TagActionResult.NotFound(lastFindMyShaped)
        }
        Log.i(TAG, "ring: tag found (rssi ${tag.rssi})")
        var session: TagSession? = null
        for (attempt in 1..3) {
            session = TagSession.open(context, tag)
            if (session != null) break
            Log.i(TAG, "ring: connect attempt $attempt failed, retrying")
            delay(800)
        }
        session ?: run { Log.i(TAG, "ring: connect failed after retries"); return TagActionResult.ConnectFailed }
        try {
            if (!session.write("PL".toByteArray())) { Log.i(TAG, "ring: PL rejected"); return TagActionResult.CommandRejected }
            return TagActionResult.Ok
        } finally {
            session.close()
        }
    }

    /** One `GVBAT` sample (raw bytes) with the tag's key hash, or null when no nearby tag / no answer. */
    class BatterySample(val hashB64: String, val raw: ByteArray)

    suspend fun battery(context: Context, expectedB64: Set<String>): BatterySample? {
        val tag = scanForVerifiedTag(context, expectedB64, seconds = SCAN_SECONDS) ?: run { Log.i(TAG, "battery: scan found no expected tag"); return null }
        var session: TagSession? = null
        for (attempt in 1..3) {
            session = TagSession.open(context, tag)
            if (session != null) break
            Log.i(TAG, "battery: connect attempt $attempt failed, retrying")
            delay(800)
        }
        session ?: run { Log.i(TAG, "battery: connect failed after retries"); return null }
        try {
            if (!session.write("GVBAT".toByteArray())) { Log.i(TAG, "battery: GVBAT rejected"); return null }
            val raw = session.awaitNotification(3000) ?: return null
            return BatterySample(tag.hashB64, raw)
        } finally {
            session.close()
        }
    }
}

/**
 * The two candidate scales for a 2-byte `GVBAT` sample (calibration pending, audit-notes 第六轮):
 * big-endian/4 and little-endian/2, in volts. Pure function so the readout is unit-testable.
 */
object GvBat {
    fun candidates(sample: ByteArray): Pair<Double, Double>? {
        if (sample.size < 2) return null
        val be = ((sample[0].toInt() and 0xFF) shl 8) or (sample[1].toInt() and 0xFF)
        val le = ((sample[1].toInt() and 0xFF) shl 8) or (sample[0].toInt() and 0xFF)
        // The raw sample reads in quarter-millivolts (be) / half-millivolts (le): 0x3d20 → 3912 mV (be) or 4126.5 mV (le).
        return Pair(be / 4000.0, le / 2000.0)
    }
}

/** Ring + battery tools for the verified nearby tag; expects the static keys already imported. */
@Composable
fun TagToolsSection(accountVm: AccountViewModel, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf<String?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    var batteryStatus by remember { mutableStateOf<String?>(null) }

    fun age(ms: Long): String {
        val h = (System.currentTimeMillis() - ms) / 3_600_000
        return when {
            h < 1 -> "just now"
            h < 48 -> "$h h ago"
            else -> "${h / 24} d ago"
        }
    }

    /** One line per stale rule: the standing battery status rendered above the buttons. */
    suspend fun statusLine(expected: Set<String>): String? {
        val mine = BatteryStore.load(context).filter { it.hashB64 in expected }.maxByOrNull { it.atMs }
            ?: return null
        val bytes = mine.rawHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val volts = GvBat.candidates(bytes)?.let { (be, le) -> " ≈ %.2f/%.2f V".format(be, le) } ?: ""
        return "Battery ${mine.rawHex.uppercase()}$volts · ${age(mine.atMs)}"
    }

    suspend fun runExpected(): Set<String>? {
        val expected = accountVm.staticKeyHashes().toSet()
        if (expected.isEmpty()) { message = "No static tag keys imported yet — import one first."; return null }
        return expected
    }

    fun needsPermissions(): Boolean =
        Build.VERSION.SDK_INT >= 31 && (context.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED ||
            context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) ||
            (Build.VERSION.SDK_INT < 31 && context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED)

    val requestPermissions = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { grants ->
        if (grants.values.all { it }) {
            scope.launch {
                // Re-run after the grant; the caller's button click already chose the action.
                message = "Permission granted — tap the action again."
            }
        } else message = "Bluetooth actions need the nearby-devices and location permissions."
    }

    LaunchedEffect(Unit) {
        val expected = accountVm.staticKeyHashes().toSet()
        if (expected.isEmpty()) return@LaunchedEffect
        batteryStatus = statusLine(expected)
        // The vendor app queries the battery on connect; mirror that: silently refresh an expired
        // sample whenever the app opens (no permission prompts from the auto path).
        val mine = BatteryStore.load(context).filter { it.hashB64 in expected }.maxByOrNull { it.atMs }
        if ((mine == null || System.currentTimeMillis() - mine.atMs > STALE_MS) && !needsPermissions() && busy == null) {
            busy = "Reading battery…"
            try {
                val sample = TagActions.battery(context, expected)
                if (sample != null) {
                    BatteryStore.save(context, BatteryStore.Sample(sample.hashB64, sample.raw.joinToString("") { "%02x".format(it) }, System.currentTimeMillis()))
                    batteryStatus = statusLine(expected)
                }
            } catch (_: Exception) { /* standing status: a failed auto-refresh stays quiet */ }
            busy = null
        }
    }


    fun launchRing() {
        if (busy != null) return
        scope.launch {
            busy = "Ringing…"
            try {
                val expected = runExpected() ?: return@launch
                when (val r = TagActions.ring(context, expected)) {
                    is TagActionResult.Ok -> message = "Done — the tag rang."
                    is TagActionResult.NotFound ->
                        message = if (r.heardAny > 0) "The tag was not heard in 5 s (other Find My devices were). Shake it and retry."
                                  else "Nothing heard in 5 s — shake the tag, keep it within a meter, retry."
                    TagActionResult.ConnectFailed -> message = "Heard it but could not connect — retry once."
                    TagActionResult.CommandRejected -> message = "Heard and connected, but the tag rejected the ring command."
                }
            } catch (e: Exception) {
                message = "Ring failed: ${e.message}"
            } finally {
                busy = null
            }
        }
    }

    fun launchBattery() {
        if (busy != null) return
        scope.launch {
            busy = "Reading battery…"
            try {
                val expected = runExpected() ?: return@launch
                val sample = TagActions.battery(context, expected)
                if (sample == null) {
                    message = "No answer — bring the tag within a meter and retry."
                } else {
                    BatteryStore.save(context, BatteryStore.Sample(sample.hashB64, sample.raw.joinToString("") { "%02x".format(it) }, System.currentTimeMillis()))
                    batteryStatus = statusLine(expected)
                    val (be, le) = GvBat.candidates(sample.raw) ?: return@launch
                    message = "Battery sample 0x${sample.raw.joinToString("") { "%02x".format(it) }.uppercase()} ≈ %.2f V or %.2f V (calibration pending)".format(be, le)
                }
            } catch (e: Exception) {
                message = "Battery failed: ${e.message}"
            } finally {
                busy = null
            }
        }
    }

    batteryStatus?.let {
        Text(it, Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 2.dp),
            style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    Row(modifier.fillMaxWidth().padding(horizontal = 20.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        val permissions = listOfNotNull(
            Manifest.permission.BLUETOOTH_CONNECT.takeIf { Build.VERSION.SDK_INT >= 31 },
            Manifest.permission.ACCESS_FINE_LOCATION,
        )
        Button(onClick = {
            if (needsPermissions()) requestPermissions.launch(permissions.toTypedArray()) else launchRing()
        }, enabled = busy == null, modifier = Modifier.weight(1f)) {
            Text(if (busy?.startsWith("Ringing") == true) busy!! else "Ring")
        }
        OutlinedButton(onClick = {
            if (needsPermissions()) requestPermissions.launch(permissions.toTypedArray()) else launchBattery()
        }, enabled = busy == null, modifier = Modifier.weight(1f)) {
            Text(when {
                busy?.startsWith("Reading") == true -> busy!!
                else -> "Battery"
            })
        }
    }
    message?.let {
        val warn = it.startsWith("⚠")
        Text(it, Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 4.dp),
            style = MaterialTheme.typography.bodyMedium,
            color = if (warn) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
