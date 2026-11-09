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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.sacca.openfinder.R
import androidx.compose.ui.unit.dp
import com.sacca.openfinder.ui.account.AccountViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive

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
 * Nearby control actions for an imported tag: `PL`/`ST`
 * ring frames and the `GVBAT` battery query, both plain FEF2 writes on a verified nearby tag.
 * The explicit key-management flow (`PK`/`UPDATE`/`GETTOKEN`) lives in [KeyRotation.kt].
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
            val deadline = android.os.SystemClock.elapsedRealtime() + 3000
            while (android.os.SystemClock.elapsedRealtime() < deadline) {
                val raw = session.awaitNotification((deadline - android.os.SystemClock.elapsedRealtime()).coerceAtLeast(1)) ?: return null
                if (GvBat.decode(raw) != null) return BatterySample(tag.hashB64, raw)
            }
            return null
        } finally {
            session.close()
        }
    }
}

/**
 * Vendor AOT handleValue (0x832ca0 / closure 0x8337cc): [0x3d, status], not a 16-bit ADC value.
 * Untagged Dart constants are 0x20/0x60/0xa0; GDT[cid=60] is integer equality.
 * These select power4/3/2.png. The vendor falls back to power1.png for every other status;
 * accept the matching 0xe0 code as one bar and leave unrecognised statuses explicitly unknown.
 */
object GvBat {
    data class Reading(val status: Int, val bars: Int?)
    fun decode(sample: ByteArray): Reading? {
        if (sample.size != 2 || sample[0] != 0x3d.toByte()) return null
        val status = sample[1].toInt() and 0xff
        return Reading(status, when (status) { 0x20 -> 4; 0x60 -> 3; 0xa0 -> 2; 0xe0 -> 1; else -> null })
    }

    fun fromHex(raw: String): Reading? = runCatching {
        if (raw.length != 4) return null
        decode(raw.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
    }.getOrNull()
}

/** Ring / battery / key-rotation tools for the verified nearby tag; expects static keys imported. */
@Composable
fun TagToolsSection(accountVm: AccountViewModel, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf<String?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    var batteryStatus by remember { mutableStateOf<String?>(null) }
    var confirmRotate by remember { mutableStateOf(false) }
    var confirmReclaim by remember { mutableStateOf(false) }

    val permissionsList = listOfNotNull(
        Manifest.permission.BLUETOOTH_CONNECT.takeIf { Build.VERSION.SDK_INT >= 31 },
        Manifest.permission.ACCESS_FINE_LOCATION,
    )

    fun needsPermissions(): Boolean =
        Build.VERSION.SDK_INT >= 31 && (context.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED ||
            context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) ||
            (Build.VERSION.SDK_INT < 31 && context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED)

    val requestPermissions = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { grants ->
        if (grants.values.all { it }) {
            scope.launch { message = context.getString(R.string.msg_perm_granted) }
        } else message = context.getString(R.string.msg_perm_needed)
    }

    /** Freshness belongs to the sample, not to the latest remote location query. */
    suspend fun statusLine(expected: Set<String>): String {
        val mine = BatteryStore.load(context).filter { it.hashB64 in expected }.maxByOrNull { it.atMs }
            ?: return context.getString(R.string.battery_unknown)
        val bars = GvBat.fromHex(mine.rawHex)?.bars
        val ageMs = (System.currentTimeMillis() - mine.atMs).coerceAtLeast(0)
        val age = ageMs / 60_000
        val ageText = when {
            age < 1 -> context.getString(R.string.battery_age_now)
            age < 60 -> context.getString(R.string.battery_age_minutes, age)
            age < 2880 -> context.getString(R.string.battery_age_hours, age / 60)
            else -> context.getString(R.string.battery_age_days, age / 1440)
        }
        val level = bars?.let { context.getString(R.string.battery_bars, it) } ?: context.getString(R.string.battery_level_unknown)
        val freshness = if (ageMs > STALE_MS) context.getString(R.string.battery_stale) else context.getString(R.string.battery_nearby)
        return context.getString(R.string.battery_status, level, ageText, freshness)
    }

    suspend fun expectedKeys(): Set<String>? {
        val expected = accountVm.staticKeyHashes().toSet()
        if (expected.isEmpty()) { message = context.getString(R.string.msg_no_keys); return null }
        return expected
    }

    LaunchedEffect(Unit) {
        val expected = accountVm.staticKeyHashes().toSet()
        if (expected.isEmpty()) return@LaunchedEffect
        batteryStatus = runCatching { statusLine(expected) }.getOrElse { context.getString(R.string.battery_storage_failed) }
        // The vendor app queries the battery on connect; mirror that: silently refresh an expired
        // sample whenever the app opens (no permission prompts from the auto path).
        val mine = runCatching { BatteryStore.load(context) }.getOrDefault(emptyList()).filter { it.hashB64 in expected }.maxByOrNull { it.atMs }
        if ((mine == null || System.currentTimeMillis() - mine.atMs > STALE_MS) && !needsPermissions() && busy == null) {
            busy = context.getString(R.string.busy_battery)
            try {
                val sample = TagActions.battery(context, expected)
                if (sample != null) {
                    BatteryStore.save(context, BatteryStore.Sample(sample.hashB64, sample.raw.joinToString("") { "%02x".format(it) }, System.currentTimeMillis()))
                    batteryStatus = statusLine(expected)
                }
            } catch (e: CancellationException) { throw e
            } catch (_: Exception) { /* Keep the last sampled time when the tag is not nearby. */
            } finally { busy = null }
        }
        while (currentCoroutineContext().isActive) {
            delay(60_000)
            batteryStatus = runCatching { statusLine(expected) }.getOrElse { context.getString(R.string.battery_storage_failed) }
        }
    }

    fun launchRing() {
        if (busy != null) return
        scope.launch {
            busy = context.getString(R.string.busy_ringing)
            try {
                val expected = expectedKeys() ?: return@launch
                when (val r = TagActions.ring(context, expected)) {
                    is TagActionResult.Ok -> message = context.getString(R.string.msg_ring_done)
                    is TagActionResult.NotFound ->
                        message = if (r.heardAny > 0) context.getString(R.string.msg_ring_not_heard)
                                  else context.getString(R.string.msg_nothing_heard)
                    TagActionResult.ConnectFailed -> message = context.getString(R.string.msg_connect_failed)
                    TagActionResult.CommandRejected -> message = context.getString(R.string.msg_ring_rejected)
                }
            } catch (e: Exception) {
                message = "${context.getString(R.string.action_ring)}: ${e.message}"
            } finally {
                busy = null
            }
        }
    }

    fun launchBattery() {
        if (busy != null) return
        scope.launch {
            busy = context.getString(R.string.busy_battery)
            try {
                val expected = expectedKeys() ?: return@launch
                val sample = TagActions.battery(context, expected)
                if (sample == null) {
                    message = context.getString(R.string.msg_battery_none)
                } else {
                    BatteryStore.save(context, BatteryStore.Sample(sample.hashB64, sample.raw.joinToString("") { "%02x".format(it) }, System.currentTimeMillis()))
                    batteryStatus = statusLine(expected)
                    val bars = GvBat.decode(sample.raw)?.bars
                    val level = bars?.let { context.getString(R.string.battery_bars, it) } ?: context.getString(R.string.battery_level_unknown)
                    val stamp = java.time.format.DateTimeFormatter.ofPattern("MM-dd HH:mm")
                        .withZone(java.time.ZoneId.systemDefault())
                    val recent = BatteryStore.load(context).filter { it.hashB64 == sample.hashB64 }.takeLast(5)
                        .joinToString("\n") { s ->
                            val b = GvBat.fromHex(s.rawHex)?.bars
                            val label = b?.let { context.getString(R.string.battery_bars, it) } ?: context.getString(R.string.battery_level_unknown)
                            "${stamp.format(java.time.Instant.ofEpochMilli(s.atMs))} · $label"
                        }
                    message = context.getString(R.string.msg_battery_sample, level) + "\n\n" + recent
                }
            } catch (e: CancellationException) { throw e
            } catch (e: Exception) {
                message = context.getString(R.string.battery_storage_failed)
            } finally {
                busy = null
            }
        }
    }

    /** Exports the current keypair for local PC tooling; report failures so both clients keep
     *  querying the key that the tag currently advertises. */
    fun exportForPc(context: Context, json: String) {
        val primary = java.io.File(context.getExternalFilesDir(null), "mtag-keypair.json")
        val target = try {
            primary.parentFile?.mkdirs()
            primary.writeText(json)
            Log.i("KeyRotation", "export ok: ${primary.absolutePath}")
            return
        } catch (e: Exception) {
            Log.i("KeyRotation", "export to external dir failed: ${e::class.java.simpleName}")
            java.io.File(context.filesDir, "mtag-keypair.json")   // debug fallback: adb run-as pull
        }
        try {
            target.writeText(json)
            Log.i("KeyRotation", "export ok (fallback): ${target.absolutePath}")
        } catch (e: Exception) {
            Log.i("KeyRotation", "export failed entirely: ${e::class.java.simpleName}")
        }
    }

    /** Runs the gated rotation (ble/KeyRotation.kt) and persists the fresh key on Success/Unverified. */
    fun launchRotation(mode: RotateMode) {
        if (busy != null) return
        scope.launch {
            busy = context.getString(R.string.busy_rotating)
            try {
                val owned = accountVm.staticKeyHashes().toSet()
                when (val r = rotateTagKey(context, mode, owned)) {
                    is RotationOutcome.Success -> {
                        val json = r.newKey.toJson().toString()
                        accountVm.rotateStaticKeys(json, r.oldHashB64)
                        exportForPc(context, json)
                        message = context.getString(R.string.msg_rotate_done, r.newHashB64.take(8))
                    }
                    is RotationOutcome.Unverified -> {
                        // Frames were accepted: persist so nothing is lost, but tell the user to re-check.
                        val json = r.newKey.toJson().toString()
                        accountVm.rotateStaticKeys(json, r.oldHashB64)
                        exportForPc(context, json)
                        message = context.getString(R.string.msg_rotate_unverified)
                    }
                    is RotationOutcome.NotFound ->
                        message = if (r.heardAny > 0) context.getString(R.string.msg_rotate_not_owned)
                                  else context.getString(R.string.msg_nothing_heard)
                    RotationOutcome.ConnectFailed -> message = context.getString(R.string.msg_connect_failed)
                    is RotationOutcome.ProtocolFailed -> message = context.getString(R.string.msg_rotate_rejected, r.step)
                }
            } catch (e: Exception) {
                message = context.getString(R.string.msg_rotation_failed, e.message ?: "")
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
        Button(onClick = {
            if (needsPermissions()) requestPermissions.launch(permissionsList.toTypedArray()) else launchRing()
        }, enabled = busy == null, modifier = Modifier.weight(1f)) {
            Text(stringResource(R.string.action_ring))
        }
        OutlinedButton(onClick = {
            if (needsPermissions()) requestPermissions.launch(permissionsList.toTypedArray()) else launchBattery()
        }, enabled = busy == null, modifier = Modifier.weight(1f)) {
            Text(stringResource(R.string.action_battery))
        }
    }
    Row(modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 2.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(onClick = {
            if (needsPermissions()) requestPermissions.launch(permissionsList.toTypedArray()) else confirmRotate = true
        }, enabled = busy == null, modifier = Modifier.weight(1f)) {
            Text(stringResource(R.string.action_rotate))
        }
        OutlinedButton(onClick = {
            if (needsPermissions()) requestPermissions.launch(permissionsList.toTypedArray()) else confirmReclaim = true
        }, enabled = busy == null, modifier = Modifier.weight(1f)) {
            Text(stringResource(R.string.action_reclaim))
        }
    }
    if (confirmRotate) {
        AlertDialog(
            onDismissRequest = { confirmRotate = false },
            title = { Text(stringResource(R.string.dlg_rotate_title)) },
            text = { Text(stringResource(R.string.dlg_rotate_text)) },
            confirmButton = { TextButton(onClick = { confirmRotate = false; launchRotation(RotateMode.Own) }) { Text(stringResource(R.string.dlg_confirm)) } },
            dismissButton = { TextButton(onClick = { confirmRotate = false }) { Text(stringResource(R.string.dlg_cancel)) } },
        )
    }
    if (confirmReclaim) {
        AlertDialog(
            onDismissRequest = { confirmReclaim = false },
            title = { Text(stringResource(R.string.dlg_reclaim_title)) },
            text = { Text(stringResource(R.string.dlg_reclaim_text)) },
            confirmButton = { TextButton(onClick = { confirmReclaim = false; launchRotation(RotateMode.Reclaim) }) { Text(stringResource(R.string.action_reclaim)) } },
            dismissButton = { TextButton(onClick = { confirmReclaim = false }) { Text(stringResource(R.string.dlg_cancel)) } },
        )
    }
    message?.let {
        val warn = it.startsWith("⚠")
        Text(it, Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 4.dp),
            style = MaterialTheme.typography.bodyMedium,
            color = if (warn) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
