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
 * The rekey frames (`PK`/`UPDATE`/`GETTOKEN`) live in [KeyRotation.kt] only (standing-ban revision,
 * user-approved 2026-11-08) — this file still never writes them.
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

    /** One line per stale rule: the standing battery status rendered above the buttons. */
    suspend fun statusLine(expected: Set<String>): String? {
        val mine = BatteryStore.load(context).filter { it.hashB64 in expected }.maxByOrNull { it.atMs }
            ?: return null
        val bytes = mine.rawHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val volts = GvBat.candidates(bytes)?.let { (be, le) -> " ≈ %.2f/%.2f V".format(be, le) } ?: ""
        val age = (System.currentTimeMillis() - mine.atMs) / 3_600_000
        val ageText = when {
            age < 1 -> context.getString(R.string.battery_age_now)
            age < 48 -> context.getString(R.string.battery_age_hours, age)
            else -> context.getString(R.string.battery_age_days, age / 24)
        }
        return context.getString(R.string.battery_status, mine.rawHex.uppercase(), volts, ageText)
    }

    suspend fun expectedKeys(): Set<String>? {
        val expected = accountVm.staticKeyHashes().toSet()
        if (expected.isEmpty()) { message = context.getString(R.string.msg_no_keys); return null }
        return expected
    }

    LaunchedEffect(Unit) {
        val expected = accountVm.staticKeyHashes().toSet()
        if (expected.isEmpty()) return@LaunchedEffect
        batteryStatus = statusLine(expected)
        // The vendor app queries the battery on connect; mirror that: silently refresh an expired
        // sample whenever the app opens (no permission prompts from the auto path).
        val mine = BatteryStore.load(context).filter { it.hashB64 in expected }.maxByOrNull { it.atMs }
        if ((mine == null || System.currentTimeMillis() - mine.atMs > STALE_MS) && !needsPermissions() && busy == null) {
            busy = context.getString(R.string.busy_battery)
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
                    val (be, le) = GvBat.candidates(sample.raw) ?: return@launch
                    message = context.getString(R.string.msg_battery_sample,
                        sample.raw.joinToString("") { "%02x".format(it) }.uppercase(), be, le)
                }
            } catch (e: Exception) {
                message = "${context.getString(R.string.action_battery)}: ${e.message}"
            } finally {
                busy = null
            }
        }
    }

    /** Exports the fresh keypair for the PC tooling (fetch-mtag.sh). Failure is LOUD in logcat — a
     *  silently lost export once left the PC querying a burned key (2026-11-08 reclaim incident). */
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
