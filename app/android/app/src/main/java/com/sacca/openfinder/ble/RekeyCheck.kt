package com.sacca.openfinder.ble

import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.sacca.openfinder.ui.account.AccountViewModel
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.ConcurrentLinkedQueue
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Read-only rekey check for static single-key tags: scan for the tag's own advertisement and compare the
 * advertised key against the imported one. This scan never writes to the tag.
 *
 * Apple's Find My advertisement (manufacturer data 0x004C, leading `12 19`) carries 22 bytes of the tag's
 * P-224 public key at data[3..25); the other 6 bytes ride in the device address, with the top two bits of
 * the first byte taken from data[25]'s low two bits. sha256 over the reconstructed 28-byte key equals the imported static
 * tag's hashed advertising key (the accessory id), so no private-key material is needed here.
 */

/** The 28-byte advertised public key X reconstructed from one Find My advertisement, or null when it is not one. */
fun advertisedPublicKey(address: String, data: ByteArray): ByteArray? {
    if (data.size < 26 || data[0] != 0x12.toByte() || data[1] != 0x19.toByte()) return null
    val mac = address.replace(":", "")
    if (mac.length != 12) return null
    return try {
        val out = ByteArray(28)
        val prefix = hex(mac)
        out[0] = (((prefix[0].toInt() and 0xFF) and 0x3F) or ((data[25].toInt() and 0x03) shl 6)).toByte()
        System.arraycopy(prefix, 1, out, 1, 5)
        System.arraycopy(data, 3, out, 6, 22)
        out
    } catch (_: IllegalArgumentException) {
        null
    }
}

private fun hex(s: String): ByteArray {
    val out = ByteArray(s.length / 2)
    for (i in out.indices) out[i] = ((Character.digit(s[i * 2], 16) shl 4) or Character.digit(s[i * 2 + 1], 16)).toByte()
    return out
}

private fun hexPrefix(hash: ByteArray, chars: Int = 12): String =
    hash.take(chars / 2).joinToString("") { "%02x".format(it) }

/** What one scan heard: how many expected keys matched, other Find My keys with their RSSI, and the raw frame count. */
class ScanOutcome(val matched: Int, val expected: Int, val others: List<Pair<ByteArray, Int>>, val rawFrames: Int) {
    /** A foreign key only counts as a possible rekey when its signal is close-range; a distant
     *  neighbor's tag is indistinguishable from "ours is out of range" and must not alarm. */
    val closeForeignKeys: List<ByteArray> get() = others.filter { it.second >= NEAR_RSSI }.map { it.first }
    val farForeignCount: Int get() = others.count { it.second < NEAR_RSSI }
    companion object { const val NEAR_RSSI = -70 }
}

/** One [seconds] foreground scan; null when Bluetooth is unavailable or off. */
suspend fun scanForExpectedKeys(context: Context, expectedB64: Set<String>, seconds: Int = 3): ScanOutcome? {
    val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager ?: return null
    val scanner = manager.adapter?.bluetoothLeScanner ?: return null
    val heard = ConcurrentLinkedQueue<ScanResult>()
    var failed = false
    val callback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            heard.add(result)
        }
        override fun onScanFailed(errorCode: Int) { failed = true }
    }
    // No hardware filter: the tag's Find My data can sit in the scan response, which some controllers
    // never feed into manufacturer-data filters. LOW_LATENCY because the window is three seconds and
    // some OEM stacks deliver little in the default balanced mode.
    val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
    scanner.startScan(null, settings, callback)
    try {
        delay(seconds * 1000L)
    } finally {
        runCatching { scanner.stopScan(callback) }
    }
    if (failed) return null
    var matched = 0
    val others = ArrayList<Pair<ByteArray, Int>>()
    val seen = HashSet<String>()
    for (result in heard) {
        val data = result.scanRecord?.manufacturerSpecificData?.let { sparse ->
            (0 until sparse.size()).firstOrNull { sparse.keyAt(it) == 0x004C }?.let { sparse.valueAt(it) }
        } ?: continue
        val key = advertisedPublicKey(result.device?.address ?: "", data) ?: continue
        val digest = MessageDigest.getInstance("SHA-256").digest(key)
        val hashB64 = Base64.getEncoder().encodeToString(digest)
        val expected = hashB64 in expectedB64
        // Keep protocol diagnostics without logging device addresses or advertising identifiers.
        if (expected) Log.i("RekeyCheck",
            "expected tag: status=0x%02x rssi=${result.rssi}".format(data[2]))
        if (!seen.add(hashB64)) continue          // the same tag repeats its frame many times per second
        if (expected) matched++ else others.add(digest to result.rssi)
    }
    return ScanOutcome(matched, expectedB64.size, others, heard.size)
}

/** Button + verdict line, wired with [AccountViewModel] for the imported static tag keys. */
@Composable
fun RekeyCheckSection(accountVm: AccountViewModel, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var running by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }

    suspend fun runCheck() {
        val expected = accountVm.staticKeyHashes().toSet()
        if (expected.isEmpty()) { message = "No static tag keys imported yet — import one first."; return }
        val outcome = scanForExpectedKeys(context, expected)
            ?: run { message = "Bluetooth is unavailable or off."; return }
        message = when {
            outcome.matched == outcome.expected && outcome.expected > 0 ->
                "✓ Tag key verified — the advertisement matches the imported key."
            outcome.matched > 0 ->
                "✓ ${outcome.matched} of ${outcome.expected} tags match; ${outcome.others.size} other Find My device(s) nearby."
            outcome.closeForeignKeys.size == 1 ->
                "⚠ Possible rekey! A close-range tag advertises a DIFFERENT key (sha256 prefix ${hexPrefix(outcome.closeForeignKeys[0])})."
            outcome.closeForeignKeys.size > 1 ->
                "⚠ Possible rekey! ${outcome.closeForeignKeys.size} close-range tags advertise keys that match none of the imported ones."
            outcome.rawFrames == 0 ->
                "No BLE frames delivered in 3 s — retry (some stacks throttle rapid scans)."
            else ->
                "Inconclusive: ${outcome.farForeignCount} distant Find My device(s) heard, none matched — bring the tag within a meter and retry."
        }
    }

    val requestPermissions = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { grants ->
        if (grants.values.all { it }) scope.launch { running = true; try { runCheck() } catch (e: Exception) { message = "Check failed: ${e.message}" }; running = false }
        else message = "Bluetooth scanning needs the location permission on this Android version."
    }

    fun launchOrRequest() {
        val needed = arrayOf(
            android.Manifest.permission.BLUETOOTH_SCAN,
            android.Manifest.permission.ACCESS_FINE_LOCATION,
        )
        val missing = needed.filter { androidx.core.content.ContextCompat.checkSelfPermission(context, it) != android.content.pm.PackageManager.PERMISSION_GRANTED }
        if (missing.isEmpty()) scope.launch { running = true; try { runCheck() } catch (e: Exception) { message = "Check failed: ${e.message}" }; running = false }
        else requestPermissions.launch(needed)
    }

    Column(modifier.fillMaxWidth().padding(top = 4.dp)) {
        Button(
            onClick = { launchOrRequest() },
            enabled = !running,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp),
        ) { Text(if (running) "Scanning 3 s…" else "Check tag (BLE, read-only)") }
        message?.let {
            val warn = it.startsWith("⚠")
            Text(it, Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 4.dp),
                style = MaterialTheme.typography.bodyMedium,
                color = if (warn) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
