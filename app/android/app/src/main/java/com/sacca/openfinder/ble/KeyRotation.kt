package com.sacca.openfinder.ble

import android.annotation.SuppressLint
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.util.Log
import com.sacca.openfinder.apple.reports.KeyPair
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.ConcurrentLinkedQueue
import kotlinx.coroutines.delay

/**
 * Nearby key management for a static single-key tag, using `GETTOKEN` → `PK`+pub → `UPDATE` on FEF2.
 *
 * This protocol does not authenticate ownership. Rotation is an explicit local operation,
 * never a background report-refresh strategy or a way to restore a lost tag remotely.
 * The UI requires confirmation, and the following gates apply:
 *
 *  - [RotateMode.Own] (normal rotation): the target must currently advertise one of the IMPORTED
 *    keys and answer at [ROTATE_NEAR_RSSI] or louder.
 *  - [RotateMode.Reclaim] (recovery): no hash gate — after someone else's write the tag no longer
 *    advertises our key, so reclaiming is only possible by matching the DEONE GATT service. The
 *    UI must explicitly confirm this mode. Use only with a device the user is authorised to manage.
 *
 * A newly generated key is persisted on success or an accepted-but-unverified write; the
 * superseded entry is removed from the active tag list.
 */
sealed interface RotateMode {
    /** Normal rotation: gated on the advertised hash being an imported key. */
    data object Own : RotateMode

    /** Recovery after a foreign write: matches the DEONE GATT service instead of the hash. */
    data object Reclaim : RotateMode
}

/** Typed outcomes so the UI never mistakes "not found" for "done". [newKey] is in-memory only (redacted toString). */
sealed interface RotationOutcome {
    /** Written and the fresh key confirmed on air. [oldHashB64] is null when the scan saw no usable hash. */
    data class Success(val oldHashB64: String?, val newKey: KeyPair) : RotationOutcome {
        val newHashB64: String get() = newKey.hashedAdvKeyB64
    }
    data class NotFound(val heardAny: Int) : RotationOutcome
    data object ConnectFailed : RotationOutcome
    data class ProtocolFailed(val step: String) : RotationOutcome

    /** Frames accepted, but the fresh key was not heard on air within the verify window — check with a scan. */
    data class Unverified(val oldHashB64: String?, val newKey: KeyPair) : RotationOutcome {
        val newHashB64: String get() = newKey.hashedAdvKeyB64
    }
}

/** Rotation requires the tag this loud, on top of the ownership gate. */
const val ROTATE_NEAR_RSSI = -70

private const val TAG = "KeyRotation"

/**
 * Rotates the nearby tag to a freshly generated static key. Persists nothing: on success the
 * caller must store [RotationOutcome.Success.newHashB64]'s keypair (see `rotateStaticKeys`)
 * so fetch and the rekey check pick the new key up.
 */
@SuppressLint("MissingPermission")   // callers hold BLUETOOTH_CONNECT (+ location on this Android version)
suspend fun rotateTagKey(context: Context, mode: RotateMode, ownedHashes: Set<String>): RotationOutcome {
    val target: VerifiedTag = when (mode) {
        is RotateMode.Own -> {
            if (ownedHashes.isEmpty()) return RotationOutcome.NotFound(0)
            scanForVerifiedTag(context, ownedHashes, seconds = 10, nearRssi = ROTATE_NEAR_RSSI)
                ?: run { Log.i(TAG, "own: no imported-key tag heard loud enough"); return RotationOutcome.NotFound(lastFindMyShaped) }
        }
        is RotateMode.Reclaim -> scanStrongestShaped(context, seconds = 10)
            ?: run { Log.i(TAG, "reclaim: no find-my-shaped tag heard loud enough"); return RotationOutcome.NotFound(lastFindMyShaped) }
    }
    Log.i(TAG, "target rssi=${target.rssi}")

    val newKey = KeyPair.generate()

    var session: TagSession? = null
    for (attempt in 1..3) {
        session = TagSession.open(context, target)
        if (session != null) break
        Log.i(TAG, "connect attempt $attempt failed")
        delay(800)
    }
    session ?: run { Log.i(TAG, "connect failed after retries"); return RotationOutcome.ConnectFailed }

    try {
        // Notification misses never abort the sequence (the proven PC path ignores them too):
        // only a rejected WRITE fails the rotation. A lost device-info notify once cost us the
        // fresh key — the tag had committed while the app threw the keypair away.
        if (!session.write("GETTOKEN".toByteArray())) return RotationOutcome.ProtocolFailed("GETTOKEN")
        val token = session.awaitNotification(2500)
        Log.i(TAG, "token ${token?.size ?: 0}B")

        if (!session.write("PK".toByteArray() + newKey.advKeyBytes)) return RotationOutcome.ProtocolFailed("PK")
        val csv = session.awaitNotification(2500)
        Log.i(TAG, "device info ${csv?.size ?: 0}B")

        if (!session.write("UPDATE".toByteArray())) return RotationOutcome.ProtocolFailed("UPDATE")
    } finally {
        session.close()
    }

    // Verify on air before declaring success: the tag beeps either way, silence would be a lie.
    delay(1500)
    val confirmed = scanForVerifiedTag(context, setOf(newKey.hashedAdvKeyB64), seconds = 8)
        ?: scanForVerifiedTag(context, setOf(newKey.hashedAdvKeyB64), seconds = 8)
    return if (confirmed != null) {
        Log.i(TAG, "rotation verified on air (rssi ${confirmed.rssi})")
        RotationOutcome.Success(target.hashB64, newKey)
    } else {
        Log.i(TAG, "frames accepted but fresh key not heard back")
        RotationOutcome.Unverified(target.hashB64, newKey)
    }
}

/**
 * Strongest Find My-shaped advert at rotation proximity, regardless of whose key it advertises —
 * the [RotateMode.Reclaim] scan. The DEONE GATT check happens implicitly at connect: a non-DEONE
 * device has no FEF1/FEF2 and [TagSession.open] returns null.
 */
@SuppressLint("MissingPermission")
private suspend fun scanStrongestShaped(context: Context, seconds: Int): VerifiedTag? {
    val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? android.bluetooth.BluetoothManager ?: return null
    val scanner = manager.adapter?.bluetoothLeScanner ?: return null
    val heard = ConcurrentLinkedQueue<ScanResult>()
    var failed = false
    val callback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) { heard.add(result) }
        override fun onScanFailed(errorCode: Int) { failed = true }
    }
    val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
    scanner.startScan(null, settings, callback)
    try {
        delay(seconds * 1000L)
    } finally {
        runCatching { scanner.stopScan(callback) }
    }
    if (failed) return null
    val shaped = heard.mapNotNull { result ->
        val data = result.scanRecord?.getManufacturerSpecificData(0x004C) ?: return@mapNotNull null
        if (data.size < 26 || data[0] != 0x12.toByte() || data[1] != 0x19.toByte()) return@mapNotNull null
        val key = advertisedPublicKey(result.device?.address ?: "", data) ?: return@mapNotNull null
        val hashB64 = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(key))
        VerifiedTag(result.device, hashB64, result.rssi)
    }.filter { it.rssi >= ROTATE_NEAR_RSSI }
    Log.i(TAG, "reclaim scan: ${heard.size} advert(s), ${shaped.size} shaped near enough")
    return shaped.maxByOrNull { it.rssi }
}
