package com.sacca.openfinder.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.util.Log
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentLinkedQueue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull

/** The tag's two working characteristics — the same UUIDs the audit's `provision_tag.py` used. */
object TagUuids {
    val FEF1 = UUID.fromString("0000fef1-0000-1000-8000-00805f9b34fb")   // notify
    val FEF2 = UUID.fromString("0000fef2-0000-1000-8000-00805f9b34fb")   // write (commands)
    val CCCD = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")   // notification enable
}

/** One verified tag heard during a scan: the device to connect to, its key hash (b64) and the best RSSI. */
class VerifiedTag(val device: BluetoothDevice, val hashB64: String, val rssi: Int)

/** Find My-shaped advert count of the most recent scan: 0 after a shake means the tag's burst has not started. */
var lastFindMyShaped: Int = 0
    private set

/**
 * Scans for [seconds] and returns the strongest heard sample of the expected tags (matched by
 * advertised key hash), or null when Bluetooth is off / nothing matched close enough. Proximity is
 * enforced by [nearRssi]: ring and battery are only offered while the tag answers this loud.
 *
 * The scan is read-only. Nothing in this file ever sends `PK`, `UPDATE` or `GETTOKEN` — the only
 * control commands issued here are `PL`/`ST` (ring) and `GVBAT` (battery); key management is separate.
 */
@SuppressLint("MissingPermission")   // callers hold BLUETOOTH_SCAN (+ location on this Android version)
suspend fun scanForVerifiedTag(context: Context, expectedB64: Set<String>, seconds: Int = 3, nearRssi: Int = -70): VerifiedTag? {
    val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager ?: return null
    val scanner = manager.adapter?.bluetoothLeScanner ?: return null
    val heard = ConcurrentLinkedQueue<ScanResult>()
    var failed = false
    val callback = object : android.bluetooth.le.ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) { heard.add(result) }
        override fun onScanFailed(errorCode: Int) { failed = true }
    }
    // LOW_LATENCY: this tag's frames are regularly missed in the balanced mode on this device
    // (the rekey check hit the same; see RekeyCheck.kt).
    val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
    scanner.startScan(null, settings, callback)
    try {
        delay(seconds * 1000L)
    } finally {
        runCatching { scanner.stopScan(callback) }
    }
    if (failed) return null
    var findMyShaped = 0
    val verified = heard.mapNotNull { result ->
        val data = result.scanRecord?.getManufacturerSpecificData(0x004C) ?: return@mapNotNull null
        if (data.size < 26 || data[0] != 0x12.toByte() || data[1] != 0x19.toByte()) return@mapNotNull null
        findMyShaped++
        val key = advertisedPublicKey(result.device?.address ?: "", data) ?: return@mapNotNull null
        val hashB64 = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(key))
        if (hashB64 !in expectedB64) return@mapNotNull null
        VerifiedTag(result.device, hashB64, result.rssi)
    }
    lastFindMyShaped = findMyShaped
    // Diagnostics: how many adverts at all, how many Find My-shaped, how many ours (duty-cycled tags
    // advertise in bursts — "0 shaped" after a shake means the burst has not started yet, retry).
    Log.i("TagLink", "scan: ${heard.size} advert(s), $findMyShaped find-my-shaped, ${verified.size} expected-tag sample(s), best rssi ${verified.maxOfOrNull { it.rssi } ?: "none"}")
    return verified.maxByOrNull { it.rssi }
}

/**
 * A connected GATT session with the tag. Writes go to FEF2; FEF1 notifications are forwarded to a
 * channel. Every awaitable is time-boxed: a silent tag must surface as a typed null, never a hang.
 */
class TagSession private constructor(
    private val gatt: BluetoothGatt,
    private val fef2: BluetoothGattCharacteristic,
    private val notifications: Channel<ByteArray>,
) {
    private var writeDone: CompletableDeferred<Boolean>? = null

    suspend fun write(bytes: ByteArray, timeoutMs: Long = 3000): Boolean {
        writeDone = CompletableDeferred()
        // The deprecated writeCharacteristic is used on every API level on purpose — same reason as
        // the CCCD write below: the API 33 Int overload rejects synchronously right after discovery
        // settles, while the Boolean overload queues reliably. WRITE_TYPE_DEFAULT = with response,
        // matching the vendor app's ATT Write Request.
        @Suppress("DEPRECATION")
        fef2.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        @Suppress("DEPRECATION")
        fef2.value = bytes
        @Suppress("DEPRECATION")
        val queued = gatt.writeCharacteristic(fef2)
        if (!queued) return false
        return withTimeoutOrNull(timeoutMs) { writeDone!!.await() } ?: false
    }

    /** The next FEF1 notification payload, or null after [timeoutMs]. */
    suspend fun awaitNotification(timeoutMs: Long = 3000): ByteArray? = withTimeoutOrNull(timeoutMs) { notifications.receive() }

    fun close() {
        runCatching { gatt.disconnect() }
        runCatching { gatt.close() }
    }

    companion object {
        /** Connects, discovers services and enables FEF1 notifications; closes on any failure or timeout. */
        @SuppressLint("MissingPermission")
        suspend fun open(context: Context, tag: VerifiedTag, timeoutMs: Long = 15_000): TagSession? {
            val notifications = Channel<ByteArray>(Channel.UNLIMITED)
            var session: TagSession? = null
            val opened = CompletableDeferred<TagSession?>()
            var discoveryRequested = false
            val notifyStarted = java.util.concurrent.atomic.AtomicBoolean(false)

            fun completeIfOpen(result: TagSession?) { if (opened.isCompleted) return; opened.complete(result) }

            // Runs the CCCD setup from whatever service list is available. The tag keeps a GATT
            // connection for only ~800 ms and a fresh discoverServices() round trip eats exactly
            // that — so on STATE_CONNECTED we first try the stack's cached services directly and
            // only fall back to discoverServices() when the cache is empty. Idempotent: doubled
            // connected callbacks on some stacks must not run the CCCD path twice.
            fun startNotify(g: BluetoothGatt, from: String) {
                if (!notifyStarted.compareAndSet(false, true)) return
                val services = g.services
                val service = services.firstOrNull { s -> s.characteristics.any { it.uuid == TagUuids.FEF2 } }
                val fef2 = service?.getCharacteristic(TagUuids.FEF2)
                val fef1 = service?.getCharacteristic(TagUuids.FEF1)
                Log.i("TagLink", "setup($from): ${services.size} service(s), fef2=${fef2 != null}, fef1=${fef1 != null}")
                if (fef2 == null || fef1 == null) {
                    if (discoveryRequested) { notifyStarted.set(false); return }   // discovery still in flight
                    discoveryRequested = true
                    g.discoverServices()
                    notifyStarted.set(false)
                    return
                }
                session = TagSession(g, fef2, notifications)
                val notifOn = g.setCharacteristicNotification(fef1, true)
                Log.i("TagLink", "setCharacteristicNotification=$notifOn")
                if (!notifOn) { completeIfOpen(null); return }
                val cccd = fef1.getDescriptor(TagUuids.CCCD)
                if (cccd == null) { Log.i("TagLink", "CCCD missing"); completeIfOpen(null); return }
                // The deprecated write is used on every API level on purpose: the API 33 Int overload
                // rejects synchronously here ("queued=false" while the stack is still settling after
                // discovery), while the Boolean overload queues reliably — same as flutter_blue_plus.
                @Suppress("DEPRECATION")
                cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                @Suppress("DEPRECATION")
                val queued = g.writeDescriptor(cccd)
                Log.i("TagLink", "cccd queued=$queued")
                if (!queued) completeIfOpen(null)
            }

            val callback = object : BluetoothGattCallback() {
                override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
                    when (newState) {
                        BluetoothProfile.STATE_CONNECTED -> { Log.i("TagLink", "gatt connected (status $status)"); startNotify(g, "cache") }
                        BluetoothProfile.STATE_DISCONNECTED -> { Log.i("TagLink", "gatt disconnected (status $status)");
                            session?.notifications?.close()
                            completeIfOpen(null)
                        }
                    }
                }

                override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
                    Log.i("TagLink", "services discovered (status $status)")
                    if (status != BluetoothGatt.GATT_SUCCESS) { completeIfOpen(null); return }
                    startNotify(g, "discovery")
                }

                override fun onDescriptorWrite(g: BluetoothGatt, d: BluetoothGattDescriptor, status: Int) {
                    Log.i("TagLink", "descriptor written (status $status)")
                    if (!opened.isCompleted) opened.complete(if (status == BluetoothGatt.GATT_SUCCESS) session else null)
                }

                override fun onCharacteristicWrite(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) {
                    session?.writeDone?.complete(status == BluetoothGatt.GATT_SUCCESS)
                }

                override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray) {
                    if (c.uuid == TagUuids.FEF1) notifications.trySend(value.copyOf())
                }

                @Deprecated("pre-33 callback path")
                @Suppress("DEPRECATION")
                override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic) {
                    if (Build.VERSION.SDK_INT < 33 && c.uuid == TagUuids.FEF1) {
                        notifications.trySend(c.value?.copyOf() ?: return)
                    }
                }
            }
            tag.device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
            val result = withTimeoutOrNull(timeoutMs) { opened.await() }
            if (result == null) { session?.close(); return null }
            return result
        }
    }
}
