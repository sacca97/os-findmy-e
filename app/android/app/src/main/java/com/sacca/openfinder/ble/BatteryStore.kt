package com.sacca.openfinder.ble

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Nearby battery observations only: a remote location refresh cannot update this timestamp. */
object BatteryStore {
    data class Sample(val hashB64: String, val rawHex: String, val atMs: Long)
    private val lock = Any()
    suspend fun load(context: Context): List<Sample> = withContext(Dispatchers.IO) {
        synchronized(lock) { BatteryHistory(File(context.filesDir, "tag_battery.json")).read() }
    }
    suspend fun save(context: Context, sample: Sample) = withContext(Dispatchers.IO) {
        synchronized(lock) { BatteryHistory(File(context.filesDir, "tag_battery.json")).append(sample) }
    }
}

/** Legacy single-sample arrays migrate naturally. Atomic writes retain 90 days / 1,000 samples per key. */
class BatteryHistory(private val file: File) {
    fun read(nowMs: Long = System.currentTimeMillis()): List<BatteryStore.Sample> {
        if (!file.exists()) return emptyList()
        val arr = JSONArray(file.readText())
        return List(arr.length()) { i ->
            val o = arr.getJSONObject(i)
            BatteryStore.Sample(o.getString("hash"), o.getString("raw"), o.getLong("at"))
        }.filter { it.hashB64.isNotBlank() && GvBat.fromHex(it.rawHex) != null && it.atMs > 0 && it.atMs <= nowMs + 300_000 }
            .sortedBy { it.atMs }
    }

    fun append(sample: BatteryStore.Sample, nowMs: Long = System.currentTimeMillis()) {
        require(sample.hashB64.isNotBlank() && GvBat.fromHex(sample.rawHex) != null)
        require(sample.atMs in 1..(nowMs + 300_000))
        // An unreadable file throws, so a transient read failure cannot erase the previous samples.
        val all = (read(nowMs) + sample).distinctBy { it.hashB64 to it.atMs }.groupBy { it.hashB64 }
            .values.flatMap { samples ->
                samples.filter { it.atMs >= nowMs - 90L * 86_400_000 }.sortedBy { it.atMs }.takeLast(1000)
                    .ifEmpty { samples.takeLast(1) }
            }.sortedBy { it.atMs }
        val arr = JSONArray()
        all.forEach { arr.put(JSONObject().put("hash", it.hashB64).put("raw", it.rawHex).put("at", it.atMs)) }
        file.parentFile?.mkdirs()
        val tmp = File.createTempFile("battery-", ".tmp", file.parentFile)
        try {
            tmp.writeText(arr.toString())
            check(tmp.renameTo(file)) { "could not store battery history" }
        } finally { tmp.delete() }
    }
}
