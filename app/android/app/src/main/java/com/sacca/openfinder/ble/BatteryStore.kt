package com.sacca.openfinder.ble

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Last `GVBAT` sample per tag key hash, persisted in files/ as plain JSON — the battery reading is
 * not a credential and follows the same "plain file" rule as the weekly worker's last_reports.
 * The UI reads this on start so the battery is a standing status, not something behind a button.
 */
object BatteryStore {
    class Sample(val hashB64: String, val rawHex: String, val atMs: Long)

    private fun file(context: Context) = File(context.filesDir, "tag_battery.json")

    fun load(context: Context): List<Sample> = runCatching {
        val arr = JSONArray(file(context).readText())
        List(arr.length()) { i ->
            arr.getJSONObject(i).let { Sample(it.getString("hash"), it.getString("raw"), it.getLong("at")) }
        }
    }.getOrDefault(emptyList())

    fun save(context: Context, sample: Sample) {
        val all = load(context).filter { it.hashB64 != sample.hashB64 } + sample
        val arr = JSONArray()
        all.forEach { arr.put(JSONObject().put("hash", it.hashB64).put("raw", it.rawHex).put("at", it.atMs)) }
        runCatching { file(context).writeText(arr.toString()) }
    }
}
