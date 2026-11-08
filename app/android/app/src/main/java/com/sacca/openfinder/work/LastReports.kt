package com.sacca.openfinder.work

import org.json.JSONObject
import java.io.File
import java.time.Instant
import java.time.format.DateTimeFormatter

/** One accessory's newest known report, as persisted by [LastReports]. */
data class LastReportEntry(
    val latitude: Double,
    val longitude: Double,
    val observedAt: Instant,
    val accuracyMeters: Double?,
)

/**
 * Plain-JSON persistence of every accessory's newest report (`files/last_reports.json`).
 *
 * Coordinates are sightings, not credentials, and the manifest sets `allowBackup=false`, so this
 * deliberately does not go through [com.sacca.openfinder.security.SecretStore]: the point is that
 * the UI and the weekly worker can share the last known state across process restarts. A missing
 * or unreadable file reads as empty; writes go through temp-file-and-rename so a crash cannot
 * leave a half-written file behind.
 */
class LastReports(private val dir: File) {
    private val file = File(dir, FILE_NAME)

    /** accessory id -> newest report. Empty when nothing was persisted (or the file is unreadable). */
    fun read(): Map<String, LastReportEntry> {
        if (!file.exists()) return emptyMap()
        return try {
            val root = JSONObject(file.readText())
            val reports = root.optJSONObject(REPORTS) ?: JSONObject()
            val out = LinkedHashMap<String, LastReportEntry>()
            for (id in reports.keys()) {
                val o = reports.getJSONObject(id)
                out[id] = LastReportEntry(
                    latitude = o.getDouble("lat"),
                    longitude = o.getDouble("lon"),
                    observedAt = Instant.parse(o.getString("observed_at")),
                    accuracyMeters = if (o.isNull("accuracy")) null else o.getDouble("accuracy"),
                )
            }
            out
        } catch (e: Exception) {
            emptyMap()
        }
    }

    fun write(reports: Map<String, LastReportEntry>, savedAt: Instant = Instant.now()) {
        dir.mkdirs()
        val root = JSONObject()
            .put("saved_at", DateTimeFormatter.ISO_INSTANT.format(savedAt))
            .put(REPORTS, JSONObject().also { out ->
                reports.forEach { (id, e) ->
                    out.put(id, JSONObject()
                        .put("lat", e.latitude)
                        .put("lon", e.longitude)
                        .put("observed_at", DateTimeFormatter.ISO_INSTANT.format(e.observedAt))
                        .put("accuracy", e.accuracyMeters ?: JSONObject.NULL))
                }
            })
        val tmp = File(dir, "$FILE_NAME.tmp")
        tmp.writeText(root.toString())
        check(tmp.renameTo(file)) { "could not store $FILE_NAME" }
    }

    companion object {
        private const val FILE_NAME = "last_reports.json"
        private const val REPORTS = "reports"

        /**
         * The subset of [current] that is genuinely new against the persisted state: an accessory
         * seen for the first time, or whose newest report is strictly more recent than the stored
         * one (pure function so the worker's decision is unit-testable).
         */
        fun newerThan(previous: Map<String, LastReportEntry>, current: Map<String, LastReportEntry>): Map<String, LastReportEntry> =
            current.filter { (id, entry) -> previous[id]?.let { entry.observedAt.isAfter(it.observedAt) } ?: true }
    }
}
