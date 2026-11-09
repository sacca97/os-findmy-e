package com.sacca.openfinder.data

import com.sacca.openfinder.apple.reports.BlobStore
import com.sacca.openfinder.domain.Accessory
import com.sacca.openfinder.domain.AccessoryType
import com.sacca.openfinder.domain.LocationReport
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant

/** Complete local trails, encrypted by the supplied Keystore-backed blob store. No tag keys here. */
class LocationHistoryStore(private val blobs: BlobStore) {
    fun exists() = blobs.exists(BLOB_NAME)
    fun read(): List<Accessory> {
        if (!blobs.exists(BLOB_NAME)) return emptyList()
        val bytes = checkNotNull(blobs.read(BLOB_NAME)) { "history unavailable" }
        try {
            val root = JSONObject(bytes.toString(Charsets.UTF_8))
            check(root.getInt("version") == 1) { "unsupported history format" }
            val tags = root.getJSONArray("tags")
            return List(tags.length()) { i ->
                val tag = tags.getJSONObject(i)
                val id = tag.getString("id")
                val reports = tag.getJSONArray("reports")
                val history = List(reports.length()) { j ->
                    val r = reports.getJSONObject(j)
                    val metadata = r.optJSONObject("metadata")
                    LocationReport(id, r.getDouble("lat"), r.getDouble("lon"), Instant.parse(r.getString("at")),
                        if (r.isNull("accuracy")) null else r.getDouble("accuracy"),
                        metadata?.keys()?.asSequence()?.associateWith { metadata.getString(it) } ?: emptyMap())
                }
                Accessory(id, tag.getString("name"),
                    runCatching { AccessoryType.valueOf(tag.getString("type")) }.getOrDefault(AccessoryType.OTHER),
                    history = history)
            }
        } finally { bytes.fill(0) }
    }

    fun write(accessories: List<Accessory>) {
        val tags = JSONArray()
        accessories.forEach { tag ->
            val reports = JSONArray()
            tag.history.forEach { r ->
                reports.put(JSONObject().put("lat", r.latitude).put("lon", r.longitude)
                    .put("at", r.observedAt.toString()).put("accuracy", r.horizontalAccuracyMeters ?: JSONObject.NULL)
                    .put("metadata", JSONObject(r.metadata)))
            }
            tags.put(JSONObject().put("id", tag.id).put("name", tag.name).put("type", tag.type.name).put("reports", reports))
        }
        val bytes = JSONObject().put("version", 1).put("tags", tags).toString().toByteArray(Charsets.UTF_8)
        try { blobs.write(BLOB_NAME, bytes) } finally { bytes.fill(0) }
    }

    // Keep an empty archive as a migration marker: an old worker's latest-point file must not
    // resurrect cleared trajectories after a restart or an account switch.
    fun clear() = write(emptyList())

    companion object { const val BLOB_NAME = "location_history.enc" }
}

/** Bound disk and map costs while retaining the last known location even for a long-lost tag. */
object LocationHistory {
    const val RETENTION_DAYS = 90L
    const val MAX_POINTS_PER_TAG = 10_000

    fun merge(id: String, reports: List<LocationReport>, now: Instant = Instant.now()): List<LocationReport> {
        val unique = reports.asSequence().filter { it.accessoryId == id && it.isValid(now) }
            .groupBy { Triple(it.observedAt, it.latitude, it.longitude) }
            .values.map { duplicates -> duplicates.minBy { it.horizontalAccuracyMeters ?: Double.POSITIVE_INFINITY } }
            .sortedWith(compareBy<LocationReport> { it.observedAt }.thenBy { it.latitude }.thenBy { it.longitude })
        val cutoff = now.minusSeconds(RETENTION_DAYS * 86_400)
        return unique.filter { !it.observedAt.isBefore(cutoff) }.takeLast(MAX_POINTS_PER_TAG)
            .ifEmpty { unique.takeLast(1) }
    }
}
