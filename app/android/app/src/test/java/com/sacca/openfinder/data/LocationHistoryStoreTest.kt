package com.sacca.openfinder.data

import com.sacca.openfinder.apple.reports.BlobStore
import com.sacca.openfinder.domain.Accessory
import com.sacca.openfinder.domain.AccessoryType
import com.sacca.openfinder.domain.LocationReport
import org.junit.Assert.*
import org.junit.Test
import java.time.Instant

internal class HistoryTestBlobs : BlobStore {
    val values = mutableMapOf<String, ByteArray>()
    var unreadable = false
    var failWrites = false
    override fun exists(name: String) = name in values
    override fun read(name: String) = if (unreadable) null else values[name]?.copyOf()
    override fun write(name: String, plaintext: ByteArray) {
        check(!failWrites)
        values[name] = plaintext.copyOf()
    }
    override fun delete(name: String) { values.remove(name) }
}

class LocationHistoryStoreTest {
    private val now = Instant.parse("2026-11-09T05:00:00Z")
    private fun report(age: Long, accuracy: Double? = null) = LocationReport("a", 43.6, 7.0, now.minusSeconds(age), accuracy)

    @Test fun archiveRoundTripPreservesSightingsAndMetadata() {
        val store = LocationHistoryStore(HistoryTestBlobs())
        val reports = listOf(report(60, 40.0).copy(metadata = mapOf("confidence" to "1")), report(10))
        store.write(listOf(Accessory("a", "Bike", AccessoryType.BIKE, history = reports)))
        val saved = store.read().single()
        assertEquals("Bike", saved.name)
        assertEquals(AccessoryType.BIKE, saved.type)
        assertEquals(reports, saved.history)
    }

    @Test fun overlappingSightingsMergeChronologicallyAndKeepBestAccuracy() {
        val history = LocationHistory.merge("a", listOf(report(10), report(60), report(60, 40.0), report(60, 10.0), report(30)), now)
        assertEquals(listOf(60L, 30L, 10L), history.map { now.epochSecond - it.observedAt.epochSecond })
        assertEquals(10.0, history.first().horizontalAccuracyMeters!!, 0.0)
    }

    @Test fun invalidAndForeignReportsCannotEnterTheArchive() {
        assertTrue(LocationHistory.merge("a", listOf(report(60).copy(accessoryId = "b"),
            report(60).copy(latitude = Double.NaN), report(-3600)), now).isEmpty())
    }

    @Test fun retentionIsBoundedButKeepsLastKnownLocationForLongLostTag() {
        val old = report(100 * 86_400)
        assertEquals(listOf(old), LocationHistory.merge("a", listOf(old, report(110 * 86_400)), now))
        assertEquals(listOf(report(60)), LocationHistory.merge("a", listOf(old, report(60)), now))
        val many = (1..10_100).map { report(it.toLong()) }
        val kept = LocationHistory.merge("a", many, now)
        assertEquals(10_000, kept.size)
        assertEquals(report(1), kept.last())
    }

    @Test(expected = IllegalStateException::class)
    fun unreadableArchiveIsReportedInsteadOfTreatedAsAbsent() {
        val blobs = HistoryTestBlobs()
        val store = LocationHistoryStore(blobs)
        store.write(emptyList())
        blobs.unreadable = true
        store.read()
    }
}
