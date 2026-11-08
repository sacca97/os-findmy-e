package com.sacca.openfinder.work

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.time.Instant

class LastReportsTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val t0: Instant = Instant.parse("2026-11-07T12:00:00Z")

    private fun entry(lat: Double = 31.3, lon: Double = 120.6, at: Instant = t0, accuracy: Double? = 25.0) =
        LastReportEntry(lat, lon, at, accuracyMeters = accuracy)

    @Test
    fun `write then read round-trips entries`() {
        val dir = tmp.newFolder()
        LastReports(dir).write(
            mapOf(
                "tag-a" to entry(),
                "tag-b" to entry(lat = 1.0, lon = -1.0, at = t0.plusSeconds(60), accuracy = null),
            ),
            savedAt = t0,
        )
        val read = LastReports(dir).read()
        assertEquals(2, read.size)
        assertEquals(entry(), read["tag-a"])
        assertEquals(entry(lat = 1.0, lon = -1.0, at = t0.plusSeconds(60), accuracy = null), read["tag-b"])
    }

    @Test
    fun `unreadable file reads as empty and write recovers it`() {
        val dir = tmp.newFolder()
        File(dir, "last_reports.json").writeText("{not json")
        assertTrue(LastReports(dir).read().isEmpty())
        LastReports(dir).write(mapOf("tag-a" to entry()), savedAt = t0)
        assertEquals(entry(), LastReports(dir).read()["tag-a"])
    }

    @Test
    fun `missing file reads as empty`() {
        assertTrue(LastReports(tmp.newFolder()).read().isEmpty())
    }

    @Test
    fun `newerThan keeps first sightings and strictly newer reports only`() {
        val previous = mapOf(
            "seen-newer" to entry(at = t0),
            "seen-older" to entry(at = t0),
        )
        val current = mapOf(
            "seen-newer" to entry(at = t0.plusSeconds(900)),   // strictly newer: report
            "seen-older" to entry(at = t0.minusSeconds(10)),   // older than stored: silent
            "seen-first" to entry(at = t0),                    // first sighting: report
        )
        assertEquals(setOf("seen-newer", "seen-first"), LastReports.newerThan(previous, current).keys)
    }

    @Test
    fun `newerThan with empty previous reports everything`() {
        val current = mapOf("a" to entry(), "b" to entry(at = t0.plusSeconds(1)))
        assertEquals(current.keys, LastReports.newerThan(emptyMap(), current).keys)
    }
}
