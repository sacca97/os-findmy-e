package com.sacca.openfinder.domain

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

class LocationReportTest {
    private val now = Instant.parse("2026-10-17T12:00:00Z")
    private fun r(lat: Double = 43.6, lon: Double = 7.0, at: Instant = now.minusSeconds(60), acc: Double? = 10.0) =
        LocationReport("a", lat, lon, at, acc)

    @Test fun acceptsASaneReport() = assertTrue(r().isValid(now))
    @Test fun rejectsNonFiniteCoordinates() {
        assertFalse(r(lat = Double.NaN).isValid(now)); assertFalse(r(lon = Double.POSITIVE_INFINITY).isValid(now))
    }
    @Test fun rejectsOutOfRangeCoordinates() {
        assertFalse(r(lat = 91.0).isValid(now)); assertFalse(r(lon = -181.0).isValid(now))
    }
    @Test fun rejectsNullIslandAsAMissingFix() = assertFalse(r(lat = 0.0, lon = 0.0).isValid(now))
    @Test fun rejectsFutureTimestampsButToleratesSmallClockSkew() {
        assertFalse(r(at = now.plusSeconds(3600)).isValid(now)); assertTrue(r(at = now.plusSeconds(60)).isValid(now))
    }
    @Test fun rejectsBadAccuracy() {
        assertFalse(r(acc = -1.0).isValid(now)); assertFalse(r(acc = Double.NaN).isValid(now)); assertTrue(r(acc = null).isValid(now))
    }
}
