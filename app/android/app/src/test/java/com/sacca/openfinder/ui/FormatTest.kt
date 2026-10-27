package com.sacca.openfinder.ui

import com.sacca.openfinder.domain.LocationReport
import com.sacca.openfinder.ui.components.Freshness
import com.sacca.openfinder.ui.components.freshnessOf
import com.sacca.openfinder.ui.components.relativeAge
import org.junit.Assert.assertEquals
import org.junit.Test
import java.time.Instant

class FormatTest {
    private val now = Instant.parse("2026-10-17T12:00:00Z")
    private fun ago(s: Long) = relativeAge(now.minusSeconds(s), now)

    @Test fun relativeAgeUsesTheRealAge() {
        assertEquals("just now", ago(5)); assertEquals("4 min ago", ago(4 * 60 + 10)); assertEquals("3 h ago", ago(3 * 3600 + 5))
        assertEquals("1 day ago", ago(86_400 + 5)); assertEquals("2 days ago", ago(2 * 86_400 + 5))
    }

    @Test fun futureTimestampsNeverShowNegativeAges() = assertEquals("just now", relativeAge(now.plusSeconds(120), now))

    @Test fun freshnessBuckets() {
        fun f(s: Long) = freshnessOf(LocationReport("a", 1.0, 1.0, now.minusSeconds(s)), now)
        assertEquals(Freshness.FRESH, f(60)); assertEquals(Freshness.RECENT, f(2 * 3600)); assertEquals(Freshness.STALE, f(7 * 3600))
    }
}
