package com.sacca.openfinder.data

import com.sacca.openfinder.domain.Accessory
import com.sacca.openfinder.domain.AccessoryType
import com.sacca.openfinder.domain.AnisetteHeaders
import com.sacca.openfinder.domain.AnisetteProvider
import com.sacca.openfinder.domain.AuthResult
import com.sacca.openfinder.domain.AuthState
import com.sacca.openfinder.domain.OpenFinderBackend
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import com.sacca.openfinder.domain.LocationReport
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.time.Instant

private class FakeBackend(var accessories: List<Accessory>, var reports: List<LocationReport>, var failure: OpenFinderException? = null) : OpenFinderBackend {
    override suspend fun getAuthState() = AuthState.Authenticated
    override suspend fun startLogin(username: String, password: String) = AuthResult.Success
    override suspend fun submitTwoFactor(challengeId: String, code: String) = AuthResult.Success
    override suspend fun getAccessories(): List<Accessory> { failure?.let { throw it }; return accessories }
    override suspend fun fetchReports(accessoryIds: List<String>): List<LocationReport> = reports
    override suspend fun logout() = Unit
}

class OpenFinderRepositoryTest {
    private val now = Instant.now()
    private val a = Accessory("a", "A", AccessoryType.KEYS)
    private fun report(id: String, lat: Double = 43.6, lon: Double = 7.0, ageS: Long = 60) = LocationReport(id, lat, lon, now.minusSeconds(ageS))

    @Test fun mergesReportsAndKeepsTheNewestPerAccessory() = runBlocking {
        val repo = OpenFinderRepository(FakeBackend(listOf(a), listOf(report("a", ageS = 600), report("a", lat = 44.0, ageS = 30))))
        repo.refresh()
        assertEquals(44.0, repo.state.value.accessories.single().latestReport!!.latitude, 0.0)
    }

    @Test fun dropsMalformedReportsInsteadOfShowingThem() = runBlocking {
        val repo = OpenFinderRepository(FakeBackend(listOf(a), listOf(report("a", lat = Double.NaN), report("a", lon = 500.0), report("a", ageS = -7200))))
        repo.refresh()
        assertNull(repo.state.value.accessories.single().latestReport)
        assertTrue(repo.state.value.error is OpenFinderError.ReportsUnavailable)
    }

    @Test fun keepsTheLastGoodDataWhenARefreshFails() = runBlocking {
        val backend = FakeBackend(listOf(a), listOf(report("a")))
        val repo = OpenFinderRepository(backend)
        repo.refresh()
        backend.failure = OpenFinderException(OpenFinderError.Network())
        repo.refresh()
        val s = repo.state.value
        assertNotNull(s.accessories.single().latestReport)          // still there: offline use
        assertTrue(s.error is OpenFinderError.Network)
        assertEquals(false, s.refreshing)
    }

    @Test fun anUnexpectedExceptionBecomesATypedBackendError() = runBlocking {
        val repo = OpenFinderRepository(object : OpenFinderBackend by FakeBackend(emptyList(), emptyList()) {
            override suspend fun getAccessories(): List<Accessory> = error("boom")
        })
        repo.refresh()
        assertTrue(repo.state.value.error is OpenFinderError.Backend)
        assertEquals(false, repo.state.value.refreshing)
    }

    @Test fun clearCacheForgetsEverything() = runBlocking {
        val repo = OpenFinderRepository(FakeBackend(listOf(a), listOf(report("a"))))
        repo.refresh(); repo.clearCache()
        assertTrue(repo.state.value.accessories.isEmpty()); assertEquals(false, repo.state.value.loadedOnce)
    }
}
