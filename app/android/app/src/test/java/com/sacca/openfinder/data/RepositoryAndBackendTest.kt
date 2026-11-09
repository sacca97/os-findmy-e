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
import kotlinx.coroutines.async
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.time.Instant
import com.sacca.openfinder.work.LastReports
import com.sacca.openfinder.work.LastReportEntry
import org.junit.Rule
import org.junit.rules.TemporaryFolder

private class FakeBackend(var accessories: List<Accessory>, var reports: List<LocationReport>, var failure: OpenFinderException? = null) : OpenFinderBackend {
    override suspend fun getAuthState() = AuthState.Authenticated
    override suspend fun startLogin(username: String, password: String) = AuthResult.Success
    override suspend fun submitTwoFactor(challengeId: String, code: String) = AuthResult.Success
    override suspend fun getAccessories(): List<Accessory> { failure?.let { throw it }; return accessories }
    override suspend fun fetchReports(accessoryIds: List<String>): List<LocationReport> = reports
    override suspend fun logout() = Unit
}

class OpenFinderRepositoryTest {
    @get:Rule val temp = TemporaryFolder()
    private val now = Instant.now()
    private val a = Accessory("a", "A", AccessoryType.KEYS)
    private fun report(id: String, lat: Double = 43.6, lon: Double = 7.0, ageS: Long = 60) = LocationReport(id, lat, lon, now.minusSeconds(ageS))

    @Test fun mergesReportsAndKeepsTheNewestPerAccessory() = runBlocking {
        val repo = OpenFinderRepository(FakeBackend(listOf(a), listOf(report("a", ageS = 600), report("a", lat = 44.0, ageS = 30))))
        repo.refresh()
        assertEquals(44.0, repo.state.value.accessories.single().latestReport!!.latitude, 0.0)
    }

    @Test fun keepsTheFullHistorySortedOldestFirst() = runBlocking {
        val repo = OpenFinderRepository(FakeBackend(listOf(a), listOf(report("a", ageS = 600), report("a", lat = 44.0, ageS = 30), report("a", lat = 45.0, ageS = 90))))
        repo.refresh()
        val history = repo.state.value.accessories.single().history
        assertEquals(listOf(600L, 90L, 30L), history.map { now.epochSecond - it.observedAt.epochSecond })
        assertEquals(44.0, repo.state.value.accessories.single().latestReport!!.latitude, 0.0)
        assertTrue(repo.state.value.accessories.single().history.last() === repo.state.value.accessories.single().latestReport)
    }

    @Test fun keepsPreviousHistoryWhenAnAccessoryGetsNoNewReports() = runBlocking {
        val backend = FakeBackend(listOf(a), listOf(report("a", lat = 44.0, ageS = 30)))
        val repo = OpenFinderRepository(backend)
        repo.refresh()
        backend.reports = emptyList()
        repo.refresh()
        assertEquals(1, repo.state.value.accessories.single().history.size)
        assertEquals(44.0, repo.state.value.accessories.single().latestReport!!.latitude, 0.0)
        // A kept (stale) report is not "waiting": the accessory still has a known location.
        org.junit.Assert.assertFalse(repo.state.value.waitingForReports)
    }

    @Test fun dropsMalformedReportsInsteadOfShowingThem() = runBlocking {
        val repo = OpenFinderRepository(FakeBackend(listOf(a), listOf(report("a", lat = Double.NaN), report("a", lon = 500.0), report("a", ageS = -7200))))
        repo.refresh()
        assertNull(repo.state.value.accessories.single().latestReport)
        // Nothing usable survived: the quiet "waiting for the first report" state, not an error banner.
        assertNull(repo.state.value.error)
        assertTrue(repo.state.value.waitingForReports)
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

    @Test fun concurrentRefreshWaitsForTheSharedResultWithoutDuplicatingTheFetch() = runBlocking {
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        var requests = 0
        val newest = report("a")
        val backend = object : OpenFinderBackend by FakeBackend(listOf(a), emptyList()) {
            override suspend fun fetchReports(accessoryIds: List<String>): List<LocationReport> {
                requests += 1
                entered.complete(Unit)
                release.await()
                return listOf(newest)
            }
        }
        val repo = OpenFinderRepository(backend)
        val uiRefresh = async { repo.refresh() }
        entered.await()
        val workerRefresh = async(start = CoroutineStart.UNDISPATCHED) {
            repo.refresh()
            repo.state.value.accessories.single().latestReport
        }
        org.junit.Assert.assertFalse(workerRefresh.isCompleted)
        release.complete(Unit)
        withTimeout(2000) {
            uiRefresh.await()
            assertEquals(newest, workerRefresh.await())
        }
        assertEquals(1, requests)
    }

    @Test fun eachNewBatchExtendsTheTrailInsteadOfReplacingIt() = runBlocking {
        val older = report("a", ageS = 600)
        val overlap = report("a", ageS = 300)
        val newest = report("a", ageS = 30)
        val backend = FakeBackend(listOf(a), listOf(older, overlap))
        val repo = OpenFinderRepository(backend)
        repo.refresh()
        backend.reports = listOf(newest, overlap, newest)
        repo.refresh()
        assertEquals(listOf(older, overlap, newest), repo.state.value.accessories.single().history)
    }

    @Test fun restartRestoresTheFullTrailEvenWhenTheNetworkIsDown() = runBlocking {
        val store = LocationHistoryStore(HistoryTestBlobs())
        val reports = listOf(report("a", ageS = 600), report("a", ageS = 30))
        OpenFinderRepository(FakeBackend(listOf(a), reports), historyStore = store).refresh()
        val restarted = OpenFinderRepository(FakeBackend(listOf(a), emptyList(), OpenFinderException(OpenFinderError.Network())), historyStore = store)
        restarted.refresh()
        assertEquals(reports, restarted.state.value.accessories.single().history)
        assertEquals(reports.last(), restarted.state.value.accessories.single().latestReport)
        assertTrue(restarted.state.value.error is OpenFinderError.Network)
    }

    @Test fun removedTagsArePrunedFromTheArchive() = runBlocking {
        val store = LocationHistoryStore(HistoryTestBlobs())
        val backend = FakeBackend(listOf(a), listOf(report("a")))
        val repo = OpenFinderRepository(backend, historyStore = store)
        repo.refresh()
        backend.accessories = emptyList()
        repo.refresh()
        assertTrue(store.read().isEmpty())
        backend.accessories = listOf(a)
        backend.reports = emptyList()
        repo.refresh()
        assertTrue(repo.state.value.accessories.single().history.isEmpty())
    }

    @Test fun unreadableArchiveIsNotOverwrittenAndRecoveryMergesBothTrails() = runBlocking {
        val blobs = HistoryTestBlobs()
        val store = LocationHistoryStore(blobs)
        val old = report("a", ageS = 600)
        val newest = report("a", ageS = 30)
        store.write(listOf(a.copy(history = listOf(old))))
        val original = blobs.values.getValue(LocationHistoryStore.BLOB_NAME).copyOf()
        blobs.unreadable = true
        val repo = OpenFinderRepository(FakeBackend(listOf(a), listOf(newest)), historyStore = store)
        repo.refresh()
        assertTrue(repo.state.value.historyStorageFailed)
        assertArrayEquals(original, blobs.values[LocationHistoryStore.BLOB_NAME])
        blobs.unreadable = false
        repo.refresh()
        assertEquals(listOf(old, newest), store.read().single().history)
        org.junit.Assert.assertFalse(repo.state.value.historyStorageFailed)
    }

    @Test fun saveFailureKeepsFreshReportsVisibleAndCanBeRetried() = runBlocking {
        val blobs = HistoryTestBlobs().apply { failWrites = true }
        val newest = report("a")
        val repo = OpenFinderRepository(FakeBackend(listOf(a), listOf(newest)), historyStore = LocationHistoryStore(blobs))
        repo.refresh()
        assertEquals(newest, repo.state.value.accessories.single().latestReport)
        assertTrue(repo.state.value.historyStorageFailed)
        blobs.failWrites = false
        repo.refresh()
        org.junit.Assert.assertFalse(repo.state.value.historyStorageFailed)
    }

    @Test fun clearsCannotBeUndoneByAnOldWorkerLatestPointFile() = runBlocking {
        val store = LocationHistoryStore(HistoryTestBlobs())
        val latest = LastReports(temp.root)
        val r = report("a")
        val backend = FakeBackend(listOf(a), listOf(r))
        val repo = OpenFinderRepository(backend, historyStore = store, legacyReports = latest)
        repo.refresh()
        repo.clearCache()
        // A worker that already took its snapshot may finish after sign-out/clear.
        latest.write(mapOf("a" to LastReportEntry(r.latitude, r.longitude, r.observedAt, null)))
        backend.reports = emptyList()
        val restarted = OpenFinderRepository(backend, historyStore = store, legacyReports = latest)
        restarted.refresh()
        assertTrue(restarted.state.value.accessories.single().history.isEmpty())
    }

    @Test fun migrationUsesOnlyLatestPointsForCurrentlyOwnedKeys() = runBlocking {
        val latest = LastReports(temp.root)
        val r = report("a")
        latest.write(mapOf("a" to LastReportEntry(r.latitude, r.longitude, r.observedAt, null),
            "foreign" to LastReportEntry(40.0, 5.0, r.observedAt, null)))
        val store = LocationHistoryStore(HistoryTestBlobs())
        val repo = OpenFinderRepository(FakeBackend(listOf(a), emptyList()), historyStore = store, legacyReports = latest)
        repo.refresh()
        assertEquals(listOf(r), store.read().single().history)
    }
}
