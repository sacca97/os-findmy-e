package com.sacca.openfinder.data

import com.sacca.openfinder.domain.Accessory
import com.sacca.openfinder.domain.OpenFinderBackend
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.sacca.openfinder.work.LastReports
import com.sacca.openfinder.domain.LocationReport
import java.time.Instant

data class RepositoryState(
    val accessories: List<Accessory> = emptyList(),
    val loadedOnce: Boolean = false,
    val refreshing: Boolean = false,
    val lastRefresh: Instant? = null,
    val error: OpenFinderError? = null,
    /** Accessories exist but none has a report: the tag simply has not been seen by an iPhone yet — informational, not an error. */
    val waitingForReports: Boolean = false,
    val historyStorageFailed: Boolean = false,
)

/**
 * Single source of truth for the UI. Keeps the last good data when a refresh fails (offline use) and drops
 * malformed reports instead of showing them. Works with any [OpenFinderBackend].
 */
class OpenFinderRepository(
    private val backend: OpenFinderBackend,
    private val icons: IconStore? = null,
    private val historyStore: LocationHistoryStore? = null,
    private val legacyReports: LastReports? = null,
) {
    private val _state = MutableStateFlow(RepositoryState())
    val state: StateFlow<RepositoryState> = _state.asStateFlow()
    private val refreshLock = Mutex()
    private var historyLoaded = false
    private var migrateLegacy = true

    suspend fun refresh() {
        if (!refreshLock.tryLock()) {
            // A worker racing the initial UI load must wait for the shared result;
            // returning early made it report SUCCESS while persisting no reports.
            refreshLock.withLock { }
            return
        }
        try {
            _state.update { it.copy(refreshing = true, error = null) }
            try {
                // Restore before touching the network: a failed request must not hide an offline trail.
                if (!historyLoaded) {
                    try {
                        val cached = withContext(Dispatchers.IO) {
                            migrateLegacy = historyStore?.exists() != true
                            historyStore?.read().orEmpty()
                        }
                        val now = Instant.now()
                        val current = _state.value.accessories.associateBy { it.id }
                        val restored = cached.map { a ->
                            val history = LocationHistory.merge(a.id, a.history + current[a.id]?.history.orEmpty(), now)
                            withIcon(a.copy(history = history, latestReport = history.lastOrNull()))
                        }.let { saved -> saved + current.values.filter { a -> saved.none { it.id == a.id } } }
                            .sortedWith(latestActivityFirst)
                        if (restored.isNotEmpty()) _state.update { it.copy(accessories = restored, loadedOnce = true) }
                        historyLoaded = true
                    } catch (e: kotlinx.coroutines.CancellationException) { throw e
                    } catch (_: Exception) {
                        // Do not overwrite an unreadable archive, e.g. during a transient Keystore failure.
                        _state.update { it.copy(historyStorageFailed = true) }
                    }
                }
                val list = backend.getAccessories()
                val now = Instant.now()
                val reports = if (list.isEmpty()) emptyList() else runCatching { backend.fetchReports(list.map { it.id }) }
                    .getOrElse { e -> if (e is OpenFinderException && e.error is OpenFinderError.ReportsUnavailable) emptyList() else throw e }
                val byId = reports.groupBy { it.accessoryId }
                val previous = _state.value.accessories.associateBy { it.id }
                val legacy = if (migrateLegacy) withContext(Dispatchers.IO) { legacyReports?.read().orEmpty() } else emptyMap()
                val merged = list.map {
                    // Apple may return only the latest batch. Keep older sightings and deduplicate overlap.
                    val seed = legacy[it.id]?.let { r -> LocationReport(it.id, r.latitude, r.longitude, r.observedAt, r.accuracyMeters) }
                    val history = LocationHistory.merge(it.id, previous[it.id]?.history.orEmpty() + it.history +
                        listOfNotNull(it.latestReport, seed) + byId[it.id].orEmpty(), now)
                    it.copy(history = history, latestReport = history.lastOrNull())
                }
                    .map(::withIcon).sortedWith(latestActivityFirst)
                val waiting = merged.isNotEmpty() && merged.none { a -> a.latestReport != null }
                val storageFailed = if (!historyLoaded) true else try {
                    withContext(Dispatchers.IO) { historyStore?.write(merged) }
                    migrateLegacy = false
                    false
                } catch (e: kotlinx.coroutines.CancellationException) { throw e
                } catch (_: Exception) { true }
                _state.update {
                    it.copy(accessories = merged, loadedOnce = true, refreshing = false, lastRefresh = now,
                        waitingForReports = waiting,
                        error = null, historyStorageFailed = storageFailed)
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: OpenFinderException) {
                // "No reports available" is the tag-not-seen-yet case, not a failure to show in red.
                if (e.error is OpenFinderError.ReportsUnavailable) {
                    _state.update { it.copy(refreshing = false, loadedOnce = true, waitingForReports = it.accessories.isNotEmpty(), error = null) }
                } else {
                    _state.update { it.copy(refreshing = false, loadedOnce = true, error = e.error) }
                }
            } catch (e: Exception) {
                _state.update { it.copy(refreshing = false, loadedOnce = true, error = OpenFinderError.Backend()) }
            }
        } finally {
            refreshLock.unlock()
        }
    }

    /** Remembers the user's icon for [id] and applies it right away. */
    fun setIcon(id: String, type: com.sacca.openfinder.domain.AccessoryType) {
        icons?.set(id, type)
        _state.update { s -> s.copy(accessories = s.accessories.map { if (it.id == id) it.copy(type = type) else it }) }
    }

    private fun withIcon(a: Accessory): Accessory = icons?.get(a.id)?.let { a.copy(type = it) } ?: a

    suspend fun clearCache() = refreshLock.withLock {
        withContext(Dispatchers.IO) { historyStore?.clear(); legacyReports?.clear() }
        historyLoaded = true
        migrateLegacy = false
        _state.value = RepositoryState()
    }

    private companion object {
        /** Most recently reported first; accessories without a report go last, by name. */
        val latestActivityFirst = compareByDescending<Accessory> { it.latestReport?.observedAt }.thenBy { it.name.lowercase() }
    }
}
