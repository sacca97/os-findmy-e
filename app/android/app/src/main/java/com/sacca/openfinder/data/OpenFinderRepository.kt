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
import java.time.Instant

data class RepositoryState(
    val accessories: List<Accessory> = emptyList(),
    val loadedOnce: Boolean = false,
    val refreshing: Boolean = false,
    val lastRefresh: Instant? = null,
    val error: OpenFinderError? = null,
)

/**
 * Single source of truth for the UI. Keeps the last good data when a refresh fails (offline use) and drops
 * malformed reports instead of showing them. Works with any [OpenFinderBackend].
 */
class OpenFinderRepository(private val backend: OpenFinderBackend, private val icons: IconStore? = null) {
    private val _state = MutableStateFlow(RepositoryState())
    val state: StateFlow<RepositoryState> = _state.asStateFlow()
    private val refreshLock = Mutex()

    suspend fun refresh() {
        if (!refreshLock.tryLock()) return                 // a refresh is already running: do not stack them
        try {
            _state.update { it.copy(refreshing = true, error = null) }
            try {
                val list = backend.getAccessories()
                val now = Instant.now()
                val reports = if (list.isEmpty()) emptyList() else runCatching { backend.fetchReports(list.map { it.id }) }
                    .getOrElse { e -> if (e is OpenFinderException && e.error is OpenFinderError.ReportsUnavailable) emptyList() else throw e }
                val byId = reports.filter { it.isValid(now) }.groupBy { it.accessoryId }
                    .mapValues { (_, v) -> v.maxBy { it.observedAt } }
                val previous = _state.value.accessories.associateBy { it.id }
                val merged = list.map { it.copy(latestReport = byId[it.id] ?: previous[it.id]?.latestReport ?: it.latestReport) }
                    .map(::withIcon).sortedWith(latestActivityFirst)
                _state.update {
                    it.copy(accessories = merged, loadedOnce = true, refreshing = false, lastRefresh = now,
                        error = if (merged.isNotEmpty() && merged.none { a -> a.latestReport != null }) OpenFinderError.ReportsUnavailable() else null)
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: OpenFinderException) {
                _state.update { it.copy(refreshing = false, loadedOnce = true, error = e.error) }
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

    fun clearCache() {
        _state.update { RepositoryState() }
    }

    private companion object {
        /** Most recently reported first; accessories without a report go last, by name. */
        val latestActivityFirst = compareByDescending<Accessory> { it.latestReport?.observedAt }.thenBy { it.name.lowercase() }
    }
}
