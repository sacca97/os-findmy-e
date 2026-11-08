package com.sacca.openfinder.viewmodel

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sacca.openfinder.AppContainer
import com.sacca.openfinder.domain.Accessory
import com.sacca.openfinder.domain.OpenFinderError
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.time.Instant

data class MapUiState(
    val accessories: List<Accessory> = emptyList(),
    val selectedId: String? = null,
    val loadedOnce: Boolean = false,
    val refreshing: Boolean = false,
    val error: OpenFinderError? = null,
    val waitingForReports: Boolean = false,
    val historyWindow: java.time.Duration = DEFAULT_HISTORY_WINDOW,
    val now: Instant = Instant.now(),
    val fitAllTick: Int = 0,
) {
    companion object {
        /** Matches the vendor app's track options; the fetch window itself is 7 days. */
        val DEFAULT_HISTORY_WINDOW: java.time.Duration = java.time.Duration.ofHours(6)
    }
}

class MapViewModel(
    private val container: AppContainer,
    private val saved: SavedStateHandle,
) : ViewModel() {
    private val repository = container.repository
    private val fitTick = MutableStateFlow(0)
    private val clock = MutableStateFlow(Instant.now())
    private val historyWindow = MutableStateFlow(MapUiState.DEFAULT_HISTORY_WINDOW)

    /** The selected accessory survives rotation and process death (SavedStateHandle). */
    private val selectedId: StateFlow<String?> = saved.getStateFlow<String?>("selected", null)

    val uiState: StateFlow<MapUiState> = combine(repository.state, selectedId, fitTick, clock, historyWindow) { values ->
        val repo = values[0] as com.sacca.openfinder.data.RepositoryState
        val sel = values[1] as String?
        val tick = values[2] as Int
        val now = values[3] as Instant
        val window = values[4] as java.time.Duration
        MapUiState(
            accessories = repo.accessories,
            selectedId = sel?.takeIf { id -> repo.accessories.any { it.id == id } },
            loadedOnce = repo.loadedOnce, refreshing = repo.refreshing, error = repo.error,
            waitingForReports = repo.waitingForReports,
            historyWindow = window,
            now = now, fitAllTick = tick,
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), MapUiState())

    fun setHistoryWindow(d: java.time.Duration) { historyWindow.value = d }

    init {
        refresh()
        viewModelScope.launch {                       // keeps "4 min ago" honest while the screen is open
            while (true) { delay(30_000); clock.value = Instant.now() }
        }
    }

    fun refresh() { viewModelScope.launch { repository.refresh(); clock.value = Instant.now() } }
    fun select(id: String?) { saved["selected"] = id }
    fun fitAll() { select(null); fitTick.value += 1 }
    fun clearCache() { repository.clearCache(); select(null) }

    fun setIcon(id: String, type: com.sacca.openfinder.domain.AccessoryType) = repository.setIcon(id, type)
}
