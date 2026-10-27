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
    val now: Instant = Instant.now(),
    val fitAllTick: Int = 0,
)

class MapViewModel(
    private val container: AppContainer,
    private val saved: SavedStateHandle,
) : ViewModel() {
    private val repository = container.repository
    private val fitTick = MutableStateFlow(0)
    private val clock = MutableStateFlow(Instant.now())

    /** The selected accessory survives rotation and process death (SavedStateHandle). */
    private val selectedId: StateFlow<String?> = saved.getStateFlow<String?>("selected", null)

    val uiState: StateFlow<MapUiState> = combine(repository.state, selectedId, fitTick, clock) { values ->
        val repo = values[0] as com.sacca.openfinder.data.RepositoryState
        val sel = values[1] as String?
        val tick = values[2] as Int
        val now = values[3] as Instant
        MapUiState(
            accessories = repo.accessories,
            selectedId = sel?.takeIf { id -> repo.accessories.any { it.id == id } },
            loadedOnce = repo.loadedOnce, refreshing = repo.refreshing, error = repo.error,
            now = now, fitAllTick = tick,
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), MapUiState())

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
