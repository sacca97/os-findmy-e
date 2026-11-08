package com.sacca.openfinder.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sacca.openfinder.domain.Accessory
import com.sacca.openfinder.domain.OpenFinderError
import java.time.Instant

/** Track window options, mirroring the vendor app's track menu; the fetch window covers all of them (7 days). */
enum class HistoryWindow(val label: String, val duration: java.time.Duration) {
    H6("6 h", java.time.Duration.ofHours(6)),
    H24("24 h", java.time.Duration.ofHours(24)),
    D3("3 d", java.time.Duration.ofDays(3)),
    D7("7 d", java.time.Duration.ofDays(7)),
}

/** Content of the draggable bottom sheet: header, state banners and the accessory list. */
@Composable
fun AccessorySheet(
    accessories: List<Accessory>,
    selectedId: String?,
    loadedOnce: Boolean,
    refreshing: Boolean,
    error: OpenFinderError?,
    waitingForReports: Boolean,
    now: Instant,
    onSelect: (String) -> Unit,
    onFitAll: () -> Unit,
    onRefresh: () -> Unit,
    onOpenInMaps: (Accessory) -> Unit,
    onSetup: () -> Unit,
    onChangeIcon: (String, com.sacca.openfinder.domain.AccessoryType) -> Unit,
    /** Optional slot under the banners: the read-only BLE rekey check (see ble/RekeyCheck.kt). */
    rekeyCheck: (@Composable () -> Unit)? = null,
    /** Optional slot under the rekey check: ring + battery for a verified nearby tag (ble/TagTools.kt). */
    tagTools: (@Composable () -> Unit)? = null,
    historyWindow: java.time.Duration = java.time.Duration.ofHours(6),
    onHistoryWindow: (java.time.Duration) -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val listState = rememberLazyListState()
    LaunchedEffect(selectedId, accessories.size) {
        val index = accessories.indexOfFirst { it.id == selectedId }
        if (index >= 0) listState.animateScrollToItem(index)
    }
    Column(modifier.fillMaxWidth()) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 20.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                if (accessories.isEmpty()) "My accessories" else "My accessories · ${accessories.size}",
                style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold,
            )
            if (accessories.size > 1) TextButton(onClick = onFitAll) { Text("Show all") }
        }
        if (accessories.any { it.history.size > 1 }) {
            // Track window: the same options the fetch window can fill (7 days).
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                HistoryWindow.entries.forEach { w ->
                    androidx.compose.material3.FilterChip(
                        selected = historyWindow == w.duration,
                        onClick = { onHistoryWindow(w.duration) },
                        label = { Text(w.label) },
                    )
                }
            }
        }
        if (error != null) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(error.message, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
                if (error is OpenFinderError.Authentication) TextButton(onClick = onSetup) { Text("Set up") }
                TextButton(onClick = onRefresh) { Text("Retry") }
            }
        } else if (waitingForReports) {
            // Quiet informational state: the tag is ours and installed, but no iPhone has reported it yet.
            Text(
                "Waiting for the first report — no nearby iPhone has seen this tag's signal yet.",
                Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 4.dp),
                style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        rekeyCheck?.invoke()
        tagTools?.invoke()
        when {
            !loadedOnce && refreshing -> Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
            loadedOnce && accessories.isEmpty() && error == null -> Box(Modifier.fillMaxWidth().padding(28.dp), contentAlignment = Alignment.Center) {
                Text("No accessories yet.\nOpen Settings > Apple account to sign in and find your tags.",
                    style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            else -> LazyColumn(
                state = listState,
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 6.dp, bottom = 16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.navigationBarsPadding(),
            ) {
                items(accessories, key = { it.id }) { a ->
                    AccessoryCard(
                        accessory = a, selected = a.id == selectedId, now = now,
                        onClick = { onSelect(a.id) }, onOpenInMaps = { onOpenInMaps(a) }, onRefresh = onRefresh,
                        onChangeIcon = { onChangeIcon(a.id, it) },
                    )
                }
            }
        }
    }
}
