package com.sacca.openfinder.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sacca.openfinder.domain.Accessory
import com.sacca.openfinder.ui.map.typeColor
import java.time.Instant

/**
 * One accessory in the list. Tapping selects it (the map flies there); when selected the card expands into the detail
 * panel. Reports are labelled with their real age and called "cached": this is never live tracking.
 */
@Composable
fun AccessoryCard(
    accessory: Accessory,
    selected: Boolean,
    now: Instant,
    onClick: () -> Unit,
    onOpenInMaps: () -> Unit,
    onRefresh: () -> Unit,
    onChangeIcon: (com.sacca.openfinder.domain.AccessoryType) -> Unit,
    modifier: Modifier = Modifier,
) {
    val report = accessory.latestReport
    var pickingIcon by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(false) }
    val freshness = report?.let { freshnessOf(it, now) }
    val summary = report?.let { "Seen ${relativeAge(it.observedAt, now)}" } ?: "No location reports yet"
    if (pickingIcon) IconPicker(accessory.type, { onChangeIcon(it); pickingIcon = false }, { pickingIcon = false })
    Card(
        modifier = modifier.fillMaxWidth().animateContentSize().semantics {
            contentDescription = "${accessory.name}. $summary" + if (selected) ". Selected" else ""
        },
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (selected) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.surfaceContainerHigh,
        ),
        border = if (selected) BorderStroke(1.5.dp, MaterialTheme.colorScheme.primary) else null,
    ) {
        Column(Modifier.clickable(onClick = onClick).padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                Box(
                    Modifier.size(46.dp).clip(CircleShape).background(typeColor(accessory.type).copy(alpha = 0.18f)),
                    contentAlignment = Alignment.Center,
                ) { Text(accessory.type.emoji, style = MaterialTheme.typography.titleLarge) }
                Column(Modifier.weight(1f)) {
                    Text(accessory.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        if (freshness != null) Box(Modifier.size(9.dp).clip(CircleShape).background(freshness.color))
                        Text(summary, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            AnimatedVisibility(selected) {
                Column(Modifier.padding(top = 14.dp)) {
                    if (report == null) {
                        Text("Nothing reported for this accessory yet. Pull a refresh later.", style = MaterialTheme.typography.bodyMedium)
                    } else {
                        DetailRow("Location", coordinates(report))
                        DetailRow("Reported", absoluteTime(report.observedAt))
                        accuracyText(report.horizontalAccuracyMeters)?.let { DetailRow("Accuracy", it) }
                        DetailRow("Status", "${freshness!!.label} · cached report, not live tracking")
                    }
                    Spacer(Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        if (report != null) Button(onClick = onOpenInMaps) { Text("Open in Maps") }
                        OutlinedButton(onClick = onRefresh) { Text("Refresh") }
                        OutlinedButton(onClick = { pickingIcon = true }) { Text("Icon") }
                    }
                }
            }
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
    }
}

/** Lets the user pick an icon for an accessory; the choice is remembered per accessory. */
@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun IconPicker(current: com.sacca.openfinder.domain.AccessoryType, onPick: (com.sacca.openfinder.domain.AccessoryType) -> Unit, onDismiss: () -> Unit) {
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { androidx.compose.material3.TextButton(onClick = onDismiss) { Text("Cancel") } },
        title = { Text("Choose an icon") },
        text = {
            androidx.compose.foundation.layout.FlowRow(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                com.sacca.openfinder.domain.AccessoryType.entries.forEach { t ->
                    Column(
                        Modifier.clip(RoundedCornerShape(14.dp))
                            .background(if (t == current) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.surfaceContainerHigh)
                            .clickable { onPick(t) }.padding(horizontal = 12.dp, vertical = 8.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Text(t.emoji, style = MaterialTheme.typography.headlineSmall)
                        Text(t.label, style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
        },
    )
}
