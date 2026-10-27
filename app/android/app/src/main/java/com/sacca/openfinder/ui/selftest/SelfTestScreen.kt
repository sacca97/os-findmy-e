package com.sacca.openfinder.ui.selftest

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.IconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class SelfTestState(val machinePresent: Boolean, val running: Boolean = false, val log: List<String> = emptyList())

class SelfTestViewModel(private val runner: SelfTestRunner) : ViewModel() {
    private val _state = MutableStateFlow(SelfTestState(machinePresent = false))
    val state: StateFlow<SelfTestState> = _state

    init { viewModelScope.launch { _state.update { it.copy(machinePresent = runner.machinePresent()) } } }

    private fun launch(block: suspend () -> List<String>) {
        if (_state.value.running) return
        _state.update { it.copy(running = true, log = listOf("Running...")) }
        viewModelScope.launch {
            val lines = block()
            _state.update { SelfTestState(runner.machinePresent(), running = false, log = lines) }
        }
    }

    fun importBundled() = launch { listOf(runner.importBundled()) }
    fun importFrom(uri: Uri) = launch { listOf(runner.importFrom(uri)) }
    fun remove() = launch { listOf(runner.remove()) }
    fun run() = launch { runner.run() }
    fun provisionNew() = launch { runner.provisionNew() }
}

/** Debug-only screen: install a machine (file picker or the bundled test machine) and prove headers() works on this device. */
@Composable
fun SelfTestScreen(vm: SelfTestViewModel, onClose: () -> Unit) {
    val state by vm.state.collectAsStateWithLifecycle()
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> if (uri != null) vm.importFrom(uri) }
    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(Modifier.safeDrawingPadding().padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("Anisette self-test", Modifier.weight(1f), style = MaterialTheme.typography.headlineSmall)
                IconButton(onClick = onClose) { Icon(Icons.Default.Close, contentDescription = "Close") }
            }
            Text("Debug only. Shows timings and sizes, never header values.", style = MaterialTheme.typography.bodyMedium)
            Text("Machine: ${if (state.machinePresent) "installed (encrypted at rest)" else "none"}", style = MaterialTheme.typography.titleMedium)
            Button(onClick = { picker.launch(arrayOf("application/json", "text/plain", "application/octet-stream", "*/*")) }, enabled = !state.running, modifier = Modifier.fillMaxWidth()) {
                Text("Import machine file…")
            }
            OutlinedButton(onClick = vm::importBundled, enabled = !state.running, modifier = Modifier.fillMaxWidth()) { Text("Use bundled test machine") }
            Button(onClick = vm::run, enabled = !state.running && state.machinePresent, modifier = Modifier.fillMaxWidth()) { Text("Run headers() test") }
            OutlinedButton(onClick = vm::remove, enabled = !state.running && state.machinePresent, modifier = Modifier.fillMaxWidth()) { Text("Remove machine") }
            // Contacting Apple is deliberate: the first tap only arms the button.
            var armed by remember { mutableStateOf(false) }
            OutlinedButton(
                onClick = { if (armed) { armed = false; vm.provisionNew() } else armed = true },
                enabled = !state.running && !state.machinePresent,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (armed) "Tap again: contact Apple and provision" else "Provision a NEW machine (contacts Apple)") }
            Column(Modifier.verticalScroll(rememberScrollState())) {
                state.log.forEach { Text(it, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace) }
            }
        }
    }
}
