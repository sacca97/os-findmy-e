package com.sacca.openfinder.ui.map

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Place
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.BottomSheetScaffold
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.SheetValue
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberBottomSheetScaffoldState
import androidx.compose.material3.rememberStandardBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.sacca.openfinder.BuildConfig
import com.sacca.openfinder.domain.Accessory
import com.sacca.openfinder.ui.components.AccessorySheet
import com.sacca.openfinder.ui.selftest.SelfTestScreen
import com.sacca.openfinder.ui.selftest.SelfTestViewModel
import com.sacca.openfinder.viewmodel.MapViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MapScreen(vm: MapViewModel, selfTestVm: SelfTestViewModel?, accountVm: com.sacca.openfinder.ui.account.AccountViewModel) {
    val ui by vm.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    var showSettings by rememberSaveable { mutableStateOf(false) }
    var showSelfTest by rememberSaveable { mutableStateOf(false) }
    var showAccount by rememberSaveable { mutableStateOf(false) }
    // Location is only used to draw "you are here"; asked once at start, and again by the button if it was refused.
    var locationGranted by remember { mutableStateOf(hasLocationPermission(context)) }
    var locateTick by rememberSaveable { mutableStateOf(0) }
    val askLocation = androidx.activity.compose.rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestMultiplePermissions(),
    ) { locationGranted = hasLocationPermission(context); if (locationGranted) locateTick += 1 }
    var askedOnce by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        if (!locationGranted && !askedOnce) {
            askedOnce = true
            askLocation.launch(arrayOf(android.Manifest.permission.ACCESS_FINE_LOCATION, android.Manifest.permission.ACCESS_COARSE_LOCATION))
        }
    }

    val sheetState = rememberStandardBottomSheetState(initialValue = SheetValue.PartiallyExpanded, skipHiddenState = true)
    val scaffoldState = rememberBottomSheetScaffoldState(sheetState)
    val navBottom = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()
    val statusTop = WindowInsets.statusBars.asPaddingValues().calculateTopPadding()
    val peek = 292.dp

    // Back first deselects, then leaves the app.
    BackHandler(enabled = ui.selectedId != null) { vm.select(null) }

    fun openInMaps(a: Accessory) {
        val r = a.latestReport ?: return
        val uri = Uri.parse("geo:${r.latitude},${r.longitude}?q=${r.latitude},${r.longitude}(${Uri.encode(a.name)})")
        try { context.startActivity(Intent(Intent.ACTION_VIEW, uri)) } catch (_: ActivityNotFoundException) { /* no maps app installed */ }
    }

    BottomSheetScaffold(
        scaffoldState = scaffoldState,
        sheetPeekHeight = peek + navBottom,
        sheetShape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
        sheetContainerColor = MaterialTheme.colorScheme.surface,
        sheetContent = {
            AccessorySheet(
                accessories = ui.accessories, selectedId = ui.selectedId, loadedOnce = ui.loadedOnce,
                refreshing = ui.refreshing, error = ui.error, now = ui.now,
                onSetup = { accountVm.reload(); showAccount = true }, onChangeIcon = vm::setIcon,
                onSelect = vm::select, onFitAll = vm::fitAll, onRefresh = vm::refresh, onOpenInMaps = ::openInMaps,
                modifier = Modifier.padding(bottom = 4.dp),
            )
        },
    ) {
        Box(Modifier.fillMaxSize()) {
            AccessoryMap(
                accessories = ui.accessories, selectedId = ui.selectedId, fitAllTick = ui.fitAllTick,
                darkTheme = isSystemInDarkTheme(),
                viewportInsets = PaddingValues(top = statusTop + 72.dp, bottom = peek + navBottom),
                onAccessoryClick = vm::select,
                showMyLocation = locationGranted, locateTick = locateTick,
                modifier = Modifier.fillMaxSize(),
            )
            androidx.compose.material3.SmallFloatingActionButton(
                onClick = {
                    if (locationGranted) locateTick += 1
                    else askLocation.launch(arrayOf(android.Manifest.permission.ACCESS_FINE_LOCATION, android.Manifest.permission.ACCESS_COARSE_LOCATION))
                },
                modifier = Modifier.align(Alignment.BottomEnd).padding(end = 16.dp, bottom = peek + navBottom + 16.dp),
            ) { Icon(Icons.Default.Place, contentDescription = "My location") }
            TopBar(refreshing = ui.refreshing, onRefresh = vm::refresh, onSettings = { showSettings = true })
        }
    }

    if (showSettings) {
        SettingsDialog(
            onClearCache = vm::clearCache,
            onOpenAccount = { showSettings = false; accountVm.reload(); showAccount = true },
            onOpenSelfTest = if (selfTestVm != null) ({ showSettings = false; showSelfTest = true }) else null,
            onDismiss = { showSettings = false },
        )
    }

    if (showAccount) com.sacca.openfinder.ui.account.AccountDialog(accountVm, onDismiss = { showAccount = false })

    // Debug-only full-screen self-test of the native Anisette library (on top of everything; Back closes it).
    if (showSelfTest && selfTestVm != null) {
        BackHandler { showSelfTest = false }
        SelfTestScreen(selfTestVm, onClose = { showSelfTest = false })
    }
}

@Composable
private fun TopBar(refreshing: Boolean, onRefresh: () -> Unit, onSettings: () -> Unit) {
    Surface(
        modifier = Modifier.statusBarsPadding().padding(horizontal = 16.dp, vertical = 8.dp).fillMaxWidth(),
        shape = RoundedCornerShape(28.dp),
        color = MaterialTheme.colorScheme.surface.copy(alpha = 0.88f),
        tonalElevation = 3.dp, shadowElevation = 4.dp,
    ) {
        Column {
            Row(Modifier.padding(start = 20.dp, end = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("OpenFinder", Modifier.weight(1f), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
                IconButton(onClick = onRefresh, enabled = !refreshing) { Icon(Icons.Default.Refresh, contentDescription = "Refresh") }
                IconButton(onClick = onSettings) { Icon(Icons.Default.Settings, contentDescription = "Settings") }
            }
            if (refreshing) LinearProgressIndicator(Modifier.fillMaxWidth().padding(horizontal = 20.dp))
        }
    }
}

@Composable
private fun SettingsDialog(
    onClearCache: () -> Unit,
    onOpenAccount: () -> Unit,
    onOpenSelfTest: (() -> Unit)?,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text("Done") } },
        title = { Text("Settings") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onOpenAccount, Modifier.fillMaxWidth()) { Text("Apple account…") }
                OutlinedButton(onClick = onClearCache, Modifier.fillMaxWidth()) { Text("Clear cached information") }
                if (onOpenSelfTest != null) {
                    OutlinedButton(onClick = onOpenSelfTest, Modifier.fillMaxWidth()) { Text("Anisette self-test (debug)") }
                }
                Text("Version ${BuildConfig.VERSION_NAME}", style = MaterialTheme.typography.bodySmall)
                Text("Map data © OpenStreetMap contributors · OpenFreeMap", style = MaterialTheme.typography.bodySmall)
            }
        },
    )
}

@Composable
private fun RadioRow(label: String, selected: Boolean, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().selectable(selected = selected, role = Role.RadioButton, onClick = onClick),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = null)
        Text(label, Modifier.padding(start = 12.dp, top = 6.dp, bottom = 6.dp))
    }
}

private fun hasLocationPermission(context: android.content.Context): Boolean =
    androidx.core.content.ContextCompat.checkSelfPermission(context, android.Manifest.permission.ACCESS_FINE_LOCATION) == android.content.pm.PackageManager.PERMISSION_GRANTED ||
        androidx.core.content.ContextCompat.checkSelfPermission(context, android.Manifest.permission.ACCESS_COARSE_LOCATION) == android.content.pm.PackageManager.PERMISSION_GRANTED
