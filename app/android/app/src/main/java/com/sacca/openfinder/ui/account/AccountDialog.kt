package com.sacca.openfinder.ui.account

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.RadioButton
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/** Setup of the live backend: machine, Apple sign-in (with 2FA), accessory keys. Nothing is sent until a button is pressed. */
@Composable
fun AccountDialog(vm: AccountViewModel, onDismiss: () -> Unit) {
    val ui by vm.state.collectAsStateWithLifecycle()
    AlertDialog(
        onDismissRequest = { if (!ui.busy) onDismiss() },
        confirmButton = { TextButton(onClick = onDismiss, enabled = !ui.busy) { Text("Close") } },
        title = { Text("Apple account") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                when (val step = ui.step) {
                    AccountStep.Loading -> CircularProgressIndicator()
                    AccountStep.NoMachine -> {
                        Text("This phone must first be registered with Apple as a machine (one time). It contacts Apple.")
                        val context = LocalContext.current
                        val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
                            uri?.let { context.contentResolver.openInputStream(it)?.use { s -> vm.importCoreAdi(s.readBytes()) } }
                        }
                        Text("It also needs Apple's CoreADI file for macOS (x86_64), which this app does not include.", style = MaterialTheme.typography.bodySmall)
                        OutlinedButton(onClick = vm::downloadCoreAdi, enabled = !ui.busy, modifier = Modifier.fillMaxWidth()) { Text("Download CoreADI (external source)") }
                        OutlinedButton(onClick = { picker.launch(arrayOf("*/*")) }, enabled = !ui.busy, modifier = Modifier.fillMaxWidth()) { Text("Import CoreADI file") }
                        Button(onClick = vm::provision, enabled = !ui.busy, modifier = Modifier.fillMaxWidth()) { Text("Register this phone") }
                    }
                    AccountStep.SignIn -> SignIn(ui.busy, vm::signIn)
                    is AccountStep.TwoFactor -> {
                        var code by remember { mutableStateOf("") }
                        OutlinedTextField(code, { code = it.filter(Char::isDigit).take(8) }, label = { Text("Verification code") },
                            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.NumberPassword), singleLine = true)
                        Button(onClick = { vm.submitCode(step.challengeId, code) }, enabled = !ui.busy && code.length >= 4, modifier = Modifier.fillMaxWidth()) { Text("Verify") }
                    }
                    is AccountStep.Discover -> Discover(step, ui.busy, vm)
                    is AccountStep.Ready -> {
                        Text("Signed in." + if (step.accessories > 0) " ${step.accessories} accessories found." else "")
                        OutlinedButton(onClick = vm::signOut, enabled = !ui.busy, modifier = Modifier.fillMaxWidth()) { Text("Sign out and forget accessories") }
                    }
                }
                if (ui.busy) CircularProgressIndicator()
                ui.message?.let {
                    Text(if (ui.isError) "Failed: $it" else it, style = MaterialTheme.typography.bodyMedium,
                        color = if (ui.isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
                }
            }
        },
    )
}

@Composable
private fun SignIn(busy: Boolean, onSignIn: (String, CharArray) -> Unit) {
    var user by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    OutlinedTextField(user, { user = it }, label = { Text("Apple ID") }, singleLine = true,
        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Email))
    OutlinedTextField(pass, { pass = it }, label = { Text("Password") }, singleLine = true, visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Password))
    Text("The password is used for this sign-in only and is never stored.", style = MaterialTheme.typography.bodySmall)
    Button(onClick = { onSignIn(user, pass.toCharArray()); pass = "" }, enabled = !busy && user.isNotBlank() && pass.isNotEmpty(), modifier = Modifier.fillMaxWidth()) { Text("Sign in") }
}

@Composable
private fun Discover(step: AccountStep.Discover, busy: Boolean, vm: AccountViewModel) {
    val context = LocalContext.current
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { context.contentResolver.openInputStream(it)?.use { s -> vm.importAccessories(String(s.readBytes())) } }
    }
    var password by remember { mutableStateOf("") }
    var passcode by remember { mutableStateOf("") }
    var chosen by remember { mutableIntStateOf(0) }
    Text("No accessories yet. To read your tags' keys, Apple requires the screen-lock passcode of one of your devices.")
    if (step.needsPassword) {
        Text("The app was restarted since you signed in, so Apple needs your password once more.", style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(password, { password = it }, label = { Text("Apple ID password") }, singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Password))
    }
    val records = step.records
    if (records == null) {
        Button(onClick = { vm.listRecords(password.takeIf { it.isNotEmpty() }?.toCharArray()) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Find my devices") }
    } else {
        // Default to the first device; a stale index (records reloaded) falls back to it too.
        val selected = records.firstOrNull { it.index == chosen } ?: records.firstOrNull()
        Text("Choose the device whose screen-lock passcode you will enter:", style = MaterialTheme.typography.labelLarge)
        records.forEach { r ->
            val isSelected = r.index == selected?.index
            Row(
                Modifier.fillMaxWidth().selectable(selected = isSelected, enabled = !busy, role = Role.RadioButton) { chosen = r.index }
                    .background(if (isSelected) MaterialTheme.colorScheme.primaryContainer else Color.Transparent, MaterialTheme.shapes.small)
                    .padding(horizontal = 4.dp, vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = isSelected, onClick = null, modifier = Modifier.padding(8.dp))
                Text(r.description, style = MaterialTheme.typography.bodyMedium)
            }
        }
        var showPasscode by remember { mutableStateOf(false) }
        OutlinedTextField(passcode, { passcode = it }, label = { Text("Passcode of ${selected?.description ?: "the selected device"}") }, singleLine = true,
            visualTransformation = if (showPasscode) VisualTransformation.None else PasswordVisualTransformation(),
            trailingIcon = { TextButton(onClick = { showPasscode = !showPasscode }) { Text(if (showPasscode) "Hide" else "Show") } },
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Password), modifier = Modifier.fillMaxWidth())
        Text("One attempt is sent and never retried; Apple limits wrong guesses.", style = MaterialTheme.typography.bodySmall)
        Button(onClick = { selected?.let { vm.discover(it.index, passcode.toCharArray(), password.takeIf { p -> p.isNotEmpty() }?.toCharArray()) }; passcode = "" },
            enabled = !busy && passcode.isNotEmpty() && selected != null, modifier = Modifier.fillMaxWidth()) { Text("Unlock and read accessories") }
    }
    OutlinedButton(onClick = { picker.launch(arrayOf("application/json", "*/*")) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Import accessory keys file instead") }
}
