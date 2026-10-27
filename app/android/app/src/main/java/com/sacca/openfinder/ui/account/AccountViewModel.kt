package com.sacca.openfinder.ui.account

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sacca.openfinder.AppContainer
import com.sacca.openfinder.anisette.CoreAdiDownloader
import com.sacca.openfinder.domain.AuthResult
import com.sacca.openfinder.domain.AuthState
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import com.sacca.openfinder.domain.RecoveryRecord
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Where the one-time setup of the live backend stands. Each step talks to Apple only when its button is pressed. */
sealed interface AccountStep {
    data object Loading : AccountStep
    data object NoMachine : AccountStep
    data object SignIn : AccountStep
    data class TwoFactor(val challengeId: String) : AccountStep
    data class Discover(val records: List<RecoveryRecord>?, val needsPassword: Boolean) : AccountStep
    data class Ready(val accessories: Int) : AccountStep
}

data class AccountUiState(val step: AccountStep = AccountStep.Loading, val busy: Boolean = false, val message: String? = null, val isError: Boolean = false)

class AccountViewModel(private val container: AppContainer, private val onChanged: () -> Unit) : ViewModel() {
    private val live = container.liveBackend
    private val setup = container.accountSetup
    private val _state = MutableStateFlow(AccountUiState())
    val state: StateFlow<AccountUiState> = _state

    init { reload() }

    fun reload() = run("") { _state.update { it.copy(step = currentStep()) } }

    /** Installs the CoreADI file the user picked (release builds do not bundle Apple's binary). */
    fun importCoreAdi(bytes: ByteArray) = run("") {
        val ok = withContext(Dispatchers.IO) { container.coreAdiImage.import(bytes) }
        _state.update { it.copy(message = if (ok) "CoreADI installed." else "That file is not a 64-bit Mach-O CoreADI.", isError = !ok) }
    }

    /** Downloads CoreADI 4.19 from the pinned external URL; the file is accepted only if its SHA-256 matches. */
    fun downloadCoreAdi() = run("Downloading CoreADI…") {
        val r = withContext(Dispatchers.IO) { CoreAdiDownloader(container.coreAdiImage).download() }
        _state.update { it.copy(message = if (r is CoreAdiDownloader.Result.Failed) r.reason else "CoreADI installed.", isError = r is CoreAdiDownloader.Result.Failed) }
    }

    fun provision() = run("Registering this phone as a machine with Apple…") { setup.provisionMachine(); step(AccountStep.SignIn) }

    fun signIn(username: String, password: CharArray) = run("Signing in…") {
        when (val r = live.startLogin(username.trim(), String(password))) {
            is AuthResult.Success -> step(afterSignIn())
            is AuthResult.TwoFactorRequired -> step(AccountStep.TwoFactor(r.challengeId), "A code was sent to your trusted device or phone.")
            is AuthResult.Failure -> fail(r.error)
        }
    }

    fun submitCode(challengeId: String, code: String) = run("Checking the code…") {
        when (val r = live.submitTwoFactor(challengeId, code.trim())) {
            is AuthResult.Success -> step(afterSignIn())
            is AuthResult.TwoFactorRequired -> step(AccountStep.TwoFactor(r.challengeId))
            is AuthResult.Failure -> fail(r.error)
        }
    }

    /** Lists the devices whose passcode can unlock the keychain (does not send a passcode). */
    fun listRecords(password: CharArray?) = run("Looking up your devices…") {
        step(AccountStep.Discover(setup.recoveryRecords(password), setup.needsPassword()))
    }

    /** ONE passcode guess, never retried. */
    fun discover(index: Int, passcode: CharArray, password: CharArray?) = run("Unlocking and reading your accessories…") {
        val n = setup.discoverAccessories(index, passcode, password)
        onChanged()
        step(AccountStep.Ready(n))
    }

    fun importAccessories(json: String) = run("Importing…") {
        val n = setup.importAccessories(json)
        onChanged()
        step(AccountStep.Ready(n))
    }

    fun signOut() = run("") { live.logout(); step(currentStep()); onChanged() }

    private suspend fun currentStep(): AccountStep = when {
        !setup.hasMachine() -> AccountStep.NoMachine
        live.getAuthState() != AuthState.Authenticated -> AccountStep.SignIn
        setup.hasAccessories() -> AccountStep.Ready(0)
        else -> AccountStep.Discover(null, setup.needsPassword())
    }

    private suspend fun afterSignIn(): AccountStep = if (setup.hasAccessories()) { onChanged(); AccountStep.Ready(0) } else AccountStep.Discover(null, setup.needsPassword())

    private fun step(s: AccountStep, message: String? = null) = _state.update { it.copy(step = s, message = message, isError = false) }
    private fun fail(e: OpenFinderError) = _state.update { it.copy(message = e.message, isError = true) }

    private fun run(busyText: String, block: suspend () -> Unit) {
        if (_state.value.busy) return
        viewModelScope.launch {
            _state.update { it.copy(busy = busyText.isNotEmpty(), message = busyText.ifEmpty { null }, isError = false) }
            try { block() } catch (e: OpenFinderException) { fail(e.error) } catch (e: Exception) { fail(OpenFinderError.Backend()) }
            _state.update { it.copy(busy = false) }
        }
    }
}
