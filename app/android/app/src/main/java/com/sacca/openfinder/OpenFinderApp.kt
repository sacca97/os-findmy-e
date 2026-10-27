package com.sacca.openfinder

import android.app.Application
import android.content.Context
import android.os.StrictMode
import com.sacca.openfinder.anisette.AssetOrFileImageSource
import com.sacca.openfinder.apple.Cooldown
import com.sacca.openfinder.apple.GsaClient
import com.sacca.openfinder.apple.PrefsCooldownStore
import com.sacca.openfinder.anisette.CoreAdiAnisetteProvider
import com.sacca.openfinder.anisette.MachineStorage
import com.sacca.openfinder.data.OpenFinderRepository
import com.sacca.openfinder.data.RustOpenFinderBackend
import com.sacca.openfinder.security.SecretStore
import com.sacca.openfinder.data.IconStore

/** Manual dependency container. The UI only ever sees the backend through [repository]. */
class AppContainer(context: Context) {
    val machineStorage = MachineStorage(context)
    val coreAdiImage = AssetOrFileImageSource(context)
    val anisette = CoreAdiAnisetteProvider(machineStorage, coreAdiImage)
    /** HTTP 429 is an inconsistency error, not a rate limit (GSA-LOGIN-TRANSPORT.md): it is recorded but never blocks a retry. */
    val cooldown = Cooldown(PrefsCooldownStore(context), minutes = 0)
    fun gsaClient(device: com.sacca.openfinder.apple.GsaDevice) = GsaClient(device, cooldown)
    /** The live backend: the whole Apple-side protocol in the Rust library. [accountSetup] is its setup half (machine, keys). */
    val liveBackend = RustOpenFinderBackend(machineStorage, coreAdiImage, SecretStore(context, "openfinder_machine_key"), cooldown)
    val accountSetup: com.sacca.openfinder.domain.AccountSetup = liveBackend

    val repository = OpenFinderRepository(liveBackend, IconStore(context))
}

class OpenFinderApp : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            // Milestone D check, early: report any disk/network work or slow call on the main thread in logcat.
            StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.Builder().detectAll().penaltyLog().build())
        }
        container = AppContainer(this)
    }
}
