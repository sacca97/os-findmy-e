package com.sacca.openfinder

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.createSavedStateHandle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.sacca.openfinder.ui.map.MapScreen
import com.sacca.openfinder.ui.selftest.SelfTestRunner
import com.sacca.openfinder.ui.selftest.SelfTestViewModel
import com.sacca.openfinder.ui.theme.OpenFinderTheme
import com.sacca.openfinder.viewmodel.MapViewModel
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val container = (application as OpenFinderApp).container
        val runner = SelfTestRunner(applicationContext, container.anisette, container::gsaClient, container.machineStorage)

        // Warm the native library in the background so the first real request is not slow (a missing machine is fine).
        lifecycleScope.launch { container.anisette.warmUp(); container.liveBackend.warmUp() }

        // Automation (debug): `adb shell am start -n com.sacca.openfinder/.MainActivity --ez selftest true`, then
        // `adb logcat -d -s OpenFinderSelfTest`. Installs the bundled test machine if none is installed. Timings and sizes only.
        if (BuildConfig.DEBUG && intent.getBooleanExtra("selftest", false)) {
            lifecycleScope.launch {
                if (!runner.machinePresent()) runner.importBundled()
                runner.run()
            }
        }

        setContent {
            OpenFinderTheme {
                val vm: MapViewModel = viewModel(factory = viewModelFactory {
                    initializer { MapViewModel(container, createSavedStateHandle()) }
                })
                val selfTestVm: SelfTestViewModel? = if (BuildConfig.DEBUG) {
                    viewModel(factory = viewModelFactory { initializer { SelfTestViewModel(runner) } })
                } else null
                val accountVm: com.sacca.openfinder.ui.account.AccountViewModel = viewModel(factory = viewModelFactory {
                    initializer { com.sacca.openfinder.ui.account.AccountViewModel(container) { vm.refresh() } }
                })
                MapScreen(vm, selfTestVm, accountVm)
            }
        }
    }
}
