package com.sacca.openfinder

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
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
    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (BuildConfig.DEBUG && intent.getBooleanExtra("fetch", false)) {
            lifecycleScope.launch {
                androidx.work.WorkManager.getInstance(applicationContext).enqueue(
                    androidx.work.OneTimeWorkRequestBuilder<com.sacca.openfinder.work.FetchWorker>().build())
            }
        }
    }

    private val requestNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* the worker simply stays silent when denied */ }

    private fun requestNotificationPermissionOnce() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) requestNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        requestNotificationPermissionOnce()
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
        // Automation (debug): `--ez fetch true` runs the background worker once without waiting for the period.
        if (BuildConfig.DEBUG && intent.getBooleanExtra("fetch", false)) {
            lifecycleScope.launch {
                androidx.work.WorkManager.getInstance(applicationContext).enqueue(
                    androidx.work.OneTimeWorkRequestBuilder<com.sacca.openfinder.work.FetchWorker>().build())
            }
        }
        // Automation (debug): `--ez import_static true` imports static tag keys pushed by rotate_key.sh to the
        // app's own external files dir (readable without storage permissions). Logs count only, never key material.
        if (BuildConfig.DEBUG && intent.getBooleanExtra("import_static", false)) {
            lifecycleScope.launch {
                val tag = "OpenFinderImport"
                try {
                    val file = java.io.File(getExternalFilesDir(null), "mtag-keypair.json")
                    if (!file.exists()) {
                        android.util.Log.i(tag, "no keypair file at ${file.absolutePath}")
                    } else {
                        val n = container.accountSetup.importStaticKeys(file.readText())
                        android.util.Log.i(tag, "imported $n static key(s) from ${file.name}")
                    }
                } catch (e: Exception) {
                    android.util.Log.i(tag, "import failed: ${e::class.java.simpleName}")
                }
            }
        }
        // Automation (debug): `--ez dump_static true` logs the imported static-key count only.
        if (BuildConfig.DEBUG && intent.getBooleanExtra("dump_static", false)) {
            lifecycleScope.launch {
                val tag = "OpenFinderImport"
                try {
                    val hashes = container.accountSetup.staticKeyHashes()
                    android.util.Log.i(tag, "static blob: ${hashes.size} key(s)")
                } catch (e: Exception) {
                    android.util.Log.i(tag, "dump failed: ${e::class.java.simpleName}")
                }
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
