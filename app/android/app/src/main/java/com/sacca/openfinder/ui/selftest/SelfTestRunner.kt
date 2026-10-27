package com.sacca.openfinder.ui.selftest

import android.content.Context
import android.net.Uri
import android.util.Log
import com.sacca.openfinder.anisette.CoreAdiAnisetteProvider
import com.sacca.openfinder.anisette.MachineStorage
import com.sacca.openfinder.domain.OpenFinderException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Debug-only checks of the native Anisette library inside the real app. Everything it reports is timings, sizes and
 * typed errors: header values, machine bytes and file contents are never shown or logged.
 */
class SelfTestRunner(
    private val context: Context,
    private val provider: CoreAdiAnisetteProvider,
    private val newClient: (com.sacca.openfinder.apple.GsaDevice) -> com.sacca.openfinder.apple.GsaClient,
    @Suppress("unused") private val storage: MachineStorage,
) {
    suspend fun machinePresent(): Boolean = provider.machinePresent()

    /** Installs the git-ignored test machine bundled into debug builds (prebuilt/dev/test.machine.json). */
    suspend fun importBundled(): String = withContext(Dispatchers.IO) {
        val json = try { context.assets.open("test.machine.json").use { String(it.readBytes()) } } catch (e: Exception) {
            return@withContext "No bundled test machine in this build (put one in app/prebuilt/dev/test.machine.json)."
        }
        install(json)
    }

    /** Installs a machine from a file the user picked. */
    suspend fun importFrom(uri: Uri): String = withContext(Dispatchers.IO) {
        val json = try { context.contentResolver.openInputStream(uri)?.use { String(it.readBytes(), Charsets.UTF_8) } } catch (e: Exception) { null }
            ?: return@withContext "Could not read that file."
        install(json)
    }

    private suspend fun install(json: String): String = try {
        provider.importMachine(json)
        "Machine installed (stored encrypted)."
    } catch (e: OpenFinderException) {
        "Import failed: ${e.error.message}"
    }

    /** CONTACTS APPLE: registers a new made-up machine (one provisioning per device id; 429s start a cooldown). */
    suspend fun provisionNew(): List<String> {
        val lines = mutableListOf<String>()
        try {
            val t0 = System.nanoTime()
            val id = provider.provisionNewMachine(newClient)
            lines += "Provisioned a new machine in ${ms(t0)} ms (device id ${id.deviceId.take(13)}…, routing ${if (id.routing != null) "set" else "none"})."
            lines += "It is stored encrypted. Run the headers() test next."
        } catch (e: OpenFinderException) {
            lines += "Provisioning failed (typed): ${e.error::class.simpleName}: ${e.error.message}"
        } catch (e: Throwable) {
            lines += "Provisioning failed: ${e.javaClass.simpleName}"
        }
        lines.forEach { Log.i("OpenFinderSelfTest", it) }
        return lines
    }

    suspend fun remove(): String { provider.removeMachine(); return "Machine removed." }

    /** First call (includes loading the library), then 5 more; reports each as milliseconds. */
    suspend fun run(): List<String> {
        val lines = mutableListOf<String>()
        try {
            val t0 = System.nanoTime()
            val first = provider.headers()
            lines += "build: ${provider.buildName()}"
            lines += "first headers(): ${ms(t0)} ms"
            val t1 = System.nanoTime()
            repeat(5) { provider.headers() }
            lines += "next 5: ${ms(t1) / 5} ms each"
            lines += "MD-M ${first.mid.size} bytes, MD ${first.otp.size} bytes"
            lines += "store persisted: ${provider.machinePresent()}"
        } catch (e: OpenFinderException) {
            lines += "FAILED (typed): ${e.error::class.simpleName}: ${e.error.message}"
        } catch (e: Throwable) {
            lines += "FAILED: ${e.javaClass.simpleName}"
        }
        lines.forEach { Log.i("OpenFinderSelfTest", it) }
        return lines
    }

    private fun ms(since: Long) = (System.nanoTime() - since) / 1_000_000
}
