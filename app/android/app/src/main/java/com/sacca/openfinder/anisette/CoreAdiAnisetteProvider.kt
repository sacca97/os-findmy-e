package com.sacca.openfinder.anisette

import android.content.Context
import com.sacca.openfinder.apple.GsaClient
import com.sacca.openfinder.apple.GsaDevice
import com.sacca.openfinder.domain.AnisetteHeaders
import com.sacca.openfinder.domain.AnisetteProvider
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import com.sacca.openfinder.adi.AdiException
import com.sacca.openfinder.adi.AlreadyProvisionedException
import com.sacca.openfinder.adi.CoreAdi
import com.sacca.openfinder.adi.NotProvisionedException
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileNotFoundException
import java.security.SecureRandom
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Base64
import java.util.concurrent.Executors

/** Where the Apple CoreADI file comes from. Null means "not available in this build". */
fun interface CoreAdiImageSource {
    fun load(): ByteArray?
}

/** A user-supplied file in app storage wins; otherwise the (git-ignored, debug-only) bundled asset. */
class AssetOrFileImageSource(
    private val context: Context,
    private val assetName: String = "CoreADI-4.19-x86_64",
    private val fileName: String = "CoreADI",
) : CoreAdiImageSource {
    override fun load(): ByteArray? {
        val file = File(context.filesDir, fileName)
        if (file.isFile) return file.readBytes()
        return try { context.assets.open(assetName).use { it.readBytes() } } catch (e: FileNotFoundException) { null }
    }

    /** Stores a user-picked CoreADI file (a 64-bit Mach-O) in app storage, where [load] prefers it. Returns false if it is not one. */
    fun import(bytes: ByteArray): Boolean {
        val magic = if (bytes.size >= 4) (bytes[0].toInt() and 0xFF) or ((bytes[1].toInt() and 0xFF) shl 8) or ((bytes[2].toInt() and 0xFF) shl 16) or ((bytes[3].toInt() and 0xFF) shl 24) else 0
        if (bytes.size < 4096 || magic != MACHO_64_MAGIC) return false
        val file = File(context.filesDir, fileName)
        File(context.filesDir, "$fileName.tmp").also { it.writeBytes(bytes); check(it.renameTo(file)) }
        return true
    }

    private companion object { const val MACHO_64_MAGIC = 0xFEEDFACF.toInt() }
}

/**
 * Anisette from the emulated Mac CoreADI (`libadi_core.so`, Java wrapper `com.sacca.openfinder.adi.CoreAdi`).
 *
 * Rules this class enforces (README, "How the native library behaves"):
 *  * every native call runs on ONE dedicated thread, never the caller's (so never the main thread);
 *  * the library is opened once and kept; [warmUp] pays the 100-250 ms first-call cost early;
 *  * the machine store is persisted (encrypted) after every call that can change it;
 *  * the host UUID comes from the machine file and is never changed;
 *  * no header value, machine byte or store byte is ever logged.
 */
class CoreAdiAnisetteProvider(
    private val storage: MachineStorage,
    private val images: CoreAdiImageSource,
) : AnisetteProvider {
    private val dispatcher = Executors.newSingleThreadExecutor { Thread(it, "coreadi").apply { isDaemon = true } }.asCoroutineDispatcher()

    // Touched only on [dispatcher].
    private var adi: CoreAdi? = null
    private var machine: MachineFile? = null

    override suspend fun isProvisioned(): Boolean = withContext(dispatcher) { storage.hasMachine() }

    /** Same answer, for callers already off the main thread. */
    suspend fun machinePresent(): Boolean = isProvisioned()

    override suspend fun warmUp() {
        try { headers() } catch (_: OpenFinderException) { /* no machine yet, or no CoreADI file: nothing to warm */ }
    }

    override suspend fun headers(): AnisetteHeaders = withContext(dispatcher) {
        val (lib, m) = ensureReady()
        val h = try {
            lib.headers()
        } catch (e: NotProvisionedException) {
            throw OpenFinderException(OpenFinderError.Authentication("The machine in the store is not provisioned. Import a provisioned machine file."))
        } catch (e: AdiException) {
            throw OpenFinderException(OpenFinderError.Backend("Anisette failed: ${e.message}"))
        }
        persistIfChanged(lib, m)
        AnisetteHeaders(h.mid, h.otp, h.routing)
    }

    /** `headers()` plus the machine's identity, as the HTTP headers a Grand Slam request carries. */
    suspend fun httpHeaders(): Map<String, String> {
        val h = headers()
        val id = withContext(dispatcher) { machine!!.identity }
        return buildMap {
            put("X-Apple-I-Client-Time", Instant.now().truncatedTo(ChronoUnit.SECONDS).toString())
            put("X-Apple-I-MD", h.otpBase64)
            put("X-Apple-I-MD-LU", Base64.getEncoder().encodeToString(id.localUserUuid.toByteArray()))
            put("X-Apple-I-MD-M", h.midBase64)
            put("X-Apple-I-MD-RINFO", h.routing.toString())
            id.serial?.let { put("X-Apple-I-SRL-NO", it) }
            // The host's timezone and locale, as the validated Python sent them (the library's
            // BaseAnisetteProvider.timezone/locale). Hardcoding UTC/en_US was a divergence.
            put("X-Apple-I-TimeZone", java.util.TimeZone.getDefault().getDisplayName(true, java.util.TimeZone.SHORT))
            put("X-Apple-Locale", java.util.Locale.getDefault().toString().ifEmpty { "en_US" })
            put("X-MMe-Client-Info", id.clientInfo)
            put("X-Mme-Device-Id", id.deviceId)
        }
    }

    /** Installs a machine from the text of a `.machine.json` file; replaces any existing machine. */
    suspend fun importMachine(json: String) = withContext(dispatcher) {
        val m = try { MachineFile.parse(json) } catch (e: IllegalArgumentException) {
            throw OpenFinderException(OpenFinderError.Backend(e.message ?: "Not a valid machine file"))
        }
        storage.save(m)
        closeLibrary()                      // reopen with the new store on the next call
    }

    /**
     * Registers a NEW made-up Mac with Apple and installs it (port of `mac_anisette.provision`). Contacts Apple twice (the URL
     * bag, then start/finish provisioning); one provisioning per device id, and Apple may answer 429 (see [com.sacca.openfinder.apple.Cooldown]).
     * Refuses to run while a machine is installed, so a working machine is never overwritten. The native begin/finish pair is
     * one session and runs on the native thread with nothing else in between.
     */
    suspend fun provisionNewMachine(
        newClient: (GsaDevice) -> GsaClient,
        random: SecureRandom = SecureRandom(),
    ): MachineIdentity = withContext(dispatcher) {
        if (storage.hasMachine()) throw OpenFinderException(OpenFinderError.Backend("A machine is already installed. Remove it first."))
        val image = images.load() ?: throw OpenFinderException(OpenFinderError.Backend("The CoreADI file is not available in this build."))
        closeLibrary()
        val hostUuid = MachineMint.hostUuid(random)
        val minted = MachineMint.identity(random)
        val lib = try { CoreAdi.open(image) } catch (e: AdiException) {
            throw OpenFinderException(OpenFinderError.Backend("Could not load CoreADI: ${e.message}"))
        } catch (e: UnsatisfiedLinkError) {
            throw OpenFinderException(OpenFinderError.Backend("The native Anisette library is not available for this device's CPU."))
        }
        try {
            lib.setHostUuid(hostUuid)
            val client = newClient(GsaDevice(minted.deviceId, minted.clientInfo, minted.localUserUuid, minted.serial))
            client.loadUrlBag()
            val spim = client.startProvisioning()
            val begin = try { lib.provisioningBegin(spim) } catch (e: AlreadyProvisionedException) {
                throw OpenFinderException(OpenFinderError.Backend("The native store already holds a machine."))
            } catch (e: AdiException) {
                throw OpenFinderException(OpenFinderError.Backend("Provisioning start failed: ${e.message}"))
            }
            val done = client.finishProvisioning(begin.cpim)
            try { lib.provisioningFinish(begin.session, done.ptm, done.tk, done.routing) } catch (e: AdiException) {
                throw OpenFinderException(OpenFinderError.Backend("Provisioning end failed: ${e.message}"))
            }
            val identity = minted.copy(routing = done.routing)
            storage.save(MachineFile(hostUuid, identity, lib.exportStore()))
            identity
        } finally {
            lib.close()
        }
    }

    /** Apple's verdict on a resync answer (`Response -> Status`), plus the routing value it may return. */
    data class ResyncVerdict(val ec: Long?, val em: String?, val hsc: Long?, val newRouting: Long?) {
        val accepted: Boolean get() = ec == 0L
    }

    /**
     * Answers Apple's resync request (HTTP 434 / `X-Apple-I-MD-DATA`, the base64 `sim` it carries): CoreAdi turns the SIM into
     * a MID and SRM, the Grand Slam client POSTs them, and a routing value in the reply is stored (port of `resync.py`).
     * The machine store is persisted afterwards. Needs an installed machine.
     */
    suspend fun answerResync(simBase64: String, gsa: GsaClient): ResyncVerdict = withContext(dispatcher) {
        val (lib, m) = ensureReady()
        val sim = try { Base64.getDecoder().decode(simBase64) } catch (e: IllegalArgumentException) {
            throw OpenFinderException(OpenFinderError.Backend("The resync request is not valid base64."))
        }
        val synced = try { lib.sync(sim) } catch (e: AdiException) {
            throw OpenFinderException(OpenFinderError.Backend("Synchronize failed: ${e.message}"))
        }
        if (gsa.urls.isEmpty()) gsa.loadUrlBag()
        val reply = gsa.syncMachine(Base64.getEncoder().encodeToString(synced.mid), Base64.getEncoder().encodeToString(synced.srm), m.identity.routing)
        @Suppress("UNCHECKED_CAST")
        val status = reply["Status"] as? Map<String, Any?>
        val newRouting = (reply["X-Apple-I-MD-RINFO"] as? Number)?.toLong() ?: (reply["X-Apple-I-MD-RINFO"] as? String)?.toLongOrNull()
        if (newRouting != null) {
            try { lib.updateRouting(newRouting) } catch (e: AdiException) { /* bookkeeping only */ }
        }
        val export = lib.exportStore()
        val updated = MachineFile(m.hostUuid, if (newRouting != null) m.identity.copy(routing = newRouting) else m.identity, export)
        storage.save(updated)
        machine = updated
        ResyncVerdict((status?.get("ec") as? Number)?.toLong(), status?.get("em") as? String, (status?.get("hsc") as? Number)?.toLong(), newRouting)
    }

    suspend fun removeMachine() = withContext(dispatcher) {
        storage.delete()
        closeLibrary()
    }

    /** Name of the loaded CoreADI build, or null before the first call. */
    suspend fun buildName(): String? = withContext(dispatcher) { adi?.build() }

    private fun ensureReady(): Pair<CoreAdi, MachineFile> {
        val m = machine ?: storage.load()?.also { machine = it }
            ?: throw OpenFinderException(OpenFinderError.Authentication("No machine installed. Import a machine file first."))
        adi?.let { return it to m }
        val image = images.load()
            ?: throw OpenFinderException(OpenFinderError.Backend("The CoreADI file is not available in this build."))
        val lib = try {
            CoreAdi.open(image).also {
                it.setHostUuid(m.hostUuid)
                it.importStore(m.storeExport)
            }
        } catch (e: AdiException) {
            throw OpenFinderException(OpenFinderError.Backend("Could not load CoreADI: ${e.message}"))
        } catch (e: UnsatisfiedLinkError) {
            throw OpenFinderException(OpenFinderError.Backend("The native Anisette library is not available for this device's CPU."))
        }
        adi = lib
        return lib to m
    }

    private fun persistIfChanged(lib: CoreAdi, m: MachineFile) {
        val export = lib.exportStore()
        if (!export.contentEquals(m.storeExport)) {
            val updated = m.withStore(export)
            storage.save(updated)
            machine = updated
        }
    }

    private fun closeLibrary() {
        adi?.close()
        adi = null
        machine = null
    }
}
