package com.sacca.openfinder.apple

import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.time.Clock
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.concurrent.TimeUnit

/** The per-"client device" values AuthKit puts in the request headers (port of `gsa.Device`). */
data class GsaDevice(
    /** `X-Mme-Device-Id` */
    val uniqueDeviceId: String,
    /** `X-MMe-Client-Info` */
    val clientInfo: String = DEFAULT_CLIENT_INFO,
    /** `X-Apple-I-MD-LU`, sent as is (login later sends its base64 instead). */
    val localUserUuid: String = "00000000000000000000000000000000",
    /** `X-Apple-I-SRL-NO`, sent only when there is one. It must be the same one the machine was provisioned with. */
    val serial: String? = null,
) {
    companion object {
        const val DEFAULT_CLIENT_INFO = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
    }
}

class ProvisioningResult(val routing: Long, val ptm: ByteArray, val tk: ByteArray) {
    override fun toString() = "ProvisioningResult(routing=<redacted>, ptm=${ptm.size} bytes, tk=${tk.size} bytes)"
}

/**
 * Apple's Grand Slam `MidService` machine-provisioning client (port of `tools/machoadi/gsa.py`). The ADI library cannot
 * provision itself: `midStartProvisioning` hands out a SPIM, the library folds it into a CPIM, and `midFinishProvisioning`
 * turns that into the PTM and trust key the library stores. Nothing here is authenticated (ds_id -2 is Apple's "no account").
 *
 * Failures are [OpenFinderException]s: HTTP 429 -> [OpenFinderError.Throttled] (and the shared [Cooldown] starts), any other HTTP
 * error -> [OpenFinderError.Rejected] carrying Apple's own `ec`/`em`, transport problems -> [OpenFinderError.Network].
 * TLS verification stays ON (the Python tool turned it off only for a gap in its own trust store).
 */
class GsaClient(
    private val device: GsaDevice,
    private val cooldown: Cooldown? = null,
    private val http: OkHttpClient = defaultHttp(),
    private val lookupUrl: String = LOOKUP_URL,
    private val clock: Clock = Clock.systemUTC(),
) {
    var urls: Map<String, String> = emptyMap()
        private set

    suspend fun loadUrlBag(): Map<String, String> {
        val raw = send(lookupUrl, body = null, clientTime = false)
        @Suppress("UNCHECKED_CAST")
        val bag = (parse(raw, lookupUrl)["urls"] as? Map<String, Any?>)?.mapNotNull { (k, v) -> (v as? String)?.let { k to it } }?.toMap()
        if (bag.isNullOrEmpty()) throw backend("The URL bag contained no `urls` dictionary")
        urls = bag
        return bag
    }

    /** The SPIM (server provisioning intermediate metadata). */
    suspend fun startProvisioning(): ByteArray {
        val response = post(url("midStartProvisioning"), emptyMap())
        val spim = response["spim"] as? String ?: throw backend("midStartProvisioning gave no spim")
        return Base64.getDecoder().decode(spim)
    }

    suspend fun finishProvisioning(cpim: ByteArray): ProvisioningResult {
        val response = post(url("midFinishProvisioning"), mapOf("cpim" to Base64.getEncoder().encodeToString(cpim)))
        fun blob(key: String) = Base64.getDecoder().decode(response[key] as? String ?: throw backend("midFinishProvisioning gave no $key"))
        val routing = (response["X-Apple-I-MD-RINFO"] as? Number)?.toLong() ?: (response["X-Apple-I-MD-RINFO"] as? String)?.toLongOrNull() ?: 0L
        return ProvisioningResult(routing, blob("ptm"), blob("tk"))
    }

    /**
     * Answers Apple's resync (hsc 434 / `X-Apple-I-MD-DATA`) the way akd sends it: `srm` and `X-Apple-I-MD-M` are both required
     * (`X-Apple-I-MD-RINFO` when known). The verdict is `Response -> Status`; the whole `Response` is returned.
     */
    suspend fun syncMachine(midBase64: String, srmBase64: String, routing: Long?): Map<String, Any?> {
        val request = buildMap<String, Any?> {
            put("srm", srmBase64)
            put("X-Apple-I-MD-M", midBase64)
            if (routing != null) put("X-Apple-I-MD-RINFO", routing)
        }
        return post(url("midSyncMachine"), request)
    }

    private fun url(name: String) = urls[name] ?: throw backend("The URL bag has no $name")

    private suspend fun post(url: String, request: Map<String, Any?>): Map<String, Any?> {
        val body = Plist.toXml(mapOf("Header" to emptyMap<String, Any?>(), "Request" to request))
        val plist = parse(send(url, body, clientTime = true), url)
        @Suppress("UNCHECKED_CAST")
        return plist["Response"] as? Map<String, Any?> ?: throw backend("No Response in the reply from $url")
    }

    private fun parse(raw: ByteArray, url: String): Map<String, Any?> =
        try { Plist.parseDict(raw) } catch (e: IllegalArgumentException) { throw backend("Unparseable response from ${hostOf(url)}") }

    private suspend fun send(url: String, body: ByteArray?, clientTime: Boolean): ByteArray = withContext(Dispatchers.IO) {
        cooldown?.guard()
        val builder = Request.Builder().url(url)
            .header("User-Agent", USER_AGENT)
            .header("Accept", "*/*")
            .header("X-Mme-Device-Id", device.uniqueDeviceId)
            .header("X-MMe-Client-Info", device.clientInfo)
            .header("X-Apple-I-MD-LU", device.localUserUuid)
            .header("X-Apple-Client-App-Name", CLIENT_APP_NAME)
        device.serial?.let { builder.header("X-Apple-I-SRL-NO", it) }
        if (clientTime) builder.header("X-Apple-I-Client-Time", CLIENT_TIME.format(clock.instant().atOffset(ZoneOffset.UTC)))
        // AuthKit really does send urlencoded for an XML plist body.
        if (body != null) builder.post(body.toRequestBody("application/x-www-form-urlencoded".toMediaType())) else builder.get()
        try {
            http.newCall(builder.build()).execute().use { resp ->
                val bytes = resp.body.bytes()
                if (resp.isSuccessful) return@withContext bytes
                if (resp.code == 429) {
                    cooldown?.noteThrottled()
                    throw OpenFinderException(OpenFinderError.Throttled("Apple answered HTTP 429. This is usually an inconsistent request or connection state, not a rate limit; retrying is safe."))
                }
                throw rejected(resp.code, bytes, url)
            }
        } catch (e: IOException) {
            throw OpenFinderException(OpenFinderError.Network("Could not reach ${hostOf(url)}: ${e.javaClass.simpleName}"))
        }
    }

    /** HTTP error with Apple's own status (`Response -> Status -> ec/em`) when the body carries one. */
    private fun rejected(http: Int, body: ByteArray, url: String): OpenFinderException {
        var ec: Long? = null
        var em = ""
        try {
            @Suppress("UNCHECKED_CAST")
            val status = (Plist.parseDict(body)["Response"] as? Map<String, Any?>)?.get("Status") as? Map<String, Any?>
            ec = (status?.get("ec") as? Number)?.toLong()
            em = status?.get("em") as? String ?: ""
        } catch (_: IllegalArgumentException) { /* the body is advisory; never mask the HTTP error */ }
        val detail = if (ec != null) " (ec $ec${if (em.isNotEmpty()) ": $em" else ""})" else ""
        return OpenFinderException(OpenFinderError.Rejected(http, ec, "HTTP $http from ${hostOf(url)}$detail"))
    }

    private fun backend(message: String) = OpenFinderException(OpenFinderError.Backend(message))
    private fun hostOf(url: String) = url.substringAfter("://").substringBefore('/')

    companion object {
        const val LOOKUP_URL = "https://gsa.apple.com/grandslam/GsService2/lookup"
        const val USER_AGENT = "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0"
        const val CLIENT_APP_NAME = "Setup"
        private val CLIENT_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")

        /** Verified against [AppleTls], one new HTTP/1.1 connection per request (as the Python's `urllib` does; see [AppleHttp.unpooled]). */
        fun defaultHttp(): OkHttpClient = AppleHttp.unpooled(
            AppleHttp.builder().callTimeout(30, TimeUnit.SECONDS).followRedirects(false).build(),
        )
    }
}
