package com.sacca.openfinder.apple.login

import com.sacca.openfinder.anisette.CoreAdiAnisetteProvider
import com.sacca.openfinder.apple.GsaClient
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException

/**
 * Anisette as the login consumes it (the part of Python's `BaseAnisetteProvider` the account reads, plus the resync our
 * `tools/machoadi/resync.py` adds). Values are secrets: never log them.
 */
interface AnisetteSource {
    /**
     * The header set of Python's `get_headers(uid, devid)` for ONE request, exactly these keys:
     * `X-Apple-I-Client-Time`, `X-Apple-I-TimeZone`, `loc`, `X-Apple-Locale`, `X-Apple-I-MD`, `X-Apple-I-MD-LU`
     * (base64 of the local user uuid), `X-Apple-I-MD-M`, `X-Apple-I-MD-RINFO`, `X-Mme-Device-Id` (uppercase) and
     * `X-Apple-I-SRL-NO`. No client info: each endpoint sets its own. [LoginAnisette.fromProvisioningHeaders] builds it.
     */
    suspend fun headers(): Map<String, String>

    /**
     * Answers Apple's resync request (hsc 434 carrying `X-Apple-I-MD-DATA`, the base64 [sim]): synchronise the machine and
     * post it to `midSyncMachine`. Returns once Apple accepted it; throws a [OpenFinderException] when it did not, so the
     * login never resends on a machine Apple still refuses.
     */
    suspend fun resync(sim: String)
}

/** Composition of the login's Anisette header set. */
object LoginAnisette {
    /** The keys of [AnisetteSource.headers], in Python's order. */
    val KEYS = listOf(
        "X-Apple-I-Client-Time", "X-Apple-I-TimeZone", "loc", "X-Apple-Locale", "X-Apple-I-MD", "X-Apple-I-MD-LU",
        "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO", "X-Mme-Device-Id", "X-Apple-I-SRL-NO",
    )

    /**
     * The login set from what [CoreAdiAnisetteProvider.httpHeaders] returns (the provisioning client's composition). The
     * differences, each matching what the Python sends: `loc` is added beside `X-Apple-Locale`, the device id is
     * uppercased, and the client info is dropped (every login endpoint names its own daemon).
     */
    fun fromProvisioningHeaders(h: Map<String, String>): Map<String, String> {
        fun need(k: String) = h[k] ?: throw OpenFinderException(OpenFinderError.Backend("Anisette headers lack $k"))
        val locale = h["X-Apple-Locale"] ?: "en_US"
        return buildMap {
            put("X-Apple-I-Client-Time", need("X-Apple-I-Client-Time"))
            put("X-Apple-I-TimeZone", h["X-Apple-I-TimeZone"] ?: "UTC")
            put("loc", locale)
            put("X-Apple-Locale", locale)
            put("X-Apple-I-MD", need("X-Apple-I-MD"))
            put("X-Apple-I-MD-LU", need("X-Apple-I-MD-LU"))
            put("X-Apple-I-MD-M", need("X-Apple-I-MD-M"))
            put("X-Apple-I-MD-RINFO", need("X-Apple-I-MD-RINFO"))
            put("X-Mme-Device-Id", need("X-Mme-Device-Id").uppercase())
            h["X-Apple-I-SRL-NO"]?.let { put("X-Apple-I-SRL-NO", it) }
        }
    }
}

/**
 * [AnisetteSource] over the app's emulated Mac CoreADI. [gsa] is the provisioning-side Grand Slam client for this same
 * machine (its URL bag holds `midSyncMachine`); it is created by the caller so it shares the app's [com.sacca.openfinder.apple.Cooldown].
 */
class CoreAdiAnisetteSource(
    private val provider: CoreAdiAnisetteProvider,
    private val gsa: GsaClient,
) : AnisetteSource {
    override suspend fun headers(): Map<String, String> = LoginAnisette.fromProvisioningHeaders(provider.httpHeaders())

    override suspend fun resync(sim: String) {
        val verdict = provider.answerResync(sim, gsa)
        if (!verdict.accepted) {
            val em = verdict.em?.takeIf { it.isNotEmpty() }?.let { ": $it" } ?: ""
            throw OpenFinderException(OpenFinderError.Rejected(200, verdict.ec, "Apple did not accept the machine's resync (ec ${verdict.ec}$em)"))
        }
    }
}
