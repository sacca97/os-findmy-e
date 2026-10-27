package com.sacca.openfinder.domain

import java.util.Base64

/** The values Apple's services want from a machine for ONE request. Raw bytes; secrets: never log, never persist. */
class AnisetteHeaders(val mid: ByteArray, val otp: ByteArray, val routing: Long) {
    /** `X-Apple-I-MD-M`. */
    val midBase64: String get() = Base64.getEncoder().encodeToString(mid)

    /** `X-Apple-I-MD`. */
    val otpBase64: String get() = Base64.getEncoder().encodeToString(otp)

    override fun toString() = "AnisetteHeaders(mid=${mid.size} bytes, otp=${otp.size} bytes, routing=<redacted>)"
}

/**
 * Source of Anisette headers. The only native piece that exists today is CoreAdi (see
 * [com.sacca.openfinder.anisette.CoreAdiAnisetteProvider]). Failures are thrown as [OpenFinderException]; calls are safe from
 * the main thread because implementations run the native library on their own thread.
 */
interface AnisetteProvider {
    /** Whether a machine (identity + store) is installed. Cheap. */
    suspend fun isProvisioned(): Boolean

    /** Headers for one request. Persists the machine store afterwards. */
    suspend fun headers(): AnisetteHeaders

    /** Opens the native library and runs one call so the first real request is not slow (100-250 ms). */
    suspend fun warmUp()
}
