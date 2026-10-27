package com.sacca.openfinder.anisette

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/**
 * Fetches Apple's CoreADI 4.19 (x86_64) from an external host. The file is not part of this project or the APK; it is
 * accepted only if its SHA-256 is the pinned one, so a wrong or tampered download is never stored or executed.
 * The host serves the bytes on a POST to the file's page (its "Download" button is a form).
 */
class CoreAdiDownloader(private val image: AssetOrFileImageSource, private val http: OkHttpClient = defaultClient) {
    sealed interface Result {
        data object Installed : Result
        data class Failed(val reason: String) : Result
    }

    /** Blocking: call off the main thread. */
    fun download(url: String = URL): Result {
        require(url.startsWith("https://")) { "HTTPS only" }
        val request = Request.Builder().url(url).post(ByteArray(0).toRequestBody()).build()
        val bytes = try {
            http.newCall(request).execute().use { r ->
                if (!r.isSuccessful) return Result.Failed("The server answered HTTP ${r.code}.")
                val body = r.body
                if (body.contentLength() > MAX_BYTES) return Result.Failed("The file is larger than expected.")
                body.byteStream().readNBytes(MAX_BYTES + 1)
            }
        } catch (e: IOException) {
            return Result.Failed("Download failed: ${e.message ?: "network error"}.")
        }
        if (bytes.size > MAX_BYTES) return Result.Failed("The file is larger than expected.")
        if (!sha256(bytes).equals(SHA256, ignoreCase = true)) return Result.Failed("The downloaded file is not CoreADI 4.19 (checksum mismatch); nothing was stored.")
        return if (image.import(bytes)) Result.Installed else Result.Failed("The downloaded file could not be installed.")
    }

    companion object {
        const val URL = "https://sharebin.eu/files/CoreADI-4.19-x86_64"
        const val SHA256 = "2eafc3c79c7f41a8afbfbeaaf23ee5dab5ad5bda55ec8e54dbc0ddf1d20ce630"
        private const val MAX_BYTES = 8 * 1024 * 1024
        private val defaultClient = OkHttpClient.Builder().connectTimeout(20, TimeUnit.SECONDS).readTimeout(60, TimeUnit.SECONDS).build()
        private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
    }
}
