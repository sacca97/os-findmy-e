package com.sacca.openfinder.apple.login

import java.nio.CharBuffer
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The Grand Slam password derivation and session-payload decryption (port of `findmy.util.crypto.encrypt_password` and
 * `decrypt_spd_aes_cbc`, plus `util.parsers.decode_plist`'s prolog rule).
 *
 * Deliberate difference: Python hashes the password string on every authentication; here the caller hashes it once with
 * [passwordDigest] and keeps only that digest (both `s2k` variants start from it), so the password itself never has to be
 * held. The digest is password-equivalent: it is kept in memory only, never persisted, never logged.
 */
object GsaCrypto {
    const val S2K = "s2k"
    const val S2K_FO = "s2k_fo"

    /** SHA-256 of the UTF-8 password. The intermediate UTF-8 bytes are zeroed; the caller zeroes [password]. */
    fun passwordDigest(password: CharArray): ByteArray {
        val buf = Charsets.UTF_8.newEncoder().encode(CharBuffer.wrap(password))
        val utf8 = ByteArray(buf.remaining()).also { buf.get(it) }
        if (buf.hasArray()) buf.array().fill(0)
        return try { MessageDigest.getInstance("SHA-256").digest(utf8) } finally { utf8.fill(0) }
    }

    /**
     * The SRP password `P` from the password digest: PBKDF2-HMAC-SHA256 over the digest (`s2k`) or over its lowercase hex
     * text (`s2k_fo`), 32 bytes. Done over raw bytes: a `PBEKeySpec(char[])` would mangle the binary `s2k` input.
     */
    fun derivePassword(digest: ByteArray, salt: ByteArray, iterations: Int, protocol: String): ByteArray {
        require(protocol == S2K || protocol == S2K_FO) { "unsupported password protocol" }
        val input = if (protocol == S2K_FO) hex(digest).toByteArray(Charsets.US_ASCII) else digest.copyOf()
        return try { pbkdf2HmacSha256(input, salt, iterations, 32) } finally { input.fill(0) }
    }

    /** RFC 8018 PBKDF2 with HMAC-SHA256. */
    fun pbkdf2HmacSha256(password: ByteArray, salt: ByteArray, iterations: Int, length: Int): ByteArray {
        require(iterations >= 1 && length >= 1)
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(password, "HmacSHA256")) }
        val out = ByteArray(length)
        var block = 1
        var offset = 0
        while (offset < length) {
            mac.update(salt)
            mac.update(byteArrayOf((block ushr 24).toByte(), (block ushr 16).toByte(), (block ushr 8).toByte(), block.toByte()))
            var u = mac.doFinal()
            val t = u.copyOf()
            repeat(iterations - 1) {
                u = mac.doFinal(u)
                for (i in t.indices) t[i] = (t[i].toInt() xor u[i].toInt()).toByte()
            }
            val n = minOf(t.size, length - offset)
            System.arraycopy(t, 0, out, offset, n)
            offset += n
            block++
        }
        return out
    }

    /** Decrypts `spd` with keys HMAC-derived from the SRP session key: AES-256-CBC, PKCS#7. Throws on a bad payload. */
    fun decryptSpd(sessionKey: ByteArray, data: ByteArray): ByteArray {
        val key = hmac(sessionKey, "extra data key:")
        val iv = hmac(sessionKey, "extra data iv:").copyOf(16)
        return Cipher.getInstance("AES/CBC/PKCS5Padding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            doFinal(data)
        }
    }

    /** `decode_plist`: an XML plist missing its prolog gets Python's prolog prepended before parsing. */
    fun withPlistProlog(data: ByteArray): ByteArray =
        if (data.size >= 5 && String(data, 0, 5, Charsets.US_ASCII) == "<?xml") data else PLIST_PROLOG + data

    private val PLIST_PROLOG = (
        "<?xml version='1.0' encoding='UTF-8'?>" +
            "<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>"
        ).toByteArray(Charsets.US_ASCII)

    private fun hmac(key: ByteArray, message: String): ByteArray =
        Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(key, "HmacSHA256")); doFinal(message.toByteArray(Charsets.US_ASCII)) }

    internal fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
