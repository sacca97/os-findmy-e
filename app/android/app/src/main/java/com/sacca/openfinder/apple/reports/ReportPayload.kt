package com.sacca.openfinder.apple.reports

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64

/**
 * A location report as Apple returns it: the partially encrypted payload and the hashed advertisement key it belongs to
 * (port of `findmy.reports.LocationReport` up to `decrypt`). Layout (the OpenHaystack scheme):
 *
 * `timestamp(4, seconds since 2001-01-01, big-endian) | [extra(1) only in the 89-byte macOS 14+ form] | confidence(1) |
 *  ephemeral point(57: 04 || x || y) | AES-GCM ciphertext(10) | tag(16)`
 *
 * The AES key and 16-byte IV are `SHA-256(ECDH(x) || 00000001 || point)` split 16/16; the 10 plaintext bytes are
 * `latitude(i32) | longitude(i32) | accuracy(u8) | status(u8)`, coordinates in 1e-7 degrees.
 */
class EncryptedReport(payload: ByteArray, hashedAdvKey: ByteArray) {
    val payload: ByteArray = payload.copyOf()
    val hashedAdvKey: ByteArray = hashedAdvKey.copyOf()

    /** When a device recorded the report (`LocationReport.timestamp`). */
    val timestamp: Instant?
        get() = if (payload.size < 4) null else Instant.ofEpochSecond((ByteBuffer.wrap(payload, 0, 4).int.toLong() and 0xFFFFFFFFL) + APPLE_EPOCH_OFFSET)

    /** Confidence 1..3: byte 4 in the 88-byte form, byte 5 otherwise (`LocationReport.confidence`). */
    val confidence: Int?
        get() = when {
            payload.size == 88 -> payload[4].toInt() and 0xFF
            payload.size > 5 -> payload[5].toInt() and 0xFF
            else -> null
        }

    fun canDecrypt(key: KeyPair) = key.hashedAdvKeyBytes.contentEquals(hashedAdvKey)

    /** @throws ReportDecryptException wrong key, wrong size, bad ephemeral point or failed MAC. */
    fun decrypt(key: KeyPair): DecryptedReport {
        if (!canDecrypt(key)) throw ReportDecryptException("wrong key for this report")
        var enc = if (payload.size >= 4) payload.copyOfRange(4, payload.size) else ByteArray(0)
        // macOS 14+ reports carry one more byte in front (FindMyFlipper#61).
        if (enc.size == 85) enc = enc.copyOfRange(1, enc.size)
        // Python slices [1:58], [58:68], [68:] and the library demands a 16-byte tag, so exactly 84 bytes remain.
        if (enc.size != 84) throw ReportDecryptException("unexpected report size")
        val ephemeral = enc.copyOfRange(1, 58)
        val shared = key.dhExchange(ephemeral)
        val sha = MessageDigest.getInstance("SHA-256")
        sha.update(shared)
        sha.update(byteArrayOf(0, 0, 0, 1))
        sha.update(ephemeral)
        val symmetric = sha.digest()
        val plain = ReportCrypto.aesGcmDecrypt(
            key = symmetric.copyOfRange(0, 16),
            iv = symmetric.copyOfRange(16, 32),
            ciphertext = enc.copyOfRange(58, 68),
            tag = enc.copyOfRange(68, 84),
        )
        val ts = timestamp ?: throw ReportDecryptException("unexpected report size")
        val conf = confidence ?: throw ReportDecryptException("unexpected report size")
        val buf = ByteBuffer.wrap(plain)
        return DecryptedReport(
            timestamp = ts,
            confidence = conf,
            latitude = buf.getInt(0) / 1.0E7,
            longitude = buf.getInt(4) / 1.0E7,
            horizontalAccuracy = plain[8].toInt() and 0xFF,
            status = plain[9].toInt() and 0xFF,
            hashedAdvKey = hashedAdvKey,
        )
    }

    companion object {
        /** `60 * 60 * 24 * 11323`: 2001-01-01T00:00:00Z in Unix seconds. */
        const val APPLE_EPOCH_OFFSET = 978_307_200L

        fun fromBase64(payloadB64: String, hashedAdvKeyB64: String) =
            EncryptedReport(Base64.getDecoder().decode(payloadB64), Base64.getDecoder().decode(hashedAdvKeyB64))
    }
}

/** A decrypted report. [horizontalAccuracy] is meters (0..255) and [status] the accessory's status byte, both as Apple sends them. */
data class DecryptedReport(
    val timestamp: Instant,
    val confidence: Int,
    val latitude: Double,
    val longitude: Double,
    val horizontalAccuracy: Int,
    val status: Int,
    val hashedAdvKey: ByteArray,
) {
    /** Python's equality: same key, timestamp and position (accuracy and status do not matter). */
    override fun equals(other: Any?) = other is DecryptedReport && timestamp == other.timestamp && latitude == other.latitude &&
        longitude == other.longitude && hashedAdvKey.contentEquals(other.hashedAdvKey)

    override fun hashCode() = (timestamp.hashCode() * 31 + latitude.hashCode()) * 31 + longitude.hashCode() + hashedAdvKey.contentHashCode()
}
