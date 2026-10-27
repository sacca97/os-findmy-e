package com.sacca.openfinder.apple.reports

import org.json.JSONObject
import java.math.BigInteger
import java.security.MessageDigest
import java.util.Base64

enum class KeyPairType(val value: Int) {
    UNKNOWN(0), PRIMARY(1), SECONDARY(2);

    companion object {
        fun of(value: Int): KeyPairType = entries.firstOrNull { it.value == value } ?: throw IllegalArgumentException("unknown key type")
    }
}

/**
 * A P-224 private/public key pair of an accessory (port of `findmy.keys.KeyPair`). The advertised key is the x coordinate of
 * the public point (28 bytes), the lookup id Apple is queried with is its SHA-256. Equality and hashing use the hashed
 * advertisement key, as in Python. The private key is a credential: [toString] redacts it and nothing here logs it.
 *
 * @throws IllegalArgumentException when [privateKey] is not a scalar in `1 until n` (Python: `ec.derive_private_key`).
 */
class KeyPair(privateKey: ByteArray, val keyType: KeyPairType = KeyPairType.UNKNOWN, var name: String? = null) {
    private val scalar = BigInteger(1, privateKey).also {
        require(ReportCrypto.isValidPrivateScalar(it)) { "not a valid P-224 private key" }
    }

    /** The private key as 28 bytes (a copy). */
    val privateKeyBytes: ByteArray get() = ReportCrypto.toFixed(scalar, ReportCrypto.KEY_BYTES)
    val privateKeyB64: String get() = B64.encodeToString(privateKeyBytes)

    val advKeyBytes: ByteArray by lazy(LazyThreadSafetyMode.PUBLICATION) { ReportCrypto.publicX(scalar) }
    val advKeyB64: String get() = B64.encodeToString(advKeyBytes)

    /** SHA-256 of the advertised key: what Apple's report service is queried with. */
    val hashedAdvKeyBytes: ByteArray by lazy(LazyThreadSafetyMode.PUBLICATION) { MessageDigest.getInstance("SHA-256").digest(advKeyBytes) }
    val hashedAdvKeyB64: String get() = B64.encodeToString(hashedAdvKeyBytes)

    /** ECDH against the ephemeral point of a report (`KeyPair.dh_exchange`). */
    internal fun dhExchange(ephemeralPoint: ByteArray): ByteArray = ReportCrypto.ecdh(scalar, ephemeralPoint)

    /** `KeyPair.to_json`. */
    fun toJson(): JSONObject = JSONObject().apply {
        put("type", "keypair")
        put("private_key", privateKeyB64)
        put("key_type", keyType.value)
        put("name", name ?: JSONObject.NULL)
    }

    override fun equals(other: Any?) = other is KeyPair && hashedAdvKeyBytes.contentEquals(other.hashedAdvKeyBytes)
    override fun hashCode() = hashedAdvKeyBytes.contentHashCode()
    override fun toString() = "KeyPair(name=$name, public_key=$advKeyB64, type=$keyType, private=<redacted>)"

    companion object {
        private val B64 = Base64.getEncoder()

        fun fromB64(privateKeyB64: String) = KeyPair(Base64.getDecoder().decode(privateKeyB64))

        /** `KeyPair.from_json`. @throws IllegalArgumentException on a missing field, wrong type or bad key. */
        fun fromJson(json: JSONObject): KeyPair {
            require(json.optString("type") == "keypair") { "not a keypair" }
            if (!json.has("private_key") || !json.has("key_type") || !json.has("name")) throw IllegalArgumentException("incomplete keypair")
            return KeyPair(
                Base64.getDecoder().decode(json.getString("private_key")),
                KeyPairType.of(json.getInt("key_type")),
                if (json.isNull("name")) null else json.getString("name"),
            )
        }
    }
}
