package com.sacca.openfinder.apple.cloudkit

import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.StandardDSAEncoding
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.interfaces.ECPrivateKey

/** The two curves PCS key material uses: P-256 throughout, P-384 only where a 48-byte scalar turns up (`servicekey.py`). */
enum class PcsCurve(val curveName: String, val size: Int) {
    P256("secp256r1", 32),
    P384("secp384r1", 48);

    internal val params: X9ECParameters by lazy { CustomNamedCurves.getByName(curveName) }
    val order: BigInteger get() = params.n

    companion object {
        fun ofScalarLength(length: Int): PcsCurve? = entries.firstOrNull { it.size == length }
    }
}

/**
 * An elliptic-curve private key as the PCS code handles it (what Python holds as `ec.EllipticCurvePrivateKey`): a curve and
 * a scalar, with the public point computed once. Built from the keychain's `ECPrivateKey`s ([of]) or from scalars found in
 * protection structures. Secret: [toString] is redacted and the scalar never leaves this package except through [scalarBytes].
 *
 * BouncyCastle's lightweight API does the curve arithmetic, so no JCA provider is involved.
 */
class PcsKey internal constructor(val curve: PcsCurve, internal val d: BigInteger) {
    init { require(d.signum() > 0 && d < curve.order) { "scalar out of range" } }

    internal val publicPoint: ECPoint by lazy { curve.params.g.multiply(d).normalize() }

    /** The scalar, big-endian, padded to the curve size. A copy: the caller zeroes it. */
    fun scalarBytes(): ByteArray = fixed(d, curve.size)

    /** X9.62 uncompressed public point (0x04 | x | y). */
    val uncompressed: ByteArray get() = publicPoint.getEncoded(false)
    val compressed: ByteArray get() = publicPoint.getEncoded(true)
    val bareX: ByteArray get() = uncompressed.copyOfRange(1, 1 + curve.size)

    /** Every way this protocol writes a public key (`pcs.public_key_forms`): compressed, uncompressed, bare x, x|y. */
    fun publicKeyForms(): List<ByteArray> {
        val u = uncompressed
        return listOf(compressed, u, u.copyOfRange(1, 1 + curve.size), u.copyOfRange(1, u.size))
    }

    /** ECDH: the x coordinate of d * [peer] (what `private_key.exchange(ec.ECDH(), peer)` returns). */
    internal fun sharedX(peer: ECPoint): ByteArray {
        val shared = peer.multiply(d).normalize()
        if (shared.isInfinity) throw PcsException("ECDH produced the point at infinity")
        return fixed(shared.affineXCoord.toBigInteger(), curve.size)
    }

    override fun toString() = "PcsKey(${curve.name}, <redacted>)"
    override fun equals(other: Any?) = other is PcsKey && other.curve == curve && other.d == d
    override fun hashCode() = d.hashCode() * 31 + curve.hashCode()

    companion object {
        /** A keychain key (from the keychain piece's `pcs_keys`). Only P-256 and P-384 keys are meaningful to PCS. */
        fun of(key: ECPrivateKey): PcsKey {
            val bits = key.params.curve.field.fieldSize
            val curve = when (bits) {
                256 -> PcsCurve.P256
                384 -> PcsCurve.P384
                else -> throw IllegalArgumentException("A $bits-bit EC key is not one PCS uses")
            }
            require(key.params.order == curve.order) { "EC key is not on ${curve.curveName}" }
            return PcsKey(curve, key.s)
        }

        /** A key from a raw big-endian scalar; null when the scalar is not in [1, n) (Python's `derive_private_key` ValueError). */
        internal fun fromScalar(curve: PcsCurve, scalar: ByteArray): PcsKey? = fromScalar(curve, BigInteger(1, scalar))

        internal fun fromScalar(curve: PcsCurve, d: BigInteger): PcsKey? =
            if (d.signum() > 0 && d < curve.order) PcsKey(curve, d) else null

        internal fun fixed(value: BigInteger, size: Int): ByteArray {
            val raw = value.toByteArray()
            return when {
                raw.size == size -> raw
                raw.size > size -> raw.copyOfRange(raw.size - size, raw.size)
                else -> ByteArray(size - raw.size) + raw
            }
        }

        /** ECDSA-SHA256 verification over [data] with a DER signature; false for a malformed or non-canonical signature. */
        internal fun verifyEcdsaSha256(key: PcsKey, signature: ByteArray, data: ByteArray): Boolean {
            val domain = ECDomainParameters(key.curve.params)
            val (r, s) = try {
                StandardDSAEncoding.INSTANCE.decode(domain.n, signature).let { it[0] to it[1] }
            } catch (e: IllegalArgumentException) {
                return false
            }
            val digest = java.security.MessageDigest.getInstance("SHA-256").digest(data)
            val signer = ECDSASigner()
            signer.init(false, ECPublicKeyParameters(key.publicPoint, domain))
            return signer.verifySignature(digest, r, s)
        }
    }
}
