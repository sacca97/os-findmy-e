package com.sacca.openfinder.apple.reports

import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.MessageDigest

/** A report that cannot be decrypted (wrong size, bad point, failed MAC). Carries no key or payload bytes. */
class ReportDecryptException(message: String) : Exception(message)

/**
 * The elliptic-curve and hash primitives of the Find My scheme (port of `findmy/util/crypto.py`'s `x963_kdf` and
 * `derive_ps_key`, `KeyPair.dh_exchange` and the decryption in `LocationReport.decrypt`).
 *
 * Uses BouncyCastle's lightweight API (`org.bouncycastle.crypto`), which needs no JCA provider at all: Android's own
 * stripped "BC" provider is never touched and nothing is registered globally. (The brief allows a provider instance;
 * the lightweight classes are the same code without the provider indirection, and need no P-224 support from the platform.)
 */
internal object ReportCrypto {
    private val params = CustomNamedCurves.getByName("secp224r1")
    private val curve = params.curve
    private val generator: ECPoint = params.g

    /** Order of the P-224 group (`P224_N`). */
    val N: BigInteger = params.n

    const val KEY_BYTES = 28
    const val POINT_BYTES = 57

    fun isValidPrivateScalar(d: BigInteger): Boolean = d.signum() > 0 && d < N

    /** The x coordinate of d*G, 28 bytes: the advertised key. */
    fun publicX(d: BigInteger): ByteArray = generator.multiply(d).normalize().affineXCoord.encoded

    /** x963 KDF with SHA-256, one counter block per 32 bytes (`crypto.x963_kdf`). */
    fun x963Kdf(value: ByteArray, sharedInfo: ByteArray, length: Int): ByteArray {
        val sha = MessageDigest.getInstance("SHA-256")
        val out = ByteArray(length)
        var done = 0
        var counter = 1
        while (done < length) {
            sha.update(value)
            sha.update(byteArrayOf((counter ushr 24).toByte(), (counter ushr 16).toByte(), (counter ushr 8).toByte(), counter.toByte()))
            sha.update(sharedInfo)
            val block = sha.digest()
            val n = minOf(block.size, length - done)
            System.arraycopy(block, 0, out, done, n)
            done += n
            counter++
        }
        return out
    }

    /** `crypto.derive_ps_key`: the private key of an accessory for one secret key `sk` (SKN primary, SKS secondary). */
    fun derivePsKey(masterKey: ByteArray, sk: ByteArray): ByteArray {
        val priv = BigInteger(1, masterKey)
        val at = x963Kdf(sk, "diversify".toByteArray(Charsets.US_ASCII), 72)
        val nMinus1 = N.subtract(BigInteger.ONE)
        val u = BigInteger(1, at.copyOfRange(0, 36)).mod(nMinus1).add(BigInteger.ONE)
        val v = BigInteger(1, at.copyOfRange(36, 72)).mod(nMinus1).add(BigInteger.ONE)
        val key = u.multiply(priv).add(v).mod(N)
        return toFixed(key, KEY_BYTES)
    }

    /** ECDH with an uncompressed 57-byte point (`04 || x || y`); the shared secret is the x coordinate (28 bytes). */
    fun ecdh(d: BigInteger, ephemeralPoint: ByteArray): ByteArray {
        if (ephemeralPoint.size != POINT_BYTES || ephemeralPoint[0].toInt() != 4) throw ReportDecryptException("bad ephemeral key")
        val point = try {
            curve.decodePoint(ephemeralPoint)           // validates that the point is on the curve
        } catch (e: IllegalArgumentException) {
            throw ReportDecryptException("bad ephemeral key")
        }
        if (point.isInfinity) throw ReportDecryptException("bad ephemeral key")
        val shared = point.multiply(d).normalize()
        if (shared.isInfinity) throw ReportDecryptException("bad ephemeral key")
        return shared.affineXCoord.encoded
    }

    /** AES-128-GCM with a 16-byte IV, a 16-byte tag appended to [ciphertext] and no AAD. */
    fun aesGcmDecrypt(key: ByteArray, iv: ByteArray, ciphertext: ByteArray, tag: ByteArray): ByteArray {
        val cipher = GCMBlockCipher.newInstance(AESEngine.newInstance())
        cipher.init(false, AEADParameters(KeyParameter(key), 128, iv))
        val input = ciphertext + tag
        val out = ByteArray(cipher.getOutputSize(input.size))
        try {
            val n = cipher.processBytes(input, 0, input.size, out, 0)
            val m = cipher.doFinal(out, n)
            return out.copyOf(n + m)
        } catch (e: org.bouncycastle.crypto.InvalidCipherTextException) {
            throw ReportDecryptException("authentication failed")
        }
    }

    /** Big-endian, left-padded to exactly [size] bytes (`int.to_bytes(size, "big")`). */
    fun toFixed(value: BigInteger, size: Int): ByteArray {
        val raw = value.toByteArray()
        val start = if (raw.size > size) raw.size - size else 0
        val out = ByteArray(size)
        System.arraycopy(raw, start, out, size - (raw.size - start), raw.size - start)
        return out
    }
}
