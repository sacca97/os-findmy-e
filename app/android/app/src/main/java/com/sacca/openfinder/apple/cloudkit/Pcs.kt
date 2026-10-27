package com.sacca.openfinder.apple.cloudkit

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.engines.RFC3394WrapEngine
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** A protection structure cannot be unwrapped or a field decrypted (`pcs.PCSError`). */
open class PcsException(message: String) : Exception(message)

/** No key held locally appears in a protection structure: the record is for someone else (`pcs.MissingKeyError`). */
class MissingKeyException(message: String) : PcsException(message)

/** One party's wrapped copy of the master key. Match on [publicKey], never index. */
class ShareKey(val keyType: BigInteger, val publicKey: ByteArray, val ciphertext: ByteArray, val flags: BigInteger?) {
    val readOnly: Boolean get() = flags?.testBit(0) ?: false
}

class SignatureData(val version: BigInteger, val data: ByteArray)

/** A signature: [keyId], when non-empty, is the signer's compressed public key; empty means self-signed. */
class PcsSignature(val keyId: ByteArray, val digest: BigInteger, val signature: ByteArray)

class PcsAttribute(val key: BigInteger, val value: ByteArray)

/** What `SignatureData.data` decodes to (`pcs.ObjectSignature`). */
class ObjectSignature(
    val rollCount: BigInteger,
    val outerSignKeyType: BigInteger,
    val publicKeyType: BigInteger,
    val publicKey: ByteArray,
    val signature: PcsSignature,
    val symmKeyCount: BigInteger? = null,
    val signature2: PcsSignature? = null,
    val ecKeyListDer: ByteArray = ByteArray(0),
    val attributesDer: ByteArray = ByteArray(0),
) {
    companion object {
        fun fromDer(data: ByteArray): ObjectSignature {
            val parts = Der.parseOne(data).first.children()
            if (parts.size < 4) throw PcsException("ObjectSignature has ${parts.size} members, expected at least 4")
            val keyRef = parts[2].children()
            if (keyRef.size < 2) throw PcsException("ObjectSignature's public key reference is incomplete")
            var symm: BigInteger? = null
            var sig2: PcsSignature? = null
            var ecKeyList = ByteArray(0)
            var attributes = ByteArray(0)
            for (extra in parts.drop(4)) {
                when {
                    extra.isContext(0) -> symm = extra.unwrap().asInt()
                    extra.isContext(1) -> sig2 = Pcs.parseSignature(extra.unwrap())
                    extra.isContext(2) -> ecKeyList = extra.unwrap().raw
                    extra.isContext(3) -> attributes = extra.unwrap().raw
                }
            }
            return ObjectSignature(parts[0].asInt(), parts[1].asInt(), keyRef[0].asInt(), keyRef[1].asBytes(),
                Pcs.parseSignature(parts[3]), symm, sig2, ecKeyList, attributes)
        }
    }
}

/** What a `protectionInfo` decodes to (`pcs.ShareProtection`). [keysetDer] and [signatureDataDer] are kept as they arrived. */
class ShareProtection(
    val keys: List<ShareKey>,
    val meta: ByteArray,
    val signatureData: SignatureData,
    val hmac: ByteArray,
    val truncatedKeyId: ByteArray,
    val signature: PcsSignature?,
    val attributes: List<PcsAttribute>,
    val keysetDer: ByteArray,
    val signatureDataDer: ByteArray,
) {
    companion object {
        /** The `hmac` OCTET STRING sits untagged between two context tags, so the sequence is walked, not indexed. */
        fun fromDer(data: ByteArray): ShareProtection {
            val sequence = Der.expectApplication(data, 1)
            var keys: List<ShareKey> = emptyList()
            var keysetDer = ByteArray(0)
            var meta = ByteArray(0)
            var signatureData: SignatureData? = null
            var signatureDataDer = ByteArray(0)
            var hmac = ByteArray(0)
            var truncated = ByteArray(0)
            var signature: PcsSignature? = null
            var attributes: List<PcsAttribute> = emptyList()
            for (element in sequence.children()) {
                when {
                    element.isUniversal(Der.TAG_SEQUENCE) && keysetDer.isEmpty() -> {
                        keys = parseKeyset(element)
                        keysetDer = element.raw
                    }
                    element.isContext(0) -> meta = element.unwrap().asBytes()
                    element.isContext(1) -> {
                        val inner = element.unwrap()
                        val parts = inner.children()
                        signatureData = SignatureData(
                            if (parts.isNotEmpty()) parts[0].asInt() else BigInteger.ZERO,
                            if (parts.size > 1) parts[1].asBytes() else ByteArray(0),
                        )
                        signatureDataDer = inner.raw
                    }
                    element.isUniversal(Der.TAG_OCTET_STRING) -> hmac = element.asBytes()
                    element.isContext(2) -> truncated = element.unwrap().asBytes()
                    element.isContext(3) -> signature = Pcs.parseSignature(element.unwrap())
                    element.isContext(4) -> attributes = element.unwrap().children().map { child ->
                        val p = child.children()
                        PcsAttribute(if (p.isNotEmpty()) p[0].asInt() else BigInteger.ZERO, if (p.size > 1) p[1].asBytes() else ByteArray(0))
                    }
                }
            }
            val sd = signatureData ?: throw PcsException("Protection structure carries no signature data")
            return ShareProtection(keys, meta, sd, hmac, truncated, signature, attributes, keysetDer, signatureDataDer)
        }

        private fun parseKeyset(element: DerElement): List<ShareKey> {
            val out = ArrayList<ShareKey>()
            for (child in element.children()) {
                if (!child.isUniversal(Der.TAG_SET)) continue
                for (entry in child.children()) {
                    val parts = entry.children()
                    if (parts.size < 2) throw PcsException("ShareKey has ${parts.size} members, expected at least 2")
                    val keyRef = parts[0].children()
                    if (keyRef.size < 2) throw PcsException("KeyRef is missing its public key")
                    out += ShareKey(keyRef[0].asInt(), keyRef[1].asBytes(), parts[1].asBytes(), if (parts.size > 2) parts[2].asInt() else null)
                }
            }
            return out
        }
    }
}

/** What a structure's `meta` holds once decrypted: more master keys, and the EC keys that open the level below. */
class MetaContents(val symmetricKeys: List<ByteArray> = emptyList(), val privateKeys: List<PcsKey> = emptyList())

/** A record's master key and how it was reached (`pcs.UnwrappedProtection`). Secret: redacted [toString]. */
class UnwrappedProtection(
    val masterKey: ByteArray,
    val shareKeyDerived: Boolean,
    val readOnly: Boolean,
    val hmacVerified: Boolean,
    /** Null when the check was skipped (a read-only entry). */
    val signatureVerified: Boolean?,
    val meta: MetaContents = MetaContents(),
) {
    /** Every key that might decrypt a field: ours first, then `symmKeys`. */
    val masterKeys: List<ByteArray> get() = listOf(masterKey) + meta.symmetricKeys
    val privateKeys: List<PcsKey> get() = meta.privateKeys
    override fun toString() = "UnwrappedProtection(<redacted>, shareKeyDerived=$shareKeyDerived, readOnly=$readOnly)"

    companion object {
        internal fun bare(masterKey: ByteArray) = UnwrappedProtection(masterKey, false, false, false, null)
    }
}

/** Which field a ciphertext belongs to; authenticated as `zone-record-field` (empty for a structure's meta). */
class FieldContext(val zoneName: String, val recordName: String, val fieldName: String) {
    fun asBytes(): ByteArray =
        if (zoneName.isEmpty() && recordName.isEmpty() && fieldName.isEmpty()) ByteArray(0)
        else "$zoneName-$recordName-$fieldName".toByteArray(Charsets.US_ASCII)

    companion object { val NONE = FieldContext("", "", "") }
}

/** An encrypted field value split into its parts. [keyId] is the two key-id ranges with the length byte between them dropped. */
class EncryptedField(val version: Int, val keyId: ByteArray, val header: ByteArray, val iv: ByteArray, val tag: ByteArray, val ciphertext: ByteArray)

/**
 * Protected Cloud Storage: the protection structures and field encryption of Find My records (port of the read path of
 * `findmy/cloudkit/pcs.py`: §5 key derivation, §3 structure parsing, §4 unwrapping including `meta` and the zone level,
 * §6 field decryption). The write half (`encrypt_field`) is not part of the app; tests use the Python's ciphertexts.
 *
 * Deliberate differences, all on paths where the Python raises an exception its callers do not catch (so one malformed
 * record would abort the whole fetch there): a share key or point that is not on P-256, a private key on the wrong curve, and
 * a signed-data integer that does not fit 32 bits all raise [PcsException] here. Error messages never carry plaintext.
 */
object Pcs {
    const val MASTER_KEY_LENGTH = 16
    val LABEL_SHARE_KEY = "MsaeEooevaX fooo 012".toByteArray(Charsets.US_ASCII)
    val LABEL_HMAC_KEY = "hmackey-of-masterkey".toByteArray(Charsets.US_ASCII)
    val LABEL_KEY_ID = "master key id labell".toByteArray(Charsets.US_ASCII)
    val LABEL_ENCRYPTION_KEY = "encryption key key m".toByteArray(Charsets.US_ASCII)
    val KEY_ID_INPUT = "M key input data 2 u".toByteArray(Charsets.US_ASCII)
    private val MASTER_EC_SALT = "full master key".toByteArray(Charsets.US_ASCII)
    private const val MASTER_EC_ITERATIONS = 10
    private const val MASTER_EC_LENGTH = 128
    const val ENCRYPTION_VERSION = 3
    const val GCM_IV_LENGTH = 12
    const val GCM_TAG_LENGTH = 12
    private val SIGNATURE_DATA_VERSION_NO_SHARE_KEY = BigInteger.valueOf(5)

    const val SIGNATURE_ABSENT = "the structure carries no signature data at all"
    const val SIGNATURE_UNPARSEABLE = "its signature data would not parse"
    const val SIGNATURE_WRONG_SIGNER = "every signature names a signer other than this record's master EC key"
    const val SIGNATURE_REJECTED = "the signature parsed, named the right key, and did not verify over the signed data"

    // RFC 6637's parameter block as PCS builds it: P-256 OID, ECDH id, 03 01, SHA-256, AES-128, sender, "fingerprint".
    private val RFC6637_PARAM: ByteArray = byteArrayOf(8, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x03, 0x01, 0x07) +
        byteArrayOf(0x12, 0x03, 0x01, 0x08, 0x07) + "Anonymous Sender    ".toByteArray(Charsets.US_ASCII) +
        "fingerprint".toByteArray(Charsets.US_ASCII) + ByteArray(9)

    // ------------------------------------------------------------------------------------------- §5 key derivation

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        // An empty HMAC key is legal (Python accepts it); SecretKeySpec does not, so pad the empty key to one zero block.
        mac.init(SecretKeySpec(if (key.isEmpty()) ByteArray(64) else key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** NIST SP 800-108 counter mode, HMAC-SHA256: `be32(i) | label | 00 | be32(bits)`, i from 1 (`derive_key`). */
    fun deriveKey(masterKey: ByteArray, label: ByteArray, length: Int? = null): ByteArray {
        val n = if (length == null || length == 0) masterKey.size else length
        val out = ByteArrayOutputStream()
        var counter = 1
        while (out.size() < n) {
            out.write(hmacSha256(masterKey, be32(counter.toLong()) + label + byteArrayOf(0) + be32(n.toLong() * 8)))
            counter++
        }
        return out.toByteArray().copyOf(n)
    }

    fun computeKeyId(masterKey: ByteArray): ByteArray = hmacSha256(deriveKey(masterKey, LABEL_KEY_ID), KEY_ID_INPUT)
    fun deriveEncryptionKey(masterKey: ByteArray): ByteArray = deriveKey(masterKey, LABEL_ENCRYPTION_KEY, MASTER_KEY_LENGTH)
    fun deriveHmacKey(masterKey: ByteArray): ByteArray = deriveKey(masterKey, LABEL_HMAC_KEY)

    /** The master EC scalar: PBKDF2 x10 to 128 bytes, reversed, low 256 bits kept, one conditional subtraction. */
    fun deriveMasterEcScalar(masterKey: ByteArray): BigInteger {
        val gen = PKCS5S2ParametersGenerator(SHA256Digest())
        gen.init(masterKey, MASTER_EC_SALT, MASTER_EC_ITERATIONS)
        val raw = (gen.generateDerivedParameters(MASTER_EC_LENGTH * 8) as KeyParameter).key
        val order = PcsCurve.P256.order
        var value = BigInteger(1, raw.reversedArray())
        value = value.and(BigInteger.ONE.shiftLeft(order.bitLength()).subtract(BigInteger.ONE))
        if (value > order) value = value.subtract(order)
        if (value.signum() <= 0 || value >= order) throw PcsException("Derived master EC scalar is out of range for P-256")
        return value
    }

    fun masterEcKey(masterKey: ByteArray): PcsKey = PcsKey(PcsCurve.P256, deriveMasterEcScalar(masterKey))

    /** `master_ec_keys`: one master EC key per master key. */
    fun masterEcKeys(masterKeys: List<ByteArray>): List<PcsKey> = masterKeys.map { masterEcKey(it) }

    // ------------------------------------------------------------------------------------------- §3 structure

    internal fun parseSignature(element: DerElement): PcsSignature {
        val parts = element.children()
        return PcsSignature(
            if (parts.isNotEmpty()) parts[0].asBytes() else ByteArray(0),
            if (parts.size > 1) parts[1].asInt() else BigInteger.ZERO,
            if (parts.size > 2) parts[2].asBytes() else ByteArray(0),
        )
    }

    // ------------------------------------------------------------------------------------------- §4 unwrapping

    private fun splitWrappedKey(ciphertext: ByteArray): Pair<ByteArray, ByteArray> {
        if (ciphertext.size < 3) throw PcsException("Wrapped key is ${ciphertext.size} bytes, too short to carry an MPI")
        val pointBits = ((ciphertext[0].toInt() and 0xff) shl 8) or (ciphertext[1].toInt() and 0xff)
        val pointEnd = 2 + (pointBits + 7) / 8
        if (ciphertext.size <= pointEnd) throw PcsException("Wrapped key claims a $pointBits-bit point but is only ${ciphertext.size} bytes")
        val point = ciphertext.copyOfRange(2, pointEnd)
        val wrappedLength = ciphertext[pointEnd].toInt() and 0xff
        val end = minOf(ciphertext.size, pointEnd + 1 + wrappedLength)
        val wrapped = ciphertext.copyOfRange(pointEnd + 1, end)
        if (wrapped.size != wrappedLength) throw PcsException("Wrapped key claims $wrappedLength bytes but only ${wrapped.size} remain")
        return point to wrapped
    }

    /** Rebuild a P-256 point from its x alone (either root serves: ECDH keeps only x). */
    private fun decompressX(x: ByteArray) = try {
        val xi = BigInteger(1, x)
        val curve = PcsCurve.P256.params.curve
        val p = curve.field.characteristic
        val alpha = xi.modPow(BigInteger.valueOf(3), p).subtract(xi.multiply(BigInteger.valueOf(3))).add(curve.b.toBigInteger()).mod(p)
        val y = alpha.modPow(p.add(BigInteger.ONE).shiftRight(2), p)
        if (y.modPow(BigInteger.TWO, p) != alpha) throw PcsException("Ephemeral point's x coordinate is not on P-256")
        if (xi >= p) throw PcsException("Ephemeral point's x coordinate is not a field element")
        curve.validatePoint(xi, y)
    } catch (e: IllegalArgumentException) {
        throw PcsException("Ephemeral point is not on P-256")
    }

    private fun unframeMasterKey(plaintext: ByteArray): ByteArray {
        if (plaintext.size < 4) throw PcsException("Unwrapped material is ${plaintext.size} bytes, too short to be framed")
        if (plaintext[0].toInt() != 1) throw PcsException("Unwrapped material announces algorithm ${plaintext[0].toInt() and 0xff}, expected 1")
        val padding = plaintext.last().toInt() and 0xff
        val keyLength = plaintext.size - padding - 3
        if (keyLength <= 0 || padding == 0 || padding > plaintext.size - 3) throw PcsException("Unwrapped material has an implausible padding length")
        val key = plaintext.copyOfRange(1, 1 + keyLength)
        val checksum = ((plaintext[1 + keyLength].toInt() and 0xff) shl 8) or (plaintext[2 + keyLength].toInt() and 0xff)
        if (key.sumOf { it.toInt() and 0xff } % 65536 != checksum) throw PcsException("Unwrapped key fails its checksum; the key-encryption key is wrong")
        for (i in 3 + keyLength until plaintext.size) {
            if (plaintext[i].toInt() and 0xff != padding) throw PcsException("Unwrapped material's padding is malformed")
        }
        return key
    }

    /** RFC 6637 ECDH key wrap: shared x -> SHA-256 KEK -> RFC 3394 unwrap -> framed master key (`unwrap_share_key`). */
    fun unwrapShareKey(privateKey: PcsKey, ciphertext: ByteArray): ByteArray {
        val (point, wrapped) = splitWrappedKey(ciphertext)
        val peer = decompressX(point)
        if (privateKey.curve != PcsCurve.P256) throw PcsException("A ${privateKey.curve.curveName} key cannot agree with a P-256 point")
        val shared = privateKey.sharedX(peer)
        val kek = MessageDigest.getInstance("SHA-256").digest(be32(1) + shared + RFC6637_PARAM)
        if (wrapped.size < 24 || wrapped.size % 8 != 0) throw PcsException("AES key unwrap failed its integrity check")
        val plaintext = try {
            RFC3394WrapEngine(AESEngine.newInstance()).run {
                init(false, KeyParameter(kek, 0, 16))
                unwrap(wrapped, 0, wrapped.size)
            }
        } catch (e: InvalidCipherTextException) {
            throw PcsException("AES key unwrap failed its integrity check. Either this entry is not for us, or the KEK was derived differently.")
        } finally {
            kek.fill(0)
            shared.fill(0)
        }
        return try { unframeMasterKey(plaintext) } finally { plaintext.fill(0) }
    }

    private fun u32(value: BigInteger): ByteArray {
        if (value.signum() < 0 || value.bitLength() > 32) throw PcsException("A signed-data integer does not fit 32 bits")
        return be32(value.toLong())
    }

    /** The bytes the structure's signature covers: a concatenation, not DER (`build_signed_data`). */
    fun buildSignedData(protection: ShareProtection, signature: ObjectSignature): ByteArray =
        protection.keysetDer + protection.meta + u32(signature.outerSignKeyType) + u32(signature.rollCount) +
            u32(signature.symmKeyCount ?: BigInteger.ZERO) + u32(signature.publicKeyType) + signature.publicKey +
            signature.attributesDer + signature.ecKeyListDer

    /** Null when a signature verified, otherwise one of the four reasons (`describe_protection_signature`). */
    fun describeProtectionSignature(protection: ShareProtection, masterKey: ByteArray): String? {
        if (protection.signatureData.data.isEmpty()) return SIGNATURE_ABSENT
        val objectSignature = try {
            ObjectSignature.fromDer(protection.signatureData.data)
        } catch (e: PcsException) {
            return SIGNATURE_UNPARSEABLE
        } catch (e: DerException) {
            return SIGNATURE_UNPARSEABLE
        }
        val publicKey = masterEcKey(masterKey)
        val signed = buildSignedData(protection, objectSignature)
        var considered = 0
        for (candidate in listOfNotNull(objectSignature.signature, objectSignature.signature2)) {
            if (candidate.keyId.isNotEmpty() && !candidate.keyId.contentEquals(publicKey.compressed)) continue
            considered++
            if (PcsKey.verifyEcdsaSha256(publicKey, candidate.signature, signed)) return null
        }
        return if (considered > 0) SIGNATURE_REJECTED else SIGNATURE_WRONG_SIGNER
    }

    /** The structure's HMAC over keyset DER | meta | the ObjectSignature bytes (not its SignatureData wrapper). */
    fun verifyProtectionHmac(protection: ShareProtection, masterKey: ByteArray): Boolean {
        if (protection.hmac.isEmpty()) return false
        val expected = hmacSha256(deriveHmacKey(masterKey), protection.keysetDer + protection.meta + protection.signatureData.data)
        val n = protection.hmac.size
        return MessageDigest.isEqual(expected.copyOf(minOf(n, expected.size)), protection.hmac)
    }

    private fun findOurKey(protection: ShareProtection, privateKeys: List<PcsKey>): Pair<ShareKey, PcsKey> {
        val byPublic = HashMap<String, PcsKey>()
        for (key in privateKeys) for (form in key.publicKeyForms()) byPublic[hex(form)] = key
        for (shareKey in protection.keys) {
            byPublic[hex(shareKey.publicKey)]?.let { return shareKey to it }
        }
        val theirs = protection.keys.map { it.publicKey.size }.toSortedSet()
        val ours = privateKeys.flatMap { k -> k.publicKeyForms().map { it.size } }.toSortedSet()
        val named = protection.keys.take(4).joinToString(", ") { hex(it.publicKey.copyOf(minOf(8, it.publicKey.size))) }
        throw MissingKeyException(
            "None of the ${privateKeys.size} key(s) held locally appears among the ${protection.keys.size} entries protecting this record. " +
                "Their public keys are $theirs bytes; the forms compared against are $ours. The record names: $named",
        )
    }

    /**
     * Recover a structure's master key with the keys held (`unwrap_protection`, defaults: HMAC and signature reported, not
     * required). Applies the share-key derivation below version 5 for writable entries, checks the truncated key id, reads meta.
     */
    fun unwrapProtection(protection: ShareProtection, privateKeys: List<PcsKey>): UnwrappedProtection {
        val (shareKey, privateKey) = findOurKey(protection, privateKeys)
        var masterKey = unwrapShareKey(privateKey, shareKey.ciphertext)
        val derived = protection.signatureData.version != SIGNATURE_DATA_VERSION_NO_SHARE_KEY && !shareKey.readOnly
        if (derived) masterKey = deriveKey(masterKey, LABEL_SHARE_KEY).also { masterKey.fill(0) }
        if (protection.truncatedKeyId.isNotEmpty()) {
            val keyId = computeKeyId(masterKey)
            if (!keyId.copyOf(minOf(protection.truncatedKeyId.size, keyId.size)).contentEquals(protection.truncatedKeyId)) {
                throw PcsException("Recovered a key, but its key id does not match the one the protection structure carries.")
            }
        }
        val hmacVerified = verifyProtectionHmac(protection, masterKey)
        val signatureVerified = if (shareKey.readOnly) null else describeProtectionSignature(protection, masterKey) == null
        return UnwrappedProtection(masterKey, derived, shareKey.readOnly, hmacVerified, signatureVerified, readMeta(protection.meta, masterKey))
    }

    /** §4 step 0: the zone's structure, opened with the keychain keys, gives the keys its records name (`unwrap_zone`). */
    fun unwrapZone(protectionInfo: ByteArray, serviceKeys: List<PcsKey>): List<PcsKey> {
        val unwrapped = unwrapProtection(ShareProtection.fromDer(protectionInfo), serviceKeys)
        val keys = unwrapped.privateKeys + masterEcKeys(unwrapped.masterKeys)
        if (keys.isEmpty()) {
            throw PcsException("The zone's protection structure unwrapped but yields no elliptic-curve keys (${unwrapped.meta.symmetricKeys.size} symmetric key(s)).")
        }
        return keys
    }

    /** The zone's `recordProtectionInfo`, opened with the zone keys: default master keys (`unwrap_zone_record_defaults`). */
    fun unwrapZoneRecordDefaults(recordProtectionInfo: ByteArray, zoneKeys: List<PcsKey>): List<ByteArray> =
        unwrapProtection(ShareProtection.fromDer(recordProtectionInfo), zoneKeys).masterKeys

    /** Which default key a record's `pcsKey` (a key-id prefix) names; one default and no `pcsKey` is unambiguous. */
    fun selectDefaultMasterKey(masterKeys: List<ByteArray>, pcsKey: ByteArray): ByteArray? {
        if (pcsKey.isEmpty()) return if (masterKeys.size == 1) masterKeys[0] else null
        return masterKeys.firstOrNull { key ->
            val id = computeKeyId(key)
            pcsKey.size <= id.size && id.copyOf(pcsKey.size).contentEquals(pcsKey)
        }
    }

    // ------------------------------------------------------------------------------------------- meta (§4 step 6)

    /** Decrypt and read `meta`; failures yield an empty result rather than costing the master key (`read_meta`). */
    fun readMeta(meta: ByteArray, masterKey: ByteArray): MetaContents {
        if (meta.isEmpty()) return MetaContents()
        val plaintext = try {
            decryptField(meta, UnwrappedProtection.bare(masterKey), FieldContext.NONE, checkKeyId = false)
        } catch (e: PcsException) {
            return MetaContents()
        }
        return try { parseMeta(plaintext) } catch (e: DerException) { MetaContents() } catch (e: PcsException) { MetaContents() } finally { plaintext.fill(0) }
    }

    /** `[0]` symmKeys, `[2]` identities (each walked for keys), `[1]` skipped (`parse_meta`). */
    fun parseMeta(plaintext: ByteArray): MetaContents {
        var element = Der.parseOne(plaintext).first
        if (element.tagClass == Der.CLASS_APPLICATION && element.constructed) {
            try { element = element.unwrap() } catch (_: DerException) { }
        }
        val symmetric = ArrayList<ByteArray>()
        val private = ArrayList<PcsKey>()
        for (child in element.children()) {
            if (child.isContext(0)) {
                child.unwrap().children().forEach { symmetric += it.asBytes() }
            } else if (child.isContext(2)) {
                for (identity in child.unwrap().children()) private += identityKeys(identity)
            }
        }
        return MetaContents(symmetric, private)
    }

    private fun membersOf(element: DerElement): List<DerElement> =
        if (!element.constructed) emptyList() else try { element.children() } catch (_: DerException) { emptyList() }

    /**
     * Every EC key in an identity, wherever it sits (`_identity_keys`): each non-SET member is tried as a key structure, and
     * the walk descends into constructed members and into OCTET STRINGs that parse as DER, even after a member yielded a key
     * (a keyset's 32-byte checksum reads as a scalar too; the real key is below it). The keyset checksum check is logging
     * only in the Python and is not ported.
     */
    private fun identityKeys(identity: DerElement, depth: Int = 6): List<PcsKey> {
        if (depth <= 0) return emptyList()
        val keys = ArrayList<PcsKey>()
        for (member in membersOf(identity)) {
            if (!member.isUniversal(Der.TAG_SET)) {
                try { keys += ServiceKeyReader.keysFromDer(member.raw) } catch (_: ServiceKeyException) { }
            }
            if (member.constructed) {
                keys += identityKeys(member, depth - 1)
                continue
            }
            try {
                val nested = Der.parseOne(member.asBytes()).first
                keys += identityKeys(nested, depth - 1)
            } catch (_: DerException) { }
        }
        return keys
    }

    // ------------------------------------------------------------------------------------------- §6 fields

    fun parseEncryptedField(data: ByteArray): EncryptedField {
        if (data.size < 4) throw PcsException("Encrypted field is ${data.size} bytes, too short to carry a header")
        val version = data[0].toInt() and 0xff
        if (version != ENCRYPTION_VERSION) throw PcsException("Encrypted field announces version $version, and only version $ENCRYPTION_VERSION is described")
        val headerLength = 4 + (data[3].toInt() and 0xff)
        if (data.size < headerLength + GCM_IV_LENGTH + GCM_TAG_LENGTH) throw PcsException("Encrypted field is truncated: header, IV and tag do not fit")
        val header = data.copyOfRange(0, headerLength)
        val keyId = data.copyOfRange(1, 3) + data.copyOfRange(4, headerLength)
        val body = headerLength
        return EncryptedField(
            version, keyId, header,
            data.copyOfRange(body, body + GCM_IV_LENGTH),
            data.copyOfRange(body + GCM_IV_LENGTH, body + GCM_IV_LENGTH + GCM_TAG_LENGTH),
            data.copyOfRange(body + GCM_IV_LENGTH + GCM_TAG_LENGTH, data.size),
        )
    }

    /** AES-128-GCM, 12-byte tag before the ciphertext, AAD = header | context (`decrypt_field`). */
    fun decryptField(data: ByteArray, unwrapped: UnwrappedProtection, context: FieldContext, checkKeyId: Boolean = true): ByteArray {
        val parsed = parseEncryptedField(data)
        if (checkKeyId && parsed.keyId.isNotEmpty()) {
            val expected = computeKeyId(unwrapped.masterKey)
            if (parsed.keyId.size > expected.size || !expected.copyOf(parsed.keyId.size).contentEquals(parsed.keyId)) {
                throw PcsException("This field is encrypted under a different key than the one recovered from the record's protection structure.")
            }
        }
        val key = deriveEncryptionKey(unwrapped.masterKey)
        try {
            val gcm = GCMBlockCipher.newInstance(AESEngine.newInstance())
            gcm.init(false, AEADParameters(KeyParameter(key), GCM_TAG_LENGTH * 8, parsed.iv, parsed.header + context.asBytes()))
            val input = parsed.ciphertext + parsed.tag
            val out = ByteArray(gcm.getOutputSize(input.size))
            val n = gcm.processBytes(input, 0, input.size, out, 0)
            val total = n + gcm.doFinal(out, n)
            return out.copyOf(total)
        } catch (e: InvalidCipherTextException) {
            throw PcsException("Field '${context.fieldName}' of record '${context.recordName}' failed to authenticate.")
        } finally {
            key.fill(0)
        }
    }

    internal fun be32(v: Long) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
    internal fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
