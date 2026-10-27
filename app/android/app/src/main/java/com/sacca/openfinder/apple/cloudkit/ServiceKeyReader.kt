package com.sacca.openfinder.apple.cloudkit

import com.google.protobuf.InvalidProtocolBufferException
import com.sacca.openfinder.apple.proto.cuttlefish.PcsServiceKeys

/** An item's key material cannot be read (`servicekey.ServiceKeyError`). */
open class ServiceKeyException(message: String) : Exception(message)

/** A 64/96-byte key blob whose public half does not match its scalar (`servicekey.KeyBlobError`). */
class KeyBlobException(message: String) : ServiceKeyException(message)

/**
 * The private-key CHOICE a protection structure's meta nests its identity keys in (port of the subset of
 * `findmy/keychain/servicekey.py` that `pcs._identity_keys` reaches: `service_keys_from_der`, `scalar_in`, `_candidates_in`,
 * `_keys_from_candidates`, `_v2_payload`, `_from_v2`, `_from_v1`).
 *
 * Ported here rather than imported from the keychain package on purpose: the `keychain` and `cloudkit` modules do not
 * import each other (FindMy.py#278), and the keychain piece reads keychain items with its own copy. Key order matters (the
 * caller tries them in this order), so it is reproduced exactly: verified blobs first, then length-matched scalars, each
 * group in wire order.
 */
internal object ServiceKeyReader {
    private const val PRIVATE_KEY_V2_TAG = 5

    private class Candidate(val scalar: ByteArray, val verified: Boolean)

    /** `service_keys_from_der(...).for_pcs()`: the encryption key, then the signing key if there is one. */
    fun keysFromDer(payload: ByteArray): List<PcsKey> {
        try {
            val (element, _) = Der.parseOne(payload)
            val usable = if (element.tagClass == Der.CLASS_APPLICATION && element.tagNumber == PRIVATE_KEY_V2_TAG) fromV2(element) else fromV1(element)
            return usable.take(2)
        } catch (e: DerException) {
            throw ServiceKeyException("An item's v_Data is not DER at all: ${e.message}")
        }
    }

    /** A blob: 32/48 bytes is a bare scalar (unverified); 64/96 bytes is public x then scalar, checked. */
    private fun scalarIn(blob: ByteArray): Candidate? {
        for (curve in PcsCurve.entries) {
            if (blob.size == curve.size) return Candidate(blob, verified = false)
            if (blob.size != 2 * curve.size) continue
            val publicX = blob.copyOfRange(0, curve.size)
            val scalar = blob.copyOfRange(curve.size, blob.size)
            val key = PcsKey.fromScalar(curve, scalar)
                ?: throw KeyBlobException("A ${blob.size}-byte key blob's trailing half is not a valid scalar")
            if (!key.bareX.contentEquals(publicX)) {
                throw KeyBlobException("A ${blob.size}-byte key blob's halves disagree: the layout is public x first, then the scalar")
            }
            return Candidate(scalar, verified = true)
        }
        return null
    }

    private fun candidatesIn(payload: ByteArray): List<Candidate> {
        val found = ArrayList<Candidate>()
        fun consider(blob: ByteArray): Boolean = scalarIn(blob)?.also { found += it } != null
        for (member in WireFields.iterate(payload)) {
            if (member.wireType != 2 || member.payload.isEmpty()) continue
            if (consider(member.payload)) continue
            for (inner in WireFields.iterate(member.payload)) {
                if (inner.wireType == 2 && inner.payload.isNotEmpty() && consider(inner.payload)) break
            }
        }
        return found
    }

    private fun keysFromCandidates(candidates: List<Candidate>): List<PcsKey> =
        (candidates.filter { it.verified } + candidates.filter { !it.verified }).mapNotNull { c ->
            PcsCurve.ofScalarLength(c.scalar.size)?.let { PcsKey.fromScalar(it, c.scalar) }
        }

    private fun v2Payload(element: DerElement): ByteArray {
        var children = element.children()
        if (children.isEmpty()) throw ServiceKeyException("A v2 private key structure carries no data element")
        if (children.size == 1 && children[0].constructed && children[0].isUniversal(Der.TAG_SEQUENCE)) children = children[0].children()
        return children.firstOrNull { it.isUniversal(Der.TAG_OCTET_STRING) }?.asBytes()
            ?: throw ServiceKeyException("A v2 private key structure holds no octet string")
    }

    private fun fromV2(element: DerElement): List<PcsKey> {
        val payload = v2Payload(element)
        val keys = try { PcsServiceKeys.parseFrom(payload) } catch (e: InvalidProtocolBufferException) { PcsServiceKeys.getDefaultInstance() }
        var candidates = listOf(keys.encryptionKey.key.toByteArray(), keys.signingKey.key.toByteArray()).mapNotNull { scalarIn(it) }
        if (candidates.none { it.verified }) {
            val positional = candidatesIn(payload)
            if (positional.isNotEmpty()) candidates = positional
        }
        val usable = keysFromCandidates(candidates)
        if (usable.isEmpty()) throw ServiceKeyException("A v2 private key structure's ${payload.size}-byte payload carries no usable private key")
        return usable
    }

    private fun fromV1(element: DerElement): List<PcsKey> {
        val children = element.children()
        if (children.isEmpty()) throw ServiceKeyException("An item's v_Data is neither a v2 structure nor a sequence holding a key")
        val usable = keysFromCandidates(children.filter { !it.constructed }.mapNotNull { scalarIn(it.asBytes()) })
        if (usable.isEmpty()) throw ServiceKeyException("A v1 private key structure carries no usable key")
        return usable
    }
}
