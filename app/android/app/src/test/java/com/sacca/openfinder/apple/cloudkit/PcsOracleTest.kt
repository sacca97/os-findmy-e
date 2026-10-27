package com.sacca.openfinder.apple.cloudkit

import com.sacca.openfinder.apple.cloudkit.CkFixtures.hex
import com.sacca.openfinder.apple.cloudkit.CkFixtures.key
import com.sacca.openfinder.apple.cloudkit.CkFixtures.keyJson
import com.sacca.openfinder.apple.cloudkit.CkFixtures.keys
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * PCS (Stage 5) against `findmy.cloudkit.pcs`: every value below was produced or consumed by the real Python on synthetic
 * inputs built the way the fork's own tests build them (fixtures/cloudkit/pcs.json, tools/oracle/cloudkit_vectors.py).
 */
class PcsOracleTest {
    private val f = CkFixtures.json("pcs.json")

    @Test fun keyDerivationMatches() {
        val labels = listOf(Pcs.LABEL_SHARE_KEY, Pcs.LABEL_HMAC_KEY, Pcs.LABEL_KEY_ID, Pcs.LABEL_ENCRYPTION_KEY, Pcs.KEY_ID_INPUT)
        for (entry in f.getJSONArray("kdf").objects()) {
            val mk = hex(entry.getString("master"))
            for (label in labels) {
                val name = String(label, Charsets.US_ASCII)
                assertEquals(name, entry.getJSONObject("derive").getString(name), hex(Pcs.deriveKey(mk, label)))
                assertEquals(name, entry.getJSONObject("derive48").getString(name), hex(Pcs.deriveKey(mk, label, 48)))
            }
            assertEquals(entry.getString("key_id"), hex(Pcs.computeKeyId(mk)))
            assertEquals(entry.getString("encryption_key"), hex(Pcs.deriveEncryptionKey(mk)))
            assertEquals(entry.getString("hmac_key"), hex(Pcs.deriveHmacKey(mk)))
            assertEquals(entry.optStringOrNull("master_ec"), "%064x".format(Pcs.deriveMasterEcScalar(mk)))
        }
    }

    @Test fun fieldsDecryptToWhatPythonEncrypted() {
        for (entry in f.getJSONArray("fields").objects()) {
            val context = FieldContext(entry.getString("zone"), entry.getString("record"), entry.getString("field"))
            assertEquals(entry.getString("aad_context"), hex(context.asBytes()))
            val data = hex(entry.getString("ciphertext"))
            val parsed = Pcs.parseEncryptedField(data)
            assertEquals(entry.getString("header"), hex(parsed.header))
            assertEquals(entry.getString("key_id"), hex(parsed.keyId))
            assertEquals(entry.getString("iv"), hex(parsed.iv))
            assertEquals(entry.getString("tag"), hex(parsed.tag))
            assertEquals(entry.getString("body"), hex(parsed.ciphertext))
            val plain = Pcs.decryptField(data, UnwrappedProtection.bare(hex(entry.getString("master"))), context)
            assertEquals(entry.getString("plaintext"), hex(plain))
            assertEquals(entry.getString("decrypted"), hex(plain))
        }
    }

    @Test fun fieldFailuresMatch() {
        val cases = f.getJSONObject("field_failures")
        for (name in cases.keys()) {
            val c = cases.getJSONObject(name)
            var plain: ByteArray? = null
            val error = errorOf {
                plain = Pcs.decryptField(hex(c.getString("data")), UnwrappedProtection.bare(hex(c.getString("master"))),
                    FieldContext(c.getString("zone"), c.getString("record"), c.getString("field")), c.getBoolean("check_key_id"))
            }
            assertEquals(name, c.optStringOrNull("error"), error)
            if (error == null) assertEquals(name, c.getString("plaintext"), hex(plain!!))
        }
    }

    @Test fun shareKeysUnwrapAsPythonDoes() {
        for (c in f.getJSONArray("unwrap_share_key").objects()) {
            var master: ByteArray? = null
            val error = errorOf { master = Pcs.unwrapShareKey(key(c.getJSONObject("key")), hex(c.getString("ciphertext"))) }
            assertEquals(c.getString("name"), c.optStringOrNull("error"), error)
            if (error == null) assertEquals(c.getString("name"), c.getString("master"), hex(master!!))
        }
    }

    @Test fun publicKeyFormsMatch() {
        for (c in f.getJSONArray("public_forms").objects()) {
            val k = key(c.getJSONObject("key"))
            assertEquals(c.getJSONArray("forms").strings(), k.publicKeyForms().map { hex(it) }.sorted())
            assertEquals(c.getString("compressed"), hex(k.compressed))
            assertEquals(c.getString("bare_x"), hex(k.bareX))
        }
    }

    @Test fun protectionStructureParsesAsPythonDoes() {
        val p = f.getJSONObject("protection_parse")
        val sp = ShareProtection.fromDer(hex(p.getString("der")))
        val keys = p.getJSONArray("keys").objects()
        assertEquals(keys.size, sp.keys.size)
        keys.zip(sp.keys).forEach { (e, a) ->
            assertEquals(e.getInt("key_type"), a.keyType.toInt())
            assertEquals(e.getString("public_key"), hex(a.publicKey))
            assertEquals(e.getString("ciphertext"), hex(a.ciphertext))
            assertEquals(if (e.isNull("flags")) null else e.getInt("flags"), a.flags?.toInt())
            assertEquals(e.getBoolean("read_only"), a.readOnly)
        }
        assertEquals(p.getString("meta"), hex(sp.meta))
        assertEquals(p.getInt("version"), sp.signatureData.version.toInt())
        assertEquals(p.getString("signature_data"), hex(sp.signatureData.data))
        assertEquals(p.getString("hmac"), hex(sp.hmac))
        assertEquals(p.getString("truncated_key_id"), hex(sp.truncatedKeyId))
        val sig = p.getJSONObject("signature")
        assertEquals(sig.getString("key_id"), hex(sp.signature!!.keyId))
        assertEquals(sig.getInt("digest"), sp.signature!!.digest.toInt())
        assertEquals(sig.getString("signature"), hex(sp.signature!!.signature))
        val attrs = p.getJSONArray("attributes").objects()
        assertEquals(attrs.map { it.getInt("key") to it.getString("value") }, sp.attributes.map { it.key.toInt() to hex(it.value) })
        assertEquals(p.getString("keyset_der"), hex(sp.keysetDer))
        assertEquals(p.getString("signature_data_der"), hex(sp.signatureDataDer))
        assertEquals(p.getBoolean("hmac_verified"), Pcs.verifyProtectionHmac(sp, hex(p.getString("master"))))
        assertEquals(p.getBoolean("hmac_verified_wrong_key"), Pcs.verifyProtectionHmac(sp, ByteArray(16) { 1 }))

        val o = p.getJSONObject("object_signature")
        val os = ObjectSignature.fromDer(sp.signatureData.data)
        assertEquals(o.getInt("roll_count"), os.rollCount.toInt())
        assertEquals(o.getInt("outer"), os.outerSignKeyType.toInt())
        assertEquals(o.getInt("pk_type"), os.publicKeyType.toInt())
        assertEquals(o.getString("pk"), hex(os.publicKey))
        assertEquals(o.getInt("symm_key_count"), os.symmKeyCount!!.toInt())
        assertEquals(o.getString("signature2"), hex(os.signature2!!.signature))
        assertEquals(o.getString("ec_key_list_der"), hex(os.ecKeyListDer))
        assertEquals(o.getString("attributes_der"), hex(os.attributesDer))
        assertEquals(p.getString("signed_data"), hex(Pcs.buildSignedData(sp, os)))
        // The asymmetry: an absent symmKeyCount is four zero bytes, absent attributes/ecKeyList are nothing.
        val minimal = ObjectSignature.fromDer(hex(minimalObjectSignature()))
        assertEquals(p.getString("signed_data_minimal"), hex(Pcs.buildSignedData(sp, minimal)))
    }

    /** The oracle's `object_signature()` with every default: {1, 2, {3, 02|11*32}, {'', 1, 'sig'}}. */
    private fun minimalObjectSignature(): String {
        fun tlv(tag: String, body: String) = tag + "%02x".format(body.length / 2) + body
        val keyRef = tlv("30", tlv("02", "03") + tlv("04", "02" + "11".repeat(32)))
        val signature = tlv("30", tlv("04", "") + tlv("02", "01") + tlv("04", hex("sig".toByteArray())))
        return tlv("30", tlv("02", "01") + tlv("02", "02") + keyRef + signature)
    }

    @Test fun malformedStructuresFailAsInPython() {
        val cases = f.getJSONObject("protection_parse_errors")
        for (name in cases.keys()) {
            val c = cases.getJSONObject(name)
            assertEquals(name, c.getString("error"), errorOf { ShareProtection.fromDer(hex(c.getString("der"))) })
        }
    }

    @Test fun signatureOutcomesMatch() {
        val sigs = f.getJSONObject("signatures")
        val reasons = f.getJSONObject("signature_reasons")
        assertEquals(reasons.getString("absent"), Pcs.SIGNATURE_ABSENT)
        assertEquals(reasons.getString("unparseable"), Pcs.SIGNATURE_UNPARSEABLE)
        assertEquals(reasons.getString("wrong_signer"), Pcs.SIGNATURE_WRONG_SIGNER)
        assertEquals(reasons.getString("rejected"), Pcs.SIGNATURE_REJECTED)
        for (name in sigs.keys()) {
            val c = sigs.getJSONObject(name)
            val sp = ShareProtection.fromDer(hex(c.getString("der")))
            assertEquals(name, c.optStringOrNull("outcome"), Pcs.describeProtectionSignature(sp, hex(c.getString("master"))))
        }
    }

    private fun assertUnwrapped(name: String, expected: JSONObject, actual: UnwrappedProtection) {
        assertEquals(name, expected.getString("master_key"), hex(actual.masterKey))
        assertEquals(name, expected.getBoolean("share_key_derived"), actual.shareKeyDerived)
        assertEquals(name, expected.getBoolean("read_only"), actual.readOnly)
        assertEquals(name, expected.getBoolean("hmac_verified"), actual.hmacVerified)
        assertEquals(name, if (expected.isNull("signature_verified")) null else expected.getBoolean("signature_verified"), actual.signatureVerified)
        assertEquals(name, expected.getJSONArray("symmetric_keys").strings(), actual.meta.symmetricKeys.map { hex(it) })
        assertEquals(name, expected.getJSONArray("private_keys").objects().map { keyJson(it) }, actual.meta.privateKeys.map { keyJson(it) })
    }

    @Test fun protectionUnwrapsAsPythonDoes() {
        for (c in f.getJSONArray("unwrap_protection").objects()) {
            val name = c.getString("name")
            var result: UnwrappedProtection? = null
            val error = errorOf { result = Pcs.unwrapProtection(ShareProtection.fromDer(hex(c.getString("der"))), keys(c.getJSONArray("held"))) }
            assertEquals(name, c.optStringOrNull("error"), error)
            if (error == null) assertUnwrapped(name, c.getJSONObject("result"), result!!)
        }
    }

    @Test fun metaIsReadAsPythonReadsIt() {
        val metas = f.getJSONObject("parse_meta")
        for (name in metas.keys()) {
            val c = metas.getJSONObject(name)
            var meta: MetaContents? = null
            val error = errorOf { meta = Pcs.parseMeta(hex(c.getString("plaintext"))) }
            assertEquals(name, c.optStringOrNull("error"), error)
            if (error != null) continue
            assertEquals(name, c.getJSONArray("symmetric_keys").strings(), meta!!.symmetricKeys.map { hex(it) })
            assertEquals(name, c.getJSONArray("private_keys").objects().map { keyJson(it) }, meta!!.privateKeys.map { keyJson(it) })
        }
    }

    @Test fun zoneLevelMatches() {
        val z = f.getJSONObject("zone")
        val service = keys(z.getJSONArray("service_keys"))
        val zoneKeys = Pcs.unwrapZone(hex(z.getString("protection")), service)
        assertEquals(z.getJSONArray("zone_keys").objects().map { keyJson(it) }, zoneKeys.map { keyJson(it) })
        assertEquals(z.getJSONArray("bare_zone_keys").objects().map { keyJson(it) }, Pcs.unwrapZone(hex(z.getString("bare_protection")), service).map { keyJson(it) })
        val stranger = PcsKey(PcsCurve.P256, java.math.BigInteger.valueOf(12345))
        assertEquals(z.getString("stranger_error"), errorOf { Pcs.unwrapZone(hex(z.getString("protection")), listOf(stranger)) })
        assertEquals(z.getJSONArray("record_defaults").strings(),
            Pcs.unwrapZoneRecordDefaults(hex(z.getString("record_defaults_protection")), zoneKeys).map { hex(it) })
    }

    @Test fun defaultKeySelectionMatches() {
        for (c in f.getJSONArray("select_default").objects()) {
            val keys = c.getJSONArray("keys").strings().map { hex(it) }
            val chosen = Pcs.selectDefaultMasterKey(keys, hex(c.getString("pcs_key")))
            assertEquals(c.optStringOrNull("chosen"), chosen?.let { hex(it) })
        }
    }

    @Test fun masterEcKeysMatch() {
        val z = f.getJSONObject("zone")
        val inputs = z.getJSONArray("master_ec_inputs").strings().map { hex(it) }
        assertEquals(z.getJSONArray("master_ec_keys").objects().map { keyJson(it) }, Pcs.masterEcKeys(inputs).map { keyJson(it) })
    }

    @Test fun aKeyFromTheKeychainIsAcceptedAsJca() {
        val k = key(f.getJSONArray("unwrap_share_key").objects().first().getJSONObject("key"))
        val back = PcsKey.of(CkFixtures.jca(k))
        assertArrayEquals(k.scalarBytes(), back.scalarBytes())
        assertEquals(k.curve, back.curve)
        assertTrue(!back.toString().contains(hex(k.scalarBytes())))
    }
}
