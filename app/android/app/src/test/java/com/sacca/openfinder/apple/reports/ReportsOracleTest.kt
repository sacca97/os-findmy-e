package com.sacca.openfinder.apple.reports

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.time.Instant
import java.time.OffsetDateTime
import java.util.Base64

/** Kotlin against vectors the real FindMy.py produced (`app/tools/oracle/reports_vectors.py`). */
class ReportsOracleTest {
    private val f = ReportFixtures

    private fun accessoryOf(e: JSONObject) = AccessoryKeys(f.hex(e.getString("master")), f.hex(e.getString("skn")), f.hex(e.getString("sks")), OffsetDateTime.parse("2026-09-01T00:00:00Z"))

    private fun assertKey(expected: JSONObject, actual: KeyPair, what: String) {
        assertEquals("$what private", expected.getString("priv"), AccessoryKeys.hex(actual.privateKeyBytes))
        assertEquals("$what adv", expected.getString("adv"), actual.advKeyB64)
        assertEquals("$what hashed", expected.getString("hashed"), actual.hashedAdvKeyB64)
    }

    @Test fun x963KdfMatchesPython() {
        val cases = f.json("keys.json").getJSONArray("kdf").objects()
        assertTrue(cases.size >= 5)
        for (c in cases) assertEquals(c.getString("out"), AccessoryKeys.hex(ReportCrypto.x963Kdf(f.hex(c.getString("value")), f.hex(c.getString("si")), c.getInt("length"))))
    }

    @Test fun derivePsKeyMatchesPython() {
        for (c in f.json("keys.json").getJSONArray("derive").objects())
            assertEquals(c.getString("out"), AccessoryKeys.hex(ReportCrypto.derivePsKey(f.hex(c.getString("master")), f.hex(c.getString("sk")))))
    }

    @Test fun keyPairPublicAndHashedKeysMatchPython() {
        val cases = f.json("keys.json").getJSONArray("keypairs").objects()
        assertEquals(4, cases.size)   // includes the extreme scalars 1 and n-1
        for (c in cases) assertKey(c, KeyPair(f.hex(c.getString("priv"))), "keypair")
    }

    @Test fun rollingKeysMatchPythonAcrossTheRolloverBoundaries() {
        for (e in f.json("keys.json").getJSONArray("accessories").objects()) {
            val acc = accessoryOf(e)
            val primary = e.getJSONObject("primary")
            // Out-of-order access (the JSON object loses order, so go through a shuffled-by-key walk too).
            for (i in primary.keys().asSequence().map { it.toInt() }.sortedDescending()) assertKey(primary.getJSONObject(i.toString()), acc.primaryKeyAt(i), "primary $i")
            for (i in primary.keys().asSequence().map { it.toInt() }.sorted()) assertKey(primary.getJSONObject(i.toString()), acc.primaryKeyAt(i), "primary $i")
            val secondary = e.getJSONObject("secondary")
            for (i in secondary.keys()) {
                // secondary index s is reached from primary index 96*(s-1) (as `+1`) and 96*(s-2) (as `+2`)
                val s = i.toInt()
                if (s >= 1) assertKey(secondary.getJSONObject(i), acc.secondaryKeysAt(96 * (s - 1)).first, "secondary $s via +1")
                if (s >= 2) assertKey(secondary.getJSONObject(i), acc.secondaryKeysAt(96 * (s - 2)).second, "secondary $s via +2")
            }
        }
    }

    @Test fun keysAtMatchesPythonSetsIncludingBoundariesAndNegativeIndices() {
        for (e in f.json("keys.json").getJSONArray("accessories").objects()) {
            val acc = accessoryOf(e)
            val keysAt = e.getJSONObject("keys_at")
            for (i in keysAt.keys()) {
                val expected = keysAt.getJSONArray(i).objects().map { it.getString("type") to it.getString("hashed") }.sortedBy { it.second }
                val actual = acc.keysAt(i.toInt()).map { it.keyType.name to it.hashedAdvKeyB64 }.sortedBy { it.second }
                assertEquals("keys_at($i)", expected, actual)
            }
            assertTrue(acc.keysAt(-1).isEmpty())
        }
    }

    @Test fun keysBetweenMatchesPythonForIndexAndTimeRanges() {
        val doc = f.json("keys.json")
        val acc = AccessoryKeys.fromJson(doc.getJSONObject("between_accessory"))
        val cases = doc.getJSONArray("between").objects()
        assertEquals(7, cases.size)
        for (c in cases) {
            val actual = if (c.opt("start") is Int) acc.keysBetween(c.getInt("start"), c.getInt("end"))
            else acc.keysBetween(OffsetDateTime.parse(c.getString("start")).toInstant(), OffsetDateTime.parse(c.getString("end")).toInstant())
            val expected = c.getJSONArray("items").objects().map { Triple(it.getInt("index"), it.getString("type"), it.getString("hashed")) }
            // Python's keys_at is an unordered set, so the order WITHIN one index is arbitrary; the index of each key is not.
            val order = compareBy<Triple<Int, String, String>>({ it.first }, { it.third })
            assertEquals(c.getString("name"), expected.sortedWith(order), actual.map { (i, k) -> Triple(i, k.keyType.name, k.hashedAdvKeyB64) }.sortedWith(order))
            assertEquals(c.getString("name") + ": each key once", actual.size, actual.map { it.second }.toSet().size)
        }
    }

    @Test fun indexRangeAndAlignmentRulesMatchPython() {
        val doc = f.json("alignment.json")
        val acc = AccessoryKeys.fromJson(doc.getJSONObject("accessory"))
        for (q in doc.getJSONArray("queries").objects()) {
            val at = OffsetDateTime.parse(q.getString("at")).toInstant()
            assertEquals("min at ${q.getString("at")}", q.getInt("min"), acc.minIndex(at))
            assertEquals("max at ${q.getString("at")}", q.getInt("max"), acc.maxIndex(at))
        }
        val probe = OffsetDateTime.parse("2026-10-02T12:00:00Z").toInstant()
        for (u in doc.getJSONArray("updates").objects()) {
            acc.updateAlignment(OffsetDateTime.parse(u.getString("at")).toInstant(), u.getInt("index"))
            assertEquals(OffsetDateTime.parse(u.getString("alignment_date")).toInstant(), acc.alignmentDate.toInstant())
            assertEquals(u.getInt("alignment_index"), acc.alignmentIndex)
            assertEquals(u.getInt("min"), acc.minIndex(probe))
            assertEquals(u.getInt("max"), acc.maxIndex(probe))
        }
    }

    @Test fun accessoryJsonRoundTripIsIdenticalToPython() {
        val doc = f.json("accessory_json.json")
        for (c in doc.getJSONArray("cases").objects()) {
            val back = AccessoryKeys.fromJson(c.getJSONObject("input")).toJson()
            val expected = c.getJSONObject("python_roundtrip")
            assertEquals(c.getString("name"), expected.keys().asSequence().toSet(), back.keys().asSequence().toSet())
            for (k in expected.keys().asSequence().toList()) assertEquals("${c.getString("name")}.$k", expected.get(k), back.get(k))
        }
    }

    @Test fun pythonExportParsesBackToTheSameKeys() {
        val c = f.json("accessory_json.json").getJSONArray("cases").objects().first()
        val acc = AccessoryKeys.fromJson(c.getJSONObject("input").toString())
        assertEquals("Keys", acc.name)
        assertEquals("ID-1", acc.id)
        assertEquals("SER1", acc.serialNumber)
        assertEquals(77, acc.alignmentIndex)
        assertEquals(c.getJSONObject("input").getString("master_key"), AccessoryKeys.hex(acc.masterKey))
    }

    @Test fun malformedAccessoryJsonIsRejectedLikePython() {
        val bad = f.json("accessory_json.json").getJSONArray("bad").objects()
        assertTrue(bad.size >= 14)
        for (c in bad) {
            try {
                AccessoryKeys.fromJson(c.getJSONObject("input"))
                fail("accepted ${c.getString("name")}")
            } catch (e: AccessoryFormatException) {
                // never carries key material
                assertFalse(c.getString("name"), e.message!!.contains(c.getJSONObject("input").optString("master_key", "?!")))
            }
        }
        try { AccessoryKeys.fromJson("not json"); fail() } catch (_: AccessoryFormatException) {}
    }

    @Test fun serialFromStableIdentifierMatchesPython() {
        for (c in f.json("accessory_json.json").getJSONArray("serials").objects()) {
            val input = if (c.isNull("input")) null else c.getJSONArray("input").let { a -> (0 until a.length()).map { a.getString(it) } }
            val expected = if (c.isNull("out")) null else c.getString("out")
            assertEquals(c.toString(), expected, AccessoryKeys.serialFromStableIdentifier(input))
        }
    }

    @Test fun reportsDecryptToWhatPythonDecrypts() {
        val doc = f.json("decrypt.json")
        val key = KeyPair(f.hex(doc.getString("key")), KeyPairType.PRIMARY)
        assertEquals(doc.getString("tag_public"), key.advKeyB64)
        var n88 = 0
        var n89 = 0
        for (v in doc.getJSONArray("valid").objects()) {
            val payload = f.b64(v.getString("payload"))
            if (payload.size == 88) n88++ else n89++
            val py = v.getJSONObject("py")
            val r = EncryptedReport(payload, f.b64(v.getString("hashed"))).decrypt(key)
            assertPython(py, r)
        }
        assertTrue(n88 >= 2 && n89 >= 2)   // both wire formats
    }

    @Test fun malformedAndInvalidPayloadsFailExactlyWhenPythonFails() {
        val doc = f.json("decrypt.json")
        val key = KeyPair(f.hex(doc.getString("key")), KeyPairType.PRIMARY)
        val cases = doc.getJSONArray("malformed").objects()
        assertTrue(cases.size > 35)
        for (c in cases) {
            val py = c.getJSONObject("py")
            val report = EncryptedReport(f.b64(c.getString("payload")), f.b64(c.getString("hashed")))
            if (py.getBoolean("ok")) {
                assertPython(py, report.decrypt(key))
            } else {
                try {
                    report.decrypt(key)
                    fail("decrypted ${c.getString("name")} but Python raised ${py.getString("why")}")
                } catch (e: ReportDecryptException) {
                    assertFalse(e.message!!.contains(doc.getString("key")))
                }
            }
        }
    }

    @Test fun timestampAndConfidenceAccessorsFollowPythonOnShortPayloads() {
        assertNull(EncryptedReport(ByteArray(3), ByteArray(32)).timestamp)
        assertNull(EncryptedReport(ByteArray(5), ByteArray(32)).confidence)
        val p = ByteArray(89).also { it[3] = 1; it[4] = 9; it[5] = 2 }
        assertEquals(Instant.ofEpochSecond(978_307_201), EncryptedReport(p, ByteArray(32)).timestamp)
        assertEquals(2, EncryptedReport(p, ByteArray(32)).confidence)            // 89 bytes: byte 5
        assertEquals(9, EncryptedReport(p.copyOf(88), ByteArray(32)).confidence) // 88 bytes: byte 4
    }

    @Test fun keyPairRejectsInvalidScalarsAndRedactsItself() {
        for (bad in listOf(ByteArray(28), ReportCrypto.N.toByteArray().let { ReportCrypto.toFixed(ReportCrypto.N, 28) })) {
            try { KeyPair(bad); fail() } catch (_: IllegalArgumentException) {}
        }
        val k = KeyPair(f.hex("00".repeat(27) + "07"))
        assertFalse(k.toString().contains(Base64.getEncoder().encodeToString(k.privateKeyBytes)))
        assertTrue(k.toString().contains("redacted"))
        val a = AccessoryKeys(ByteArray(28) { 1 }, ByteArray(32) { 2 }, ByteArray(32) { 3 }, OffsetDateTime.parse("2026-01-01T00:00:00Z"), name = "n")
        assertFalse(a.toString().contains("0101"))
    }

    private fun assertPython(py: JSONObject, r: DecryptedReport) {
        assertEquals(py.getDouble("lat"), r.latitude, 0.0)       // identical division: exact
        assertEquals(py.getDouble("lon"), r.longitude, 0.0)
        assertEquals(py.getInt("acc"), r.horizontalAccuracy)
        assertEquals(py.getInt("status"), r.status)
        assertEquals(py.getInt("conf"), r.confidence)
        assertEquals(py.getLong("ts"), r.timestamp.epochSecond)
    }
}
