package com.sacca.openfinder.apple.login

import com.sacca.openfinder.apple.Plist
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.GeneralSecurityException
import java.security.MessageDigest

/** SRP-6a, both password derivations and the `spd` payload against vectors from the real Python (`login_vectors.py`). */
class LoginCryptoTest {
    private val vectors = JSONObject(fixture("crypto.json"))

    private fun srpCases() = vectors.getJSONArray("srp").let { a -> (0 until a.length()).map { a.getJSONObject(it) } }

    @Test fun srpMatchesPysrpForEveryVector() {
        val names = mutableListOf<String>()
        for (v in srpCases()) {
            val name = v.getString("name").also { names += it }
            val digest = GsaCrypto.passwordDigest(v.getString("password").toCharArray())
            val p = GsaCrypto.derivePassword(digest, b64d(v.getString("salt")), v.getInt("iterations"), v.getString("sp"))
            assertEquals("$name P", v.getString("P"), hex(p))
            val srp = SrpClient(v.getString("username"), unhex(v.getString("a")))
            assertEquals("$name A", v.getString("A"), hex(srp.publicA))
            val m1 = srp.processChallenge(b64d(v.getString("salt")), unhex(v.getString("B")), p)!!
            assertEquals("$name M1", v.getString("M1"), hex(m1))
            assertNull("$name: no key before the server proof", srp.sessionKey)
            assertTrue("$name M2", srp.verifySession(unhex(v.getString("M2"))))
            assertEquals("$name K", v.getString("K"), hex(srp.sessionKey!!))
        }
        assertEquals(listOf("s2k", "s2k_fo", "non_ascii", "leading_zero_A", "leading_zero_B"), names)
    }

    /** The vectors really exercise the minimal-encoding trap (a 255-byte A, a 255-byte B). */
    @Test fun leadingZeroVectorsAreShort() {
        val byName = srpCases().associateBy { it.getString("name") }
        assertEquals(255, unhex(byName.getValue("leading_zero_A").getString("A")).size)
        assertEquals(255, unhex(byName.getValue("leading_zero_B").getString("B")).size)
        assertEquals(256, unhex(byName.getValue("s2k").getString("A")).size)
    }

    @Test fun wrongServerProofIsRefused() {
        val v = srpCases().first()
        val srp = SrpClient(v.getString("username"), unhex(v.getString("a")))
        srp.processChallenge(b64d(v.getString("salt")), unhex(v.getString("B")), unhex(v.getString("P")))
        assertFalse(srp.verifySession(ByteArray(32)))
        assertFalse(srp.verifySession(null))
        assertNull(srp.sessionKey)
    }

    @Test fun degenerateServerValueIsRefused() {
        val v = srpCases().first()
        val srp = SrpClient(v.getString("username"), unhex(v.getString("a")))
        assertNull(srp.processChallenge(b64d(v.getString("salt")), ByteArray(256), unhex(v.getString("P"))))
        assertFalse(srp.verifySession(unhex(v.getString("M2"))))
    }

    @Test fun randomEphemeralHasPysrpShape() {
        val a = SrpClient.randomEphemeral()
        assertEquals(256, a.size)
        assertTrue(a[0].toInt() and 0x80 != 0)
    }

    @Test fun pbkdf2BothVariantsMatchPython() {
        val a = vectors.getJSONArray("pbkdf2")
        val sps = mutableSetOf<String>()
        for (i in 0 until a.length()) {
            val v = a.getJSONObject(i)
            sps += v.getString("sp")
            val digest = GsaCrypto.passwordDigest(v.getString("password").toCharArray())
            assertEquals("vector $i", v.getString("P"), hex(GsaCrypto.derivePassword(digest, b64d(v.getString("salt")), v.getInt("iterations"), v.getString("sp"))))
        }
        assertEquals(setOf("s2k", "s2k_fo"), sps)
    }

    @Test fun passwordDigestIsSha256OfUtf8AndZeroesNothingItDoesNotOwn() {
        val pw = "pässwörd-☃".toCharArray()
        val d = GsaCrypto.passwordDigest(pw)
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest("pässwörd-☃".toByteArray(Charsets.UTF_8)), d)
        assertEquals("pässwörd-☃", String(pw))       // the caller owns (and zeroes) the CharArray
    }

    @Test fun unknownProtocolIsRejected() {
        try { GsaCrypto.derivePassword(ByteArray(32), ByteArray(16), 1, "s2k_new"); fail() } catch (_: IllegalArgumentException) {}
    }

    @Test fun spdDecodesWithAndWithoutProlog() {
        val a = vectors.getJSONArray("spd")
        assertEquals(2, a.length())
        for (i in 0 until a.length()) {
            val v = a.getJSONObject(i)
            val plain = GsaCrypto.decryptSpd(unhex(v.getString("K")), b64d(v.getString("spd")))
            assertArrayEquals(v.getString("name"), b64d(v.getString("plaintext")), plain)
            val decoded = Plist.parseDict(GsaCrypto.withPlistProlog(plain))
            LoginTestSupport.assertPlistEquals(v.getString("name"), LoginTestSupport.fromOracle(v.getJSONObject("decoded")), decoded)
        }
    }

    @Test fun spdUnderTheWrongKeyFails() {
        val v = vectors.getJSONArray("spd").getJSONObject(0)
        val wrong = unhex(v.getString("K")).also { it[0] = (it[0].toInt() xor 1).toByte() }
        try {
            val out = GsaCrypto.decryptSpd(wrong, b64d(v.getString("spd")))
            // Padding can pass by chance (1 in 256); the plist then cannot.
            try { Plist.parseDict(GsaCrypto.withPlistProlog(out)); fail("garbage parsed as a plist") } catch (_: IllegalArgumentException) {}
        } catch (_: GeneralSecurityException) { /* expected */ }
    }
}
