package com.sacca.openfinder.apple.reports

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** KeyPair.generate (ble/KeyRotation.kt's fresh-key source): validity, shape and JSON round-trip. */
class KeyPairGenerateTest {
    @Test
    fun `generated key is a valid 28-byte static keypair`() {
        val k = KeyPair.generate()
        assertEquals(28, k.privateKeyBytes.size)
        assertEquals(KeyPairType.UNKNOWN, k.keyType)
        assertEquals(28, k.advKeyBytes.size)
        assertEquals(32, k.hashedAdvKeyBytes.size)
    }

    @Test
    fun `generated keys are distinct and round-trip through json`() {
        val a = KeyPair.generate()
        val b = KeyPair.generate()
        assertNotEquals(a.advKeyB64, b.advKeyB64)

        val restored = KeyPair.fromJson(JSONObject(a.toJson().toString()))
        assertEquals(a.privateKeyB64, restored.privateKeyB64)
        assertEquals(a.advKeyB64, restored.advKeyB64)
        assertEquals(a.keyType, restored.keyType)
    }

    @Test
    fun `toString never carries the private key`() {
        val k = KeyPair.generate()
        assertTrue(!k.toString().contains(k.privateKeyB64))
    }
}
