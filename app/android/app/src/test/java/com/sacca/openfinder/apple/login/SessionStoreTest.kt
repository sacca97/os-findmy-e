package com.sacca.openfinder.apple.login

import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant

/** Persistence of the signed-in state: round trip, what is (never) in it, and restoring only onto the same machine. */
class SessionStoreTest {
    private val session = SavedSession(
        username = "Synthetic.User@example.invalid", localUserUuid = OracleDevice.uid, deviceId = OracleDevice.devid,
        cloudKitDeviceUuid = OracleDevice.device.cloudKitDeviceUuid, accountName = "synthetic.user@example.invalid",
        firstName = "Synth", lastName = null, dsid = "1234567890", adsid = "000123-05-synthetic", idmsHb = "HB-1",
        serviceTokens = mapOf("searchPartyToken" to "SP-TOKEN", "cloudKitToken" to "CK-TOKEN", "mmeAuthToken" to "MME"),
        savedAt = Instant.parse("2026-10-17T12:34:56Z"),
    )

    @Test fun roundTrip() {
        val blobs = MemoryBlobs()
        val store = SessionStore(blobs)
        assertNull(store.load())
        store.save(session)
        assertEquals(session, store.load())
        store.clear()
        assertNull(store.load())
    }

    @Test fun neverHoldsAPasswordOrAPet() = runTest {
        // The stored JSON has no field that could hold either (LoginFlowOracleTest checks a real snapshot's values too).
        val blobs = MemoryBlobs()
        val flow = org.json.JSONArray(fixture("flows.json")).getJSONObject(0)
        assertEquals("signin_no_2fa", flow.getString("name"))
        val json = SessionStore(blobs).run { save(session); String(blobs.map.values.single()) }
        val keys = mutableListOf<String>()
        fun walk(o: Any?) { if (o is JSONObject) o.keys().forEach { keys += it; walk(o.get(it)) } }
        walk(JSONObject(json))
        assertFalse(keys.any { it.contains("password", ignoreCase = true) || it.contains("pet", ignoreCase = true) })
        val pw = flow.getString("password")
        assertFalse(json.contains(pw))
        assertFalse(json.contains(GsaCrypto.hex(MessageDigest.getInstance("SHA-256").digest(pw.toByteArray()))))
    }

    @Test fun unreadableBlobReadsAsNoSession() {
        val blobs = MemoryBlobs()
        blobs.write("apple_session.json", "{not json".toByteArray())
        assertNull(SessionStore(blobs).load())
        blobs.write("apple_session.json", JSONObject(session.toJson()).put("version", 99).toString().toByteArray())
        assertNull(SessionStore(blobs).load())
    }

    @Test fun toStringRedactsCredentials() {
        val s = session.toString()
        assertFalse(s.contains("SP-TOKEN") || s.contains("HB-1") || s.contains("1234567890"))
    }

    @Test fun ageCheck() {
        assertTrue(session.olderThan(Duration.ofDays(7), Instant.parse("2026-10-25T00:00:00Z")))
        assertFalse(session.olderThan(Duration.ofDays(7), Instant.parse("2026-10-18T00:00:00Z")))
    }

    @Test fun restoredAccountServesTokensWithoutAnyRequest() = runTest {
        val anisette = FakeAnisette()
        val acc = AppleAccount.restore(session, OracleDevice.device, anisette, endpoints = LoginEndpoints.under("http://127.0.0.1:9", emptySet()))
        assertEquals(LoginState.LOGGED_IN, acc.loginState)
        assertEquals("SP-TOKEN", acc.serviceToken("searchPartyToken"))
        assertNull(acc.serviceToken("missing"))
        assertEquals("1234567890", acc.dsid)
        assertEquals("000123-05-synthetic", acc.adsid)
        assertEquals("synthetic.user@example.invalid", acc.accountName)
        assertEquals(OracleDevice.device.cloudKitDeviceUuid, acc.deviceUuid)
        assertEquals(DeviceIdentity.MAC_13_1.clientInfo(LoginBundles.XCODE), acc.clientInfo)
        assertEquals(OracleDevice.anisette, acc.anisetteHeaders())
        assertFalse(acc.hasPassword())
        assertEquals(session, acc.snapshot())                      // savedAt stays when the tokens were obtained
    }

    @Test fun aSessionFromAnotherMachineIsRefused() {
        val other = OracleDevice.device.copy(deviceId = "00006000-FFFFFFFFFFFFFFFF")
        try {
            AppleAccount.restore(session, other, FakeAnisette()); fail()
        } catch (e: OpenFinderException) {
            assertTrue(e.error is OpenFinderError.Authentication)
        }
    }
}
