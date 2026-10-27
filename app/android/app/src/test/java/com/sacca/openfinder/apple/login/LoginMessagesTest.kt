package com.sacca.openfinder.apple.login

import com.sacca.openfinder.anisette.MachineIdentity
import com.sacca.openfinder.apple.Plist
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Base64

/** Header sets, `cpd`, bodies and the 2FA page parsing against the Python's own output (`headers.json`). */
class LoginMessagesTest {
    private val h = JSONObject(fixture("headers.json"))
    private val fixed = h.getJSONObject("fixed")
    private fun map(key: String) = LoginTestSupport.stringMap(h.getJSONObject(key))

    /** What CoreAdiAnisetteProvider.httpHeaders() returns for the oracle's values (its own composition). */
    private fun provisioningShaped(deviceId: String = OracleDevice.devid.lowercase()) = mapOf(
        "X-Apple-I-Client-Time" to fixed.getString("time"),
        "X-Apple-I-MD" to fixed.getString("otp"),
        "X-Apple-I-MD-LU" to Base64.getEncoder().encodeToString(OracleDevice.uid.toByteArray()),
        "X-Apple-I-MD-M" to fixed.getString("mid"),
        "X-Apple-I-MD-RINFO" to fixed.getString("routing"),
        "X-Apple-I-SRL-NO" to OracleDevice.serial,
        "X-Apple-I-TimeZone" to "UTC",
        "X-Apple-Locale" to "en_US",
        "X-MMe-Client-Info" to "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
        "X-Mme-Device-Id" to deviceId,
    )

    @Test fun provisioningHeadersBecomePythonsLoginSet() {
        val login = LoginAnisette.fromProvisioningHeaders(provisioningShaped())
        assertEquals(map("get_headers"), login)
        assertEquals(LoginAnisette.KEYS.toSet(), login.keys)
    }

    @Test fun cpdMatchesGetCpd() {
        val expected = LoginTestSupport.fromOracle(h.getJSONObject("get_cpd"))
        LoginTestSupport.assertPlistEquals("cpd", expected, LoginMessages.cpd(map("get_headers")))
        // and it survives the plist round trip with its types (booleans stay booleans, RINFO stays a string)
        val body = Plist.parseDict(LoginMessages.gsaBody(mapOf("o" to "init"), LoginMessages.cpd(map("get_headers"))))
        LoginTestSupport.assertPlistEquals("body", mapOf("Header" to mapOf("Version" to "1.0.1"), "Request" to mapOf("cpd" to expected, "o" to "init")), body)
    }

    @Test fun identityCompositesMatchPython() {
        val id = DeviceIdentity.MAC_13_1
        assertEquals(h.getString("client_akd"), id.clientInfo(LoginBundles.AKD))
        assertEquals(h.getString("client_xcode"), id.clientInfo(LoginBundles.XCODE))
        assertEquals(h.getString("accountsd_client_info"), id.clientInfo(LoginBundles.ACCOUNTSD))
        assertEquals(h.getString("icloud_helper_user_agent"), id.userAgent(LoginBundles.ICLOUD_HELPER))
        assertEquals(h.getString("akd_user_agent"), id.userAgent("akd/1.0"))
        assertEquals(h.getString("gsa_user_agent"), LoginBundles.GSA_USER_AGENT)
        val identity = h.getJSONObject("identity")
        assertEquals(DeviceIdentity(identity.getString("model"), identity.getString("os_name"), identity.getString("os_version"),
            identity.getString("os_build"), identity.getString("cfnetwork"), identity.getString("darwin")), id)
    }

    /** The machine file's client info is the akd composite of the identity it parses to: one device, one string. */
    @Test fun machineClientInfoRoundTrips() {
        val machine = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        val device = LoginDevice.fromMachine(MachineIdentity("00006000-0A1B2C3D4E5F6071", OracleDevice.uid, machine, "C02X", 7L), OracleDevice.hostUuid)
        assertEquals(machine, device.identity.clientInfo(LoginBundles.AKD))
        assertEquals("A0A1A2A3-A4A5-A6A7-A8A9-AAABACADAEAF", device.cloudKitDeviceUuid)
        try { DeviceIdentity.fromClientInfo("<iPhone14,2> <iPhone OS;99.0;ZZZ> <x>"); fail() } catch (_: IllegalArgumentException) {}
        try {
            LoginDevice.fromMachine(MachineIdentity("d", "u", "<iPhone14,2> <iPhone OS;99.0;ZZZ> <x>", null, null), OracleDevice.hostUuid); fail()
        } catch (e: com.sacca.openfinder.domain.OpenFinderException) {
            assertTrue(e.error is com.sacca.openfinder.domain.OpenFinderError.Backend)
        }
    }

    @Test fun cloudKitUuidPrefersARealUuid() {
        assertEquals("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", LoginDevice.cloudKitUuid("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", null))
        try { LoginDevice.cloudKitUuid("00006000-0A1B2C3D4E5F6071", null); fail() } catch (_: IllegalArgumentException) {}
    }

    @Test fun twoFactorHeadersMatchGetHeadersWithClientInfo() {
        val token = h.getJSONObject("identity_token")
        val built = LoginMessages.twoFactorHeaders(DeviceIdentity.MAC_13_1, token.getString("value"), map("get_headers"))
        val expected = map("get_headers_with_client_info") + mapOf(
            "User-Agent" to "Xcode", "Accept-Language" to "en-us", "X-Apple-Identity-Token" to token.getString("value"),
        )
        assertEquals(expected, built)
    }

    @Test fun identityTokenAndJsonBodiesAreByteIdentical() {
        val token = h.getJSONObject("identity_token")
        assertEquals(token.getString("value"), LoginMessages.identityToken(token.getString("adsid"), token.getString("idms_token")))
        assertEquals(h.getString("sms_request_body"), LoginMessages.smsRequestBody(2))
        assertEquals(h.getString("sms_submit_body"), LoginMessages.smsSubmitBody(2, "123456"))
        assertEquals("\"a\\\"b\\u00e9\"", LoginMessages.pyJsonString("a\"bé"))
    }

    @Test fun anisetteNeverBringsItsOwnClientInfo() {
        val withCi = map("get_headers") + ("x-mme-client-info" to "<Bogus> <x;y;z> <com.apple.dt.Xcode/1>")
        val mm = LoginMessages.loginDelegatesHeaders(DeviceIdentity.MAC_13_1, "adsid", withCi)
        assertEquals(h.getString("accountsd_client_info"), mm["X-Mme-Client-Info"])
        assertFalse(mm.containsKey("x-mme-client-info"))
    }

    @Test fun phoneNumbersAreExtractedLikeBs4() {
        val cases = h.getJSONArray("phones")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val expected = c.getJSONArray("numbers").let { a ->
                (0 until a.length()).map { a.getJSONObject(it) }.map { n ->
                    val id = n.opt("id").let { if (it is Number && it.toLong() != 0L) it.toLong() else -1L }
                    val num = n.opt("numberWithDialCode").let { if (it is String && it.isNotEmpty()) it else "-" }
                    SecondFactorMethod.Sms(id, num)
                }
            }
            assertEquals(c.getString("name"), expected, LoginMessages.extractPhoneNumbers(c.getString("html")))
        }
        assertTrue(h.getString("phones_missing_script").startsWith("RuntimeError"))
        try { LoginMessages.extractPhoneNumbers("<html><body>no script</body></html>"); fail() } catch (_: IllegalArgumentException) {}
    }

    @Test fun phoneNumberFallbacksMatchPythonFlowOutcome() {
        // Python's get_2fa_methods on the oracle page: ids 1, 2 and the `or -1` / `or "-"` fallback.
        val parsed = LoginMessages.extractPhoneNumbers(h.getJSONArray("phones").getJSONObject(0).getString("html"))
        assertEquals(listOf(1L, 2L, -1L), parsed.map { it.phoneNumberId })
        assertEquals("-", parsed.last().phoneNumber)
    }
}
