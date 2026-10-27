package com.sacca.openfinder.apple.login

import com.sacca.openfinder.apple.Plist
import com.sacca.openfinder.domain.GrandSlamStep
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import okhttp3.OkHttpClient
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.net.URI
import java.util.Base64

/**
 * Whole login flows replayed against the Python. `login_vectors.py` drove the real `AsyncAppleAccount` (with our
 * `auth_probe.py` wrappers) against a scripted server and recorded every request it sent and every reply it got. Here the
 * same replies are served by a MockWebServer and the Kotlin client must send the same requests, in the same order, with the
 * same headers and (structurally) the same bodies. Because the SRP secrets are the oracle's, Apple's side of the
 * cryptography (M2, the encrypted `spd`) verifies for real.
 */
class LoginFlowOracleTest {
    private val flows: JSONArray = JSONArray(fixture("flows.json"))
    private lateinit var server: MockWebServer
    private lateinit var exchanges: List<JSONObject>
    private val seen = mutableListOf<RecordedRequest>()

    private fun scenario(name: String): JSONObject =
        (0 until flows.length()).map { flows.getJSONObject(it) }.first { it.getString("name") == name }

    @Before fun start() {
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val i = seen.size
                seen += request
                if (i >= exchanges.size) return MockResponse.Builder().code(599).body("unexpected extra request").build()
                val r = exchanges[i].getJSONObject("response")
                val b = MockResponse.Builder().code(r.getInt("status")).body(okio.Buffer().write(b64d(r.getString("body"))))
                LoginTestSupport.stringMap(r.getJSONObject("headers")).forEach { (k, v) -> b.addHeader(k, v) }
                return b.build()
            }
        }
        server.start()
    }

    @After fun stop() = server.close()

    private fun account(sc: JSONObject, anisette: FakeAnisette = FakeAnisette()): Pair<AppleAccount, FakeAnisette> {
        exchanges = sc.getJSONArray("exchanges").let { a -> (0 until a.length()).map { a.getJSONObject(it) } }
        val a = sc.getJSONArray("a_values").let { arr -> (0 until arr.length()).map { unhex(arr.getString(it)) } }.iterator()
        val endpoints = LoginEndpoints.under(server.url("/").toString(), setOf(server.hostName))
        return AppleAccount(OracleDevice.device, anisette, endpoints = endpoints, baseHttp = OkHttpClient(), ephemeral = { a.next() }) to anisette
    }

    /** Every request the Kotlin client sent equals the one Python sent at the same position. */
    private fun assertSameRequestsAsPython() {
        assertEquals("number of requests: ${seen.map { it.url.encodedPath }}", exchanges.size, seen.size)
        exchanges.forEachIndexed { i, py ->
            val kt = seen[i]
            val where = "request $i (${py.getString("method")} ${URI(py.getString("url")).path})"
            assertEquals(where, py.getString("method"), kt.method)
            assertEquals(where, URI(py.getString("url")).path, kt.url.encodedPath)
            for ((name, value) in LoginTestSupport.stringMap(py.getJSONObject("headers"))) {
                if (name.equals("Content-Type", ignoreCase = true)) {
                    assertEquals("$where $name", value, kt.headers[name]?.substringBefore(';'))
                } else {
                    assertEquals("$where $name", value, kt.headers[name])
                }
            }
            py.optString("implied_content_type").takeIf { it.isNotEmpty() && it != "null" }?.let {
                assertEquals("$where implied Content-Type", it, kt.headers["Content-Type"])
            }
            // ...and the reverse: Kotlin sends nothing Python did not, beyond what the HTTP stack itself adds.
            val pyNames = LoginTestSupport.stringMap(py.getJSONObject("headers")).keys.map { it.lowercase() }.toMutableSet()
            pyNames += setOf("host", "connection", "accept-encoding", "content-length")
            if (py.optString("implied_content_type").let { it.isNotEmpty() && it != "null" }) pyNames += "content-type"
            if (py.optJSONArray("auth") != null) pyNames += "authorization"
            val extra = kt.headers.names().map { it.lowercase() }.filter { it !in pyNames }
            assertEquals("$where headers Python did not send", emptyList<String>(), extra)
            assertEquals("$where duplicated headers", kt.headers.names().size, kt.headers.size)
            val auth = py.optJSONArray("auth")
            if (auth != null) {
                val basic = "Basic " + Base64.getEncoder().encodeToString("${auth.getString(0)}:${auth.getString(1)}".toByteArray(Charsets.ISO_8859_1))
                assertEquals("$where Authorization", basic, kt.headers["Authorization"])
            } else {
                assertEquals("$where Authorization", null, kt.headers["Authorization"])
            }
            val pyBody = b64d(py.getString("body"))
            val ktBody = kt.body?.toByteArray() ?: ByteArray(0)
            when (py.getString("body_kind")) {
                "plist" -> LoginTestSupport.assertPlistEquals(where, Plist.parseDict(pyBody), Plist.parseDict(ktBody))
                "json" -> assertEquals(where, String(pyBody), String(ktBody))
                else -> assertEquals("$where has no body", 0, ktBody.size)
            }
        }
    }

    private fun outcome(sc: JSONObject) = sc.getJSONObject("outcome")

    private suspend fun assertSignedInAsPython(acc: AppleAccount, o: JSONObject) {
        assertEquals(LoginState.LOGGED_IN, acc.loginState)
        assertEquals(o.getString("dsid"), acc.dsid)
        assertEquals(o.getString("adsid"), acc.adsid)
        assertEquals(o.getString("account_name"), acc.accountName)
        assertEquals(o.getString("first_name"), acc.accountInfo?.firstName)
        assertEquals(o.getString("last_name"), acc.accountInfo?.lastName)
        val tokens = LoginTestSupport.stringMap(o.getJSONObject("tokens"))
        assertEquals(tokens.keys, acc.serviceTokenNames())
        tokens.forEach { (k, v) -> assertEquals(k, v, acc.serviceToken(k)) }
        assertEquals(o.getString("idms_hb"), acc.snapshot().idmsHb)
    }

    @Test fun signInWithoutSecondFactorThenRenewThePet() = runTest {
        val sc = scenario("signin_no_2fa")
        val (acc, _) = account(sc)
        assertEquals(LoginResult.SignedIn, acc.login(sc.getString("username"), sc.getString("password").toCharArray()))
        assertSignedInAsPython(acc, outcome(sc))
        assertEquals(outcome(sc).getString("pet"), acc.requestPet())
        assertEquals(LoginState.LOGGED_IN, acc.loginState)
        assertSignedInAsPython(acc, outcome(sc))           // the renewal changed nothing about the session
        val stored = acc.snapshot().toJson()
        for (secret in listOf(sc.getString("password"), "PET-1", outcome(sc).getString("pet"))) assertTrue(secret, !stored.contains(secret))
        assertSameRequestsAsPython()
        // gsa.apple.com refuses a reused connection: init and complete must arrive on different connections.
        val gsa = seen.filter { it.url.encodedPath == "/grandslam/GsService2" }.map { it.connectionIndex }
        assertEquals(gsa.size, gsa.toSet().size)
    }

    @Test fun trustedDevicePushWithPhoneNumbersListed() = runTest {
        val sc = scenario("signin_trusted_device")
        val (acc, _) = account(sc)
        val r = acc.login(sc.getString("username"), sc.getString("password").toCharArray())
        val expected = outcome(sc).getJSONArray("methods").let { a -> (0 until a.length()).map { a.getJSONObject(it) } }.map {
            if (it.getString("kind") == "trusted_device") SecondFactorMethod.TrustedDevice else SecondFactorMethod.Sms(it.getLong("id"), it.getString("number"))
        }
        assertEquals(LoginResult.SecondFactorRequired(expected), r)
        assertEquals(LoginState.REQUIRE_2FA, acc.loginState)
        assertEquals(null, acc.serviceToken("searchPartyToken"))
        acc.requestTrustedDeviceCode()
        assertEquals(LoginResult.SignedIn, acc.submitTrustedDeviceCode("123456"))
        assertSignedInAsPython(acc, outcome(sc))
        assertSameRequestsAsPython()
    }

    @Test fun hsc409WithoutAuIsATrustedDeviceSecondFactor() = runTest {
        val sc = scenario("signin_trusted_device_409")
        val (acc, _) = account(sc)
        val r = acc.login(sc.getString("username"), sc.getString("password").toCharArray(), listPhoneNumbers = false)
        assertEquals(LoginResult.SecondFactorRequired(listOf(SecondFactorMethod.TrustedDevice)), r)
        assertTrue(acc.accountInfo!!.trustedDevice2fa)
        acc.requestTrustedDeviceCode()
        acc.submitTrustedDeviceCode(" 123456 ")
        assertSignedInAsPython(acc, outcome(sc))
        assertSameRequestsAsPython()
    }

    @Test fun smsSecondFactor() = runTest {
        val sc = scenario("signin_sms")
        val (acc, _) = account(sc)
        val r = acc.login(sc.getString("username"), sc.getString("password").toCharArray()) as LoginResult.SecondFactorRequired
        assertTrue(SecondFactorMethod.TrustedDevice !in r.methods)
        val sms = r.methods.filterIsInstance<SecondFactorMethod.Sms>()[1]
        assertEquals(2L, sms.phoneNumberId)
        acc.requestSmsCode(sms.phoneNumberId)
        assertEquals(LoginResult.SignedIn, acc.submitSmsCode(sms.phoneNumberId, "123456"))
        assertSignedInAsPython(acc, outcome(sc))
        assertSameRequestsAsPython()
    }

    @Test fun resync434IsAnsweredAndTheSameInitResent() = runTest {
        val sc = scenario("resync_434_on_init")
        val (acc, anisette) = account(sc)
        assertEquals(LoginResult.SignedIn, acc.login(sc.getString("username"), sc.getString("password").toCharArray()))
        val sims = sc.getJSONArray("resync_sims")
        assertEquals((0 until sims.length()).map { sims.getString(it) }, anisette.sims)
        // The resent init carries the same A: a resync renews the machine, not the SRP exchange.
        val first = Plist.parseDict(seen[0].body!!.toByteArray())["Request"] as Map<*, *>
        val again = Plist.parseDict(seen[1].body!!.toByteArray())["Request"] as Map<*, *>
        assertTrue((first["A2k"] as ByteArray).contentEquals(again["A2k"] as ByteArray))
        assertSignedInAsPython(acc, outcome(sc))
        assertSameRequestsAsPython()
    }

    @Test fun wrongPasswordRetainsTheCompleteRefusalAndForgetsTheDigest() = runTest {
        val sc = scenario("wrong_password")
        assertTrue(outcome(sc).getString("error").startsWith("InvalidCredentialsError"))
        val (acc, _) = account(sc)
        try {
            acc.login(sc.getString("username"), sc.getString("password").toCharArray()); fail()
        } catch (e: OpenFinderException) {
            assertTrue(e.error.toString(), e.error is OpenFinderError.GrandSlamRefused)
            val refusal = e.error as OpenFinderError.GrandSlamRefused
            assertEquals(GrandSlamStep.COMPLETE, refusal.step)
            assertFalse(refusal.beforePassword)
            assertEquals(-22406L, refusal.ec)
            assertTrue(e.error.message.contains("-22406"))
        }
        assertEquals(LoginState.LOGGED_OUT, acc.loginState)
        assertEquals(false, acc.hasPassword())
        assertSameRequestsAsPython()
    }

    @Test fun passwordCharArrayIsZeroed() = runTest {
        val sc = scenario("signin_no_2fa")
        val (acc, _) = account(sc)
        val pw = sc.getString("password").toCharArray()
        acc.login(sc.getString("username"), pw)
        assertTrue(pw.all { it == '\u0000' })
        assertNotEquals(0, pw.size)
    }
}
