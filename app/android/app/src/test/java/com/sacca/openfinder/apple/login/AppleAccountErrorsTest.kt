package com.sacca.openfinder.apple.login

import com.sacca.openfinder.apple.Cooldown
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
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay

/**
 * Error mapping and the recovery paths, built from the oracle's recorded replies (so the SRP side stays valid) with one
 * reply changed per test: throttling, refusals, malformed answers, a forged server proof, the delegate's two error
 * channels, the 434 resync's limits, a restored session's PET renewal and the second-factor edge cases.
 */
class AppleAccountErrorsTest {
    private val flows = JSONArray(fixture("flows.json"))
    private lateinit var server: MockWebServer
    private val queue = ArrayDeque<MockResponse>()
    private val seen = mutableListOf<RecordedRequest>()
    private val clock = Clock.fixed(Instant.parse("2026-10-17T12:34:56Z"), ZoneOffset.UTC)
    private val cooldownStore = MemoryCooldownStore()
    private val cooldown = Cooldown(cooldownStore, clock)

    private fun scenario(name: String) = (0 until flows.length()).map { flows.getJSONObject(it) }.first { it.getString("name") == name }
    private fun exchanges(sc: JSONObject) = sc.getJSONArray("exchanges").let { a -> (0 until a.length()).map { a.getJSONObject(it) } }
    private fun aValues(sc: JSONObject) = sc.getJSONArray("a_values").let { a -> (0 until a.length()).map { unhex(a.getString(it)) } }

    private val noTwoFactor = scenario("signin_no_2fa")
    private val username = noTwoFactor.getString("username")
    private val password = noTwoFactor.getString("password")

    /** The recorded reply of exchange [i] of [sc], optionally with its `Response` plist edited. */
    private fun recorded(sc: JSONObject, i: Int, edit: ((MutableMap<String, Any?>) -> Unit)? = null): MockResponse {
        val r = exchanges(sc)[i].getJSONObject("response")
        var body = b64d(r.getString("body"))
        if (edit != null) {
            val root = Plist.parseDict(body).toMutableMap()
            @Suppress("UNCHECKED_CAST")
            val response = (root["Response"] as? Map<String, Any?>)?.toMutableMap()
            if (response != null) { edit(response); root["Response"] = response } else edit(root)
            body = Plist.toXml(root)
        }
        return MockResponse.Builder().code(r.getInt("status")).body(okio.Buffer().write(body)).build()
    }

    private fun plist(root: Map<String, Any?>, code: Int = 200) = MockResponse.Builder().code(code).body(okio.Buffer().write(Plist.toXml(root))).build()
    private fun text(code: Int, body: String = "") = MockResponse.Builder().code(code).body(body).build()

    @Before fun start() {
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                seen += request
                return queue.removeFirstOrNull() ?: text(599, "unexpected request")
            }
        }
        server.start()
    }

    @After fun stop() = server.close()

    private fun account(sc: JSONObject = noTwoFactor, anisette: FakeAnisette = FakeAnisette()): AppleAccount {
        val a = aValues(sc).iterator()
        return AppleAccount(
            OracleDevice.device, anisette, cooldown, LoginEndpoints.under(server.url("/").toString(), setOf(server.hostName)),
            baseHttp = OkHttpClient(), ephemeral = { if (a.hasNext()) a.next() else SrpClient.randomEphemeral() }, clock = clock,
        )
    }

    private inline fun <reified E : OpenFinderError> assertFails(block: () -> Unit): E {
        try { block() } catch (e: OpenFinderException) {
            assertTrue("expected ${E::class.simpleName} but got ${e.error}", e.error is E)
            return e.error as E
        }
        fail("expected a OpenFinderException"); throw IllegalStateException()
    }

    // ---------------------------------------------------------------- Grand Slam

    @Test fun throttledInitStartsTheCooldownAndNothingMoreIsSent() = runTest {
        queue += text(429, "<html>Too Many Requests</html>")
        val acc = account()
        assertFails<OpenFinderError.Throttled> { acc.login(username, password.toCharArray()) }
        assertEquals(clock.instant().epochSecond, cooldownStore.last429EpochSeconds)
        assertFails<OpenFinderError.Throttled> { acc.login(username, password.toCharArray()) }
        assertEquals(1, seen.size)                                   // the cooldown refused before sending
        assertEquals(LoginState.LOGGED_OUT, acc.loginState)
    }

    @Test fun serviceUnavailableCarriesStatusAndRetryAfter() = runTest {
        queue += MockResponse.Builder().code(503).addHeader("Retry-After", "120").body("<html/>").build()
        val e = assertFails<OpenFinderError.Rejected> { account().login(username, password.toCharArray()) }
        assertEquals(503, e.http)
        assertTrue(e.message, e.message.contains("120"))
    }

    @Test fun nonPlistReplyIsBackend() = runTest {
        queue += text(200, "<html>edge page</html>")
        assertFails<OpenFinderError.Backend> { account().login(username, password.toCharArray()) }
    }

    @Test fun appleStatusIsReportedVerbatim() = runTest {
        queue += plist(mapOf("Response" to mapOf("Status" to mapOf("ec" to -20209L, "em" to "This Apple ID has been locked for security reasons."))))
        val e = assertFails<OpenFinderError.GrandSlamRefused> { account().login(username, password.toCharArray()) }
        assertEquals(GrandSlamStep.INIT, e.step)
        assertTrue(e.beforePassword)
        assertEquals(-20209L, e.ec)
        assertEquals("This Apple ID has been locked for security reasons.", e.em)
        assertTrue(e.message.contains("locked for security reasons"))
        assertTrue(e.message.contains("password was not sent"))
    }

    @Test fun refusalWithoutAppleMessageKeepsItsStepAndCode() = runTest {
        queue += plist(mapOf("Response" to mapOf("Status" to mapOf("ec" to -22421L))))
        val e = assertFails<OpenFinderError.GrandSlamRefused> { account().login(username, password.toCharArray()) }
        assertEquals(GrandSlamStep.INIT, e.step)
        assertTrue(e.beforePassword)
        assertEquals(-22421L, e.ec)
        assertEquals(null, e.em)
        assertTrue(e.message.contains("no message"))
    }

    @Test fun badCredentialsCodeAtInitDoesNotBlameThePassword() = runTest {
        queue += plist(mapOf("Response" to mapOf("Status" to mapOf("ec" to -22406L, "em" to "Your Apple ID or password was incorrect."))))
        val e = assertFails<OpenFinderError.GrandSlamRefused> { account().login(username, password.toCharArray()) }
        assertEquals(GrandSlamStep.INIT, e.step)
        assertTrue(e.beforePassword)
        assertEquals(-22406L, e.ec)
        assertTrue(e.message.contains("password was not sent"))
    }

    @Test fun unsupportedPasswordProtocolIsBackend() = runTest {
        queue += recorded(noTwoFactor, 0) { it["sp"] = "s2k_new" }
        assertFails<OpenFinderError.Backend> { account().login(username, password.toCharArray()) }
        assertEquals(1, seen.size)
    }

    @Test fun forgedServerProofIsRefused() = runTest {
        queue += recorded(noTwoFactor, 0)
        queue += recorded(noTwoFactor, 1) { it["M2"] = ByteArray(32) }
        val acc = account()
        val e = assertFails<OpenFinderError.Backend> { acc.login(username, password.toCharArray()) }
        assertTrue(e.message.contains("proof"))
        assertEquals(LoginState.LOGGED_OUT, acc.loginState)
        assertEquals(2, seen.size)                                   // no delegate request after a failed proof
    }

    @Test fun unknownSecondFactorKindIsBackend() = runTest {
        queue += recorded(noTwoFactor, 0)
        queue += recorded(noTwoFactor, 1) { r -> r["Status"] = (r["Status"] as Map<*, *>) + ("au" to "somethingNew") }
        val e = assertFails<OpenFinderError.Backend> { account().login(username, password.toCharArray()) }
        assertTrue(e.message.contains("somethingNew"))
    }

    @Test fun corruptSessionPayloadIsBackend() = runTest {
        queue += recorded(noTwoFactor, 0)
        queue += recorded(noTwoFactor, 1) { it["spd"] = ByteArray(48) { 7 } }
        assertFails<OpenFinderError.Backend> { account().login(username, password.toCharArray()) }
    }

    @Test fun networkFailureIsNetwork() = runTest {
        val acc = account()
        server.close()
        assertFails<OpenFinderError.Network> { acc.login(username, password.toCharArray()) }
    }

    // ---------------------------------------------------------------- resync

    @Test fun aSecond434IsNotAnsweredAgain() = runTest {
        val resync = mapOf("Response" to mapOf("Status" to mapOf("ec" to -22421L, "em" to "Anisette Resync Required", "hsc" to 434L, "X-Apple-I-MD-DATA" to "U0lN")))
        queue += plist(resync); queue += plist(resync)
        val anisette = FakeAnisette()
        val e = assertFails<OpenFinderError.GrandSlamRefused> { account(anisette = anisette).login(username, password.toCharArray()) }
        assertEquals(-22421L, e.ec)
        assertEquals(listOf("U0lN"), anisette.sims)
        assertEquals(2, seen.size)
    }

    @Test fun aRefusedResyncStopsTheLogin() = runTest {
        queue += plist(mapOf("Response" to mapOf("Status" to mapOf("ec" to -22421L, "hsc" to 434L, "X-Apple-I-MD-DATA" to "U0lN"))))
        val anisette = FakeAnisette(onResync = { throw OpenFinderException(OpenFinderError.Rejected(200, -1L, "refused")) })
        assertFails<OpenFinderError.Rejected> { account(anisette = anisette).login(username, password.toCharArray()) }
        assertEquals(1, seen.size)
    }

    @Test fun http434WithTheSimInAHeaderIsAnsweredToo() = runTest {
        queue += MockResponse.Builder().code(434).addHeader("X-Apple-I-MD-DATA", "SEVBREVS").build()
        repeat(3) { queue += recorded(noTwoFactor, it) }
        val anisette = FakeAnisette()
        assertEquals(LoginResult.SignedIn, account(anisette = anisette).login(username, password.toCharArray()))
        assertEquals(listOf("SEVBREVS"), anisette.sims)
        assertEquals(4, seen.size)
    }

    // ---------------------------------------------------------------- delegate

    @Test fun delegateUnauthorizedIsAuthenticationAndCompleteLoginRetries() = runTest {
        queue += recorded(noTwoFactor, 0); queue += recorded(noTwoFactor, 1)
        queue += plist(mapOf("localizedError" to "UNAUTHORIZED", "status" to 1L, "description" to "nope"), code = 401)
        queue += recorded(noTwoFactor, 2)
        val acc = account()
        assertFails<OpenFinderError.Authentication> { acc.login(username, password.toCharArray()) }
        assertEquals(LoginState.AUTHENTICATED, acc.loginState)
        assertEquals(LoginResult.SignedIn, acc.completeLogin())
        assertEquals("SP-TOKEN", acc.serviceToken("searchPartyToken"))
        assertEquals(seen[2].headers["Authorization"], seen[3].headers["Authorization"])   // the same PET, resent
    }

    @Test fun delegateRefusingTheAccountReportsItsOwnStatus() = runTest {
        queue += recorded(noTwoFactor, 0); queue += recorded(noTwoFactor, 1)
        queue += plist(mapOf("dsid" to "1", "delegates" to mapOf("com.apple.mobileme" to mapOf("status" to 1L, "status-message" to "Account limit reached"))))
        val e = assertFails<OpenFinderError.Rejected> { account().login(username, password.toCharArray()) }
        assertEquals(1L, e.ec)
        assertTrue(e.message, e.message.contains("Account limit reached") && e.message.contains("not the terms channel"))
    }

    @Test fun delegateServerErrorWithoutPlistIsRejected() = runTest {
        queue += recorded(noTwoFactor, 0); queue += recorded(noTwoFactor, 1)
        queue += text(500, "oops")
        assertEquals(500, assertFails<OpenFinderError.Rejected> { account().login(username, password.toCharArray()) }.http)
    }

    // ---------------------------------------------------------------- PET and refresh

    private suspend fun signedIn(): AppleAccount {
        repeat(3) { queue += recorded(noTwoFactor, it) }
        return account().also { it.login(username, password.toCharArray()) }
    }

    @Test fun restoredSessionNeedsThePasswordToRenewAPet() = runTest {
        val saved = signedIn().snapshot()
        seen.clear()
        val a = aValues(noTwoFactor).drop(1).iterator()
        val restored = AppleAccount.restore(saved, OracleDevice.device, FakeAnisette(), cooldown,
            LoginEndpoints.under(server.url("/").toString(), setOf(server.hostName)), baseHttp = OkHttpClient(), ephemeral = { a.next() })
        assertEquals("SP-TOKEN", restored.serviceToken("searchPartyToken"))
        assertFails<OpenFinderError.Authentication> { restored.requestPet() }
        assertEquals(0, seen.size)
        queue += recorded(noTwoFactor, 3); queue += recorded(noTwoFactor, 4)
        restored.providePassword(password.toCharArray())
        assertEquals(noTwoFactor.getJSONObject("outcome").getString("pet"), restored.requestPet())
        assertEquals(LoginState.LOGGED_IN, restored.loginState)
        assertEquals("SP-TOKEN", restored.serviceToken("searchPartyToken"))
    }

    /** Other pieces read the account while a PET is renewed: they must keep seeing the signed-in session, never a half state. */
    @Test fun petRenewalNeverExposesAHalfUpdatedSession() = runTest {
        val acc = signedIn()
        queue += recorded(noTwoFactor, 3).newBuilder().headersDelay(400, TimeUnit.MILLISECONDS).build()
        queue += recorded(noTwoFactor, 4).newBuilder().headersDelay(400, TimeUnit.MILLISECONDS).build()
        coroutineScope {
            val pet = async(Dispatchers.Default) { acc.requestPet() }
            suspend fun stillSignedIn() {
                assertEquals(LoginState.LOGGED_IN, acc.loginState)
                assertEquals("1234567890", acc.dsid)
                assertEquals("000123-05-synthetic", acc.adsid)
                assertEquals("SP-TOKEN", acc.serviceToken("searchPartyToken"))
            }
            var reads = 0
            while (!pet.isCompleted) { stillSignedIn(); reads++; delay(10) }
            assertEquals("PET-2", pet.await())
            stillSignedIn()
            assertTrue("the reads overlapped the renewal", reads > 20)
        }
    }

    @Test fun petRenewalAnsweredWithASecondFactorKeepsTheSession() = runTest {
        val acc = signedIn()
        queue += recorded(noTwoFactor, 3)
        queue += recorded(noTwoFactor, 4) { r -> r["Status"] = mapOf("ec" to 0L, "au" to "trustedDeviceSecondaryAuth") }
        assertFails<OpenFinderError.Authentication> { acc.requestPet() }
        assertEquals(LoginState.LOGGED_IN, acc.loginState)
        assertEquals("SP-TOKEN", acc.serviceToken("searchPartyToken"))
    }

    @Test fun refreshSessionRedoesTheDelegateAndKeepsTheOldOnFailure() = runTest {
        val acc = signedIn()
        queue += recorded(noTwoFactor, 3); queue += recorded(noTwoFactor, 4)
        queue += plist(mapOf("dsid" to "1234567890", "status" to 0L, "delegates" to mapOf("com.apple.mobileme" to mapOf("status" to 0L, "service-data" to mapOf("tokens" to mapOf("searchPartyToken" to "SP-NEW"))))))
        acc.refreshSession()
        assertEquals("SP-NEW", acc.serviceToken("searchPartyToken"))
        queue += text(503)
        assertFails<OpenFinderError.Rejected> { acc.refreshSession() }
        assertEquals(LoginState.LOGGED_IN, acc.loginState)
        assertEquals("SP-NEW", acc.serviceToken("searchPartyToken"))
    }

    // ---------------------------------------------------------------- second factor

    @Test fun failedPhonePageStillOffersTheTrustedDevice() = runTest {
        val td = scenario("signin_trusted_device")
        queue += recorded(td, 0); queue += recorded(td, 1); queue += text(401)
        val r = account(td).login(username, password.toCharArray())
        assertEquals(LoginResult.SecondFactorRequired(listOf(SecondFactorMethod.TrustedDevice)), r)
    }

    @Test fun failedPhonePageWithoutTrustedDeviceIsAnError() = runTest {
        val sms = scenario("signin_sms")
        queue += recorded(sms, 0); queue += recorded(sms, 1); queue += text(401)
        val acc = account(sms)
        assertEquals(401, assertFails<OpenFinderError.Rejected> { acc.login(username, password.toCharArray()) }.http)
        assertEquals(LoginState.REQUIRE_2FA, acc.loginState)
        queue += recorded(sms, 2)
        assertEquals(3, acc.secondFactorMethods().size)              // asking again works
    }

    @Test fun refusedTrustedDeviceCodeStopsBeforeAuthenticatingAgain() = runTest {
        val td = scenario("signin_trusted_device_409")
        queue += recorded(td, 0); queue += recorded(td, 1)
        val acc = account(td)
        acc.login(username, password.toCharArray(), listPhoneNumbers = false)
        queue += plist(mapOf("Response" to mapOf("Status" to mapOf("ec" to -21669L, "em" to "Incorrect verification code."))))
        val e = assertFails<OpenFinderError.Rejected> { acc.submitTrustedDeviceCode("000000") }
        assertEquals(-21669L, e.ec)
        assertEquals(3, seen.size)
        assertEquals(LoginState.REQUIRE_2FA, acc.loginState)
    }

    @Test fun throttledSmsRequestIsThrottled() = runTest {
        val sms = scenario("signin_sms")
        queue += recorded(sms, 0); queue += recorded(sms, 1)
        val acc = account(sms)
        acc.login(username, password.toCharArray(), listPhoneNumbers = false)
        queue += text(429)
        assertFails<OpenFinderError.Throttled> { acc.requestSmsCode(2) }
        assertTrue(cooldown.remainingSeconds() > 0)
    }

    @Test fun callsInTheWrongStateAreProgrammingErrors() = runTest {
        val acc = account()
        val calls: List<suspend () -> Unit> = listOf(
            { acc.submitSmsCode(1, "1"); Unit }, { acc.requestTrustedDeviceCode() }, { acc.requestPet(); Unit },
            { acc.completeLogin(); Unit }, { acc.snapshot(); Unit },
        )
        for (call in calls) {
            try { call(); fail() } catch (_: IllegalStateException) {}
        }
        assertEquals(0, seen.size)
        assertFalse(acc.hasPassword())
    }
}
