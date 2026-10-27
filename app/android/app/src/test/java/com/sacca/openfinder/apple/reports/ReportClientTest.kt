package com.sacca.openfinder.apple.reports

import com.sacca.openfinder.apple.Cooldown
import com.sacca.openfinder.apple.CooldownStore
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import okhttp3.Credentials
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.util.Base64

private class MemoryCooldown(override var last429EpochSeconds: Long? = null) : CooldownStore

/** MockWebServer end to end: the exact request the client sends, and how it handles Apple's answers. */
class ReportClientTest {
    private lateinit var server: MockWebServer
    private val account = FakeAccount()
    private val seen = mutableListOf<RecordedRequest>()
    private var replies: (Int) -> MockResponse = { MockResponse.Builder().code(404).build() }
    private val pauses = mutableListOf<Long>()
    private val f = ReportFixtures

    @Before fun start() {
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                seen += request
                return replies(seen.size - 1)
            }
        }
        server.start()
    }

    @After fun stop() = server.close()

    private fun clientAt(now: Instant, cooldown: Cooldown? = null, reauth: (suspend () -> Boolean)? = null) = ReportClient(
        account, endpoint = server.url("/findmyservice/v2/fetch").toString(), clock = Clock.fixed(now, ZoneOffset.UTC),
        cooldown = cooldown, reauthenticate = reauth, pause = { pauses += it },
    )

    private fun answer(code: Int = 200, body: String) = MockResponse.Builder().code(code).body(body).build()

    /** The v2 answer for a list of (hashedAdvKey, payload) pairs, grouped by id the way Apple does. */
    private fun v2(reports: List<Pair<String, String>>, status: String = "200"): String {
        val payload = JSONArray()
        for ((id, group) in reports.groupBy({ it.first }, { it.second })) {
            payload.put(JSONObject().put("id", id).put("locationInfo", JSONArray(group)))
        }
        return JSONObject().put("acsnLocations", JSONObject().put("statusCode", status).put("locationPayload", payload)).toString()
    }

    private fun sha(ids: List<String>) = MessageDigest.getInstance("SHA-256").digest(ids.sorted().joinToString("\n").toByteArray())
        .joinToString("") { "%02x".format(it) }

    private fun ids(entry: JSONObject, field: String): List<String> = entry.getJSONArray(field).let { a -> (0 until a.length()).map { a.getString(it) } }

    private fun assertEnvelope(request: RecordedRequest, now: Instant): JSONObject {
        assertEquals("POST", request.method)
        assertEquals("/findmyservice/v2/fetch", request.url.encodedPath)
        assertEquals(Credentials.basic("1234567890", "SYNTHETIC-SEARCH-PARTY-TOKEN"), request.headers["Authorization"])
        assertEquals("application/json", request.headers["Content-Type"])
        for ((k, v) in account.headers) assertEquals("header $k", v, request.headers[k])
        // The without-client-info Anisette set: the library's report request never carries these three.
        for (k in listOf("X-Mme-Client-Info", "X-Apple-App-Info", "X-Xcode-Version")) assertNull(k, request.headers[k])
        val body = JSONObject(request.body!!.utf8())
        assertEquals(setOf("clientContext", "fetch"), body.keys().asSequence().toSet())
        val ctx = body.getJSONObject("clientContext")
        assertEquals("com.apple.icloud.searchpartyuseragent", ctx.getString("clientBundleIdentifier"))
        assertEquals("foregroundClient", ctx.getString("policy"))
        for (entry in body.getJSONArray("fetch").objects()) {
            assertEquals(
                setOf("ownedDeviceIds", "keyType", "startDate", "startDateSecondary", "endDate", "primaryIds", "secondaryIds"),
                entry.keys().asSequence().toSet(),
            )
            assertEquals(1, entry.getInt("keyType"))
            assertEquals(0, entry.getJSONArray("ownedDeviceIds").length())
            val start = (now.epochSecond - 7 * 86400) * 1000
            assertEquals(start, entry.getLong("startDate"))
            assertEquals(start, entry.getLong("startDateSecondary"))
            assertEquals(now.epochSecond * 1000, entry.getLong("endDate"))
        }
        return body
    }

    // ---------------------------------------------------------------------------------- rolling accessories vs the oracle

    @Test fun everyRollingScenarioSendsPythonsRequestsAndReturnsPythonsReports() = runTest {
        val scenarios = f.json("fetch.json").getJSONArray("rolling").objects()
        assertTrue(scenarios.size >= 7)
        for (s in scenarios) {
            seen.clear()
            val name = s.getString("name")
            val now = OffsetDateTime.parse(s.getString("now")).toInstant()
            val steps = s.getJSONArray("replies")
            replies = { i ->
                val step = if (i < steps.length()) steps.getJSONArray(i).objects() else emptyList()
                answer(body = v2(step.map { it.getString("hashed") to it.getString("payload") }))
            }
            val accessory = AccessoryKeys.fromJson(s.getJSONObject("accessory"))
            val result = clientAt(now).fetchLocationHistory(accessory, onlyLatest = s.getBoolean("only_latest"))

            val calls = s.getJSONArray("calls")
            assertEquals("$name: number of requests", calls.length(), seen.size)
            assertEquals(calls.length(), result.requests)
            for (i in 0 until calls.length()) {
                val entries = assertEnvelope(seen[i], now).getJSONArray("fetch").objects()
                assertEquals(1, entries.size)
                val expected = calls.getJSONArray(i).getJSONObject(0)
                for (kind in listOf("primary", "secondary")) {
                    val sent = ids(entries[0], kind + "Ids")
                    val e = expected.getJSONObject(kind)
                    assertEquals("$name call $i $kind count", e.getInt("count"), sent.size)
                    assertEquals("$name call $i $kind set", e.getString("sha256"), sha(sent))
                    assertTrue("$name: ids are unique", sent.toSet().size == sent.size)
                    assertTrue("$name: at most 290 ids", sent.size <= 290)
                }
            }

            // Python's reports, minus what the app's domain rules drop (no (0,0) fix, no timestamp from the future).
            val expectedReports = s.getJSONArray("reports").objects().filter {
                !(it.getDouble("lat") == 0.0 && it.getDouble("lon") == 0.0) && it.getLong("ts") < now.epochSecond + 300
            }
            assertEquals("$name: reports", expectedReports.size, result.reports.size)
            for ((e, r) in expectedReports.zip(result.reports)) {
                assertEquals(e.getLong("ts"), r.observedAt.epochSecond)
                assertEquals(e.getDouble("lat"), r.latitude, 0.0)
                assertEquals(e.getDouble("lon"), r.longitude, 0.0)
                assertEquals(e.getInt("acc").toDouble(), r.horizontalAccuracyMeters!!, 0.0)
                assertEquals(e.getInt("status").toString(), r.metadata["status"])
                assertEquals(e.getInt("conf").toString(), r.metadata["confidence"])
                assertEquals(accessory.id, r.accessoryId)
                assertTrue(r.isValid(now))
            }
            assertEquals("$name: dropped by domain rules", s.getJSONArray("reports").length() - expectedReports.size, result.invalid)
            assertEquals("$name: alignment index", s.getInt("alignment_index"), accessory.alignmentIndex)
            assertEquals("$name: alignment date", s.getLong("alignment_epoch"), accessory.alignmentDate.toEpochSecond())
            assertEquals(0, result.undecryptable)
            assertFalse(result.emptyResponse)
        }
    }

    @Test fun onlyLatestStopsAtTheFirstRequestThatYieldsReports() = runTest {
        val s = f.json("fetch.json").getJSONArray("rolling").objects().first { it.getString("name") == "chunked_only_latest" }
        // 7 requests would be needed to cover the window; the second answer carries a report, so only 2 are sent.
        assertEquals(2, s.getJSONArray("calls").length())
        val nothing = f.json("fetch.json").getJSONArray("rolling").objects().first { it.getString("name") == "chunked_nothing_found" }
        assertEquals(7, nothing.getJSONArray("calls").length())
    }

    @Test fun fetchLocationReturnsTheNewestReport() = runTest {
        val s = f.json("fetch.json").getJSONArray("rolling").objects().first { it.getString("name") == "single_request_primary_then_secondary" }
        val steps = s.getJSONArray("replies").getJSONArray(0).objects()
        replies = { answer(body = v2(steps.map { it.getString("hashed") to it.getString("payload") })) }
        val accessory = AccessoryKeys.fromJson(s.getJSONObject("accessory"))
        val newest = clientAt(OffsetDateTime.parse(s.getString("now")).toInstant()).fetchLocation(accessory)!!
        assertEquals(s.getJSONArray("reports").objects().maxOf { it.getLong("ts") }, newest.observedAt.epochSecond)
    }

    // ------------------------------------------------------------------------------------------ static keys vs the oracle

    @Test fun staticKeysAreOneFetchEntryEachAndDecryptWithTheirOwnKey() = runTest {
        val st = f.json("fetch.json").getJSONObject("static")
        val now = OffsetDateTime.parse(st.getString("now")).toInstant()
        val reps = st.getJSONArray("replies").getJSONArray(0).objects()
        replies = { answer(body = v2(reps.map { it.getString("hashed") to it.getString("payload") })) }
        val keys = (0 until st.getJSONArray("keys").length()).map { KeyPair.fromB64(st.getJSONArray("keys").getString(it)) }
        val out = clientAt(now).fetchKeyHistory(keys)

        assertEquals(1, seen.size)
        val entries = assertEnvelope(seen[0], now).getJSONArray("fetch").objects()
        val expectedCalls = st.getJSONArray("calls").getJSONArray(0).objects()
        assertEquals(expectedCalls.size, entries.size)
        for ((i, e) in entries.withIndex()) {
            assertEquals(ids(expectedCalls[i], "primary"), ids(e, "primaryIds"))
            assertEquals(0, e.getJSONArray("secondaryIds").length())
        }
        for (key in keys) {
            val expected = st.getJSONObject("reports").getJSONArray(key.privateKeyB64).objects()
            val actual = out.getValue(key).reports
            assertEquals(expected.size, actual.size)
            for ((e, r) in expected.zip(actual)) {
                assertEquals(e.getLong("ts"), r.observedAt.epochSecond)
                assertEquals(e.getDouble("lat"), r.latitude, 0.0)
                assertEquals(e.getDouble("lon"), r.longitude, 0.0)
            }
        }
    }

    // ------------------------------------------------------------------------------------------------- replies we cannot use

    private fun simpleScenario() = f.json("fetch.json").getJSONArray("rolling").objects().first { it.getString("name") == "single_request_primary_then_secondary" }

    @Test fun corruptAndForeignReportsAreCountedNotFatal() = runTest {
        val s = simpleScenario()
        val steps = s.getJSONArray("replies").getJSONArray(0).objects()
        val good = steps.map { it.getString("hashed") to it.getString("payload") }
        val corrupt = good[0].first to Base64.getEncoder().encodeToString(f.b64(good[0].second).also { it[80] = (it[80].toInt() xor 1).toByte() })
        val foreign = Base64.getEncoder().encodeToString(ByteArray(32) { 9 }) to good[0].second
        replies = { answer(body = v2(listOf(corrupt, foreign, good[1]))) }
        val accessory = AccessoryKeys.fromJson(s.getJSONObject("accessory"))
        val r = clientAt(OffsetDateTime.parse(s.getString("now")).toInstant()).fetchLocationHistory(accessory)
        assertEquals(1, r.reports.size)
        assertEquals(1, r.undecryptable)
        assertEquals(1, r.unknownKey)
    }

    @Test fun emptyReplyListYieldsNoReports() = runTest {
        val s = simpleScenario()
        replies = { answer(body = v2(emptyList())) }
        val r = clientAt(OffsetDateTime.parse(s.getString("now")).toInstant()).fetchLocationHistory(AccessoryKeys.fromJson(s.getJSONObject("accessory")))
        assertTrue(r.reports.isEmpty())
        assertFalse(r.emptyResponse)
        assertEquals(1, seen.size)
    }

    @Test fun emptyBodyIsRetriedFiveTimesWithGrowingPausesThenReportedAsEmptyResponse() = runTest {
        val s = simpleScenario()
        replies = { answer(body = "") }
        val accessory = AccessoryKeys.fromJson(s.getJSONObject("accessory"))
        val r = clientAt(OffsetDateTime.parse(s.getString("now")).toInstant()).fetchLocationHistory(accessory)
        assertTrue(r.emptyResponse)
        assertTrue(r.reports.isEmpty())
        assertEquals(6, seen.size)                              // first attempt + 5 retries, as the library's bandaid
        assertEquals(listOf(2000L, 4000L, 6000L, 8000L, 10000L), pauses)
        assertEquals(6, account.anisetteCalls)                  // fresh Anisette headers for every attempt

        seen.clear()
        try { clientAt(Instant.parse("2026-10-03T12:00:00Z")).fetchRaw(listOf(KeyIds(listOf("AAAA")))); fail() } catch (e: OpenFinderException) {
            assertTrue(e.error is OpenFinderError.ReportsUnavailable)
        }
    }

    @Test fun anEmptyBodyThatRecoversIsRetriedTransparently() = runTest {
        val s = simpleScenario()
        val steps = s.getJSONArray("replies").getJSONArray(0).objects()
        replies = { i -> if (i < 2) answer(body = "  ") else answer(body = v2(steps.map { it.getString("hashed") to it.getString("payload") })) }
        val r = clientAt(OffsetDateTime.parse(s.getString("now")).toInstant()).fetchLocationHistory(AccessoryKeys.fromJson(s.getJSONObject("accessory")))
        assertEquals(2, r.reports.size)
        assertEquals(3, seen.size)
        assertEquals(listOf(2000L, 4000L), pauses)
    }

    // ----------------------------------------------------------------------------------------------------- error mapping

    private suspend fun failure(block: suspend () -> Unit): OpenFinderError {
        try { block(); fail("expected a OpenFinderException") } catch (e: OpenFinderException) { return e.error }
        error("unreachable")
    }

    private suspend fun fetchOnce(client: ReportClient = clientAt(Instant.parse("2026-10-03T12:00:00Z"))) = client.fetchRaw(listOf(KeyIds(listOf("AAAA"))))

    @Test fun http401IsAnAuthenticationFailureAndCanReauthenticateOnce() = runTest {
        replies = { answer(401, "") }
        assertTrue(failure { fetchOnce() } is OpenFinderError.Authentication)
        assertEquals(1, seen.size)

        seen.clear()
        var reauths = 0
        assertTrue(failure { fetchOnce(clientAt(Instant.parse("2026-10-03T12:00:00Z"), reauth = { reauths++; true })) } is OpenFinderError.Authentication)
        assertEquals(1, reauths)
        assertEquals(2, seen.size)                              // retried once, then gave up

        seen.clear()
        reauths = 0
        replies = { i -> if (i == 0) answer(401, "") else answer(body = v2(emptyList())) }
        assertTrue(fetchOnce(clientAt(Instant.parse("2026-10-03T12:00:00Z"), reauth = { reauths++; true })).isEmpty())
        assertEquals(1, reauths)

        seen.clear()
        replies = { answer(401, "") }
        assertTrue(failure { fetchOnce(clientAt(Instant.parse("2026-10-03T12:00:00Z"), reauth = { false })) } is OpenFinderError.Authentication)
        assertEquals(1, seen.size)                              // a refused reauthentication does not resend
    }

    @Test fun missingSearchPartyTokenIsAnAuthenticationFailureAndNothingIsSent() = runTest {
        account.token = null
        assertTrue(failure { fetchOnce() } is OpenFinderError.Authentication)
        assertTrue(seen.isEmpty())
    }

    @Test fun http429IsThrottledAndStartsTheSharedCooldown() = runTest {
        replies = { MockResponse.Builder().code(429).addHeader("Retry-After", "120").body("<html>slow down</html>").build() }
        val cooldown = Cooldown(MemoryCooldown(), Clock.fixed(Instant.parse("2026-10-03T12:00:00Z"), ZoneOffset.UTC))
        val e = failure { fetchOnce(clientAt(Instant.parse("2026-10-03T12:00:00Z"), cooldown)) }
        assertTrue(e is OpenFinderError.Throttled)
        assertTrue(e.message.contains("120"))
        assertTrue(cooldown.remainingSeconds() > 0)
        assertTrue(failure { fetchOnce(clientAt(Instant.parse("2026-10-03T12:00:00Z"), cooldown)) } is OpenFinderError.Throttled)
        assertEquals(1, seen.size)                              // the second call never reached the network
    }

    @Test fun http5xxIsABackendFailure() = runTest {
        for (code in listOf(500, 502, 503)) {
            replies = { answer(code, "oops") }
            assertTrue("HTTP $code", failure { fetchOnce() } is OpenFinderError.Backend)
        }
    }

    @Test fun otherRefusalsAreRejectedWithApplesStatus() = runTest {
        replies = { answer(400, JSONObject().put("statusCode", "400").toString()) }
        val e = failure { fetchOnce() } as OpenFinderError.Rejected
        assertEquals(400, e.http)
        assertEquals(400L, e.ec)

        replies = { answer(200, v2(emptyList(), status = "500")) }
        val e2 = failure { fetchOnce() } as OpenFinderError.Rejected
        assertEquals(200, e2.http)
        assertEquals(500L, e2.ec)

        replies = { answer(200, "{}") }
        assertTrue(failure { fetchOnce() } is OpenFinderError.Rejected)

        replies = { answer(403, "forbidden") }
        assertEquals(403, (failure { fetchOnce() } as OpenFinderError.Rejected).http)
    }

    @Test fun http433IsRejectedWithItsCode() = runTest {
        replies = { answer(433, "") }
        assertEquals(433, (failure { fetchOnce() } as OpenFinderError.Rejected).http)
    }

    @Test fun aShorterWindowNarrowsBothTheRequestDatesAndTheIndexWalk() = runTest {
        val s = f.json("fetch.json").getJSONArray("rolling").objects().first { it.getString("name") == "chunked_nothing_found" }
        val now = OffsetDateTime.parse(s.getString("now")).toInstant()
        replies = { answer(body = v2(emptyList())) }
        val accessory = AccessoryKeys.fromJson(s.getJSONObject("accessory"))   // aligned at index 1800 on Sep 20
        val client = ReportClient(
            account, endpoint = server.url("/findmyservice/v2/fetch").toString(), clock = Clock.fixed(now, ZoneOffset.UTC),
            pause = { pauses += it }, window = java.time.Duration.ofDays(2),
        )
        val r = client.fetchLocationHistory(accessory)
        // 2 days back from index 3720 (the alignment is older than the window, so the walk stops at the alignment index, as Python
        // does for any window): the walk is the same as for 7 days here, but the dates in the body must follow the window.
        val body = JSONObject(seen[0].body!!.utf8()).getJSONArray("fetch").getJSONObject(0)
        assertEquals((now.epochSecond - 2 * 86400) * 1000, body.getLong("startDate"))
        assertEquals(now.epochSecond * 1000, body.getLong("endDate"))
        assertTrue(r.requests >= 1)
        try { ReportClient(account, window = java.time.Duration.ZERO); fail() } catch (_: IllegalArgumentException) {}
    }

    @Test fun severalAccessoriesAreQueriedOneAfterTheOther() = runTest {
        val s = simpleScenario()
        val steps = s.getJSONArray("replies").getJSONArray(0).objects()
        replies = { answer(body = v2(steps.map { it.getString("hashed") to it.getString("payload") })) }
        val a = AccessoryKeys.fromJson(s.getJSONObject("accessory"))
        val b = AccessoryKeys.fromJson(s.getJSONObject("accessory"))   // same secrets, so equal: one map entry
        val c = f.json("fetch.json").getJSONArray("rolling").objects().first { it.getString("name") == "chunked_only_latest" }
            .let { AccessoryKeys.fromJson(it.getJSONObject("accessory")) }
        val client = clientAt(OffsetDateTime.parse(s.getString("now")).toInstant())
        val latest = client.fetchLocations(listOf(a, c))
        assertEquals(2, latest.size)
        assertTrue(latest.getValue(a) != null)
        assertNull(latest.getValue(c))
        assertEquals(setOf(a, b), setOf(a))
    }

    @Test fun malformedAnswersAreBackendFailures() = runTest {
        replies = { answer(200, "<html>not json</html>") }
        assertTrue(failure { fetchOnce() } is OpenFinderError.Backend)
        replies = { answer(200, """{"acsnLocations":{"statusCode":"200","locationPayload":[{"locationInfo":["AAAA"]}]}}""") }   // no id
        assertTrue(failure { fetchOnce() } is OpenFinderError.Backend)
        replies = { answer(200, """{"acsnLocations":{"statusCode":"200","locationPayload":[{"id":"@@@","locationInfo":["AAAA"]}]}}""") }
        assertTrue(failure { fetchOnce() } is OpenFinderError.Backend)
        replies = { answer(200, """{"acsnLocations":{"statusCode":"200"}}""") }                                               // no payload: no reports
        assertTrue(fetchOnce().isEmpty())
    }

    @Test fun transportFailureIsANetworkError() = runTest {
        val client = clientAt(Instant.parse("2026-10-03T12:00:00Z"))
        server.close()
        assertTrue(failure { client.fetchRaw(listOf(KeyIds(listOf("AAAA")))) } is OpenFinderError.Network)
    }

    @Test fun rawFetchExposesPayloadsWithoutDecrypting() = runTest {
        val id = Base64.getEncoder().encodeToString(ByteArray(32) { 7 })
        val payload = ByteArray(88) { it.toByte() }
        replies = { answer(body = v2(listOf(id to Base64.getEncoder().encodeToString(payload), id to Base64.getEncoder().encodeToString(payload)))) }
        val raw = fetchOnce()
        assertEquals(2, raw.size)
        assertEquals(id, Base64.getEncoder().encodeToString(raw[0].hashedAdvKey))
        assertTrue(payload.contentEquals(raw[1].payload))
    }
}
