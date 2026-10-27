package com.sacca.openfinder.apple.cloudkit

import com.google.protobuf.ByteString
import com.sacca.openfinder.apple.Cooldown
import com.sacca.openfinder.apple.CooldownStore
import com.sacca.openfinder.apple.cloudkit.CkFixtures.hex
import com.sacca.openfinder.apple.proto.cloudkit.Error
import com.sacca.openfinder.apple.proto.cloudkit.Identifier
import com.sacca.openfinder.apple.proto.cloudkit.ProtectionInfo
import com.sacca.openfinder.apple.proto.cloudkit.RecordChange
import com.sacca.openfinder.apple.proto.cloudkit.RecordZoneIdentifier
import com.sacca.openfinder.apple.proto.cloudkit.RequestOperation
import com.sacca.openfinder.apple.proto.cloudkit.ResponseOperation
import com.sacca.openfinder.apple.proto.cloudkit.Result
import com.sacca.openfinder.apple.proto.cloudkit.RetrieveChangesResponse
import com.sacca.openfinder.apple.proto.cloudkit.Zone
import com.sacca.openfinder.apple.proto.cloudkit.ZoneRetrieveResponse
import com.sacca.openfinder.apple.proto.cloudkit.ZoneSummary
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import kotlinx.coroutines.flow.toList
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import okhttp3.Credentials
import okio.Buffer
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.zip.GZIPInputStream

private class MemoryCooldown(override var last429EpochSeconds: Long? = null) : CooldownStore

/**
 * The client against a MockWebServer: the exact requests (URL, headers, Basic auth, gzip + length-delimited body) compared
 * byte for byte with what the real Python client sent for the same calls (fixtures/cloudkit/client.json, recorded from
 * `AsyncCloudKitClient` with its random ids replaced by counters), and how replies, errors, throttling and malformed protobuf
 * are handled. Reply shapes marked [observed] come from fixtures/cloudkit/observed.json.
 */
class CloudKitClientTest {
    private lateinit var server: MockWebServer
    private val seen = mutableListOf<RecordedRequest>()
    private val routes = mutableMapOf<String, MutableList<MockResponse>>()
    private val account = CkFakeAccount()
    private val fixture = CkFixtures.json("client.json")
    private val observed = CkFixtures.json("observed.json")

    @Before fun start() {
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                seen += request
                val queue = routes[request.url.encodedPath] ?: return MockResponse.Builder().code(404).build()
                return if (queue.size > 1) queue.removeAt(0) else queue.first()
            }
        }
        server.start()
    }

    @After fun stop() = server.close()

    private fun url(path: String) = server.url(path).toString().trimEnd('/')

    private fun appInit(base: JSONObject = JSONObject(fixture.getJSONObject("flow").getJSONObject("replies").getString("app_init"))): String {
        base.put("cloudKitDatabaseGatewayUrl", url("/ckdatabase"))
        base.put("cloudKitCodeGatewayUrl", url("/ckcoderouter"))
        return base.toString()
    }

    private fun route(path: String, vararg replies: MockResponse) { routes[path] = replies.toMutableList() }
    private fun bytes(code: Int, body: ByteArray, gzip: Boolean = false): MockResponse {
        val b = MockResponse.Builder().code(code).body(Buffer().write(if (gzip) CloudKitClient.gzip(body) else body))
        if (gzip) b.addHeader("Content-Encoding", "gzip")
        return b.build()
    }
    private fun json(code: Int, body: String) = MockResponse.Builder().code(code).body(body).build()
    private fun frame(vararg ops: ResponseOperation): ByteArray = ops.fold(ByteArray(0)) { acc, op ->
        val p = op.toByteArray(); acc + Delimited.encodeVarint(p.size.toLong()) + p
    }
    private fun ok(op: ResponseOperation.Builder): ResponseOperation = op.setResult(Result.newBuilder().setCode(ResultCode.SUCCESS)).build()

    private fun client(ids: CloudKitIds = CountingIds(), cooldown: Cooldown? = null, account: CkFakeAccount = this.account) = CloudKitClient(
        account, CloudKitConstants.SEARCHPARTY_CONTAINER, CloudKitConstants.SEARCHPARTY_BUNDLE, "Production", "PRIVATE", "FindMy.py",
        null, url("/setup/setup/ck/v1/ckAppInit"), cooldown, ids,
    )

    private fun gunzip(b: ByteArray) = GZIPInputStream(ByteArrayInputStream(b)).use { it.readBytes() }

    private fun standardRoutes() {
        val replies = fixture.getJSONObject("flow").getJSONObject("replies")
        route("/setup/setup/ck/v1/ckAppInit", json(200, appInit()))
        route("/ckdatabase/api/client/zone/retrieve", bytes(200, hex(replies.getString("zone"))))
        route("/ckdatabase/api/client/record/sync", bytes(200, hex(replies.getString("page1"))), bytes(200, hex(replies.getString("page2"))))
        route("/ckcoderouter/api/client/code/invoke", bytes(200, hex(replies.getString("invoke"))))
    }

    /** One recorded request against the Python's: path and query, every header the Python sent, nothing else, the body. */
    private fun assertSameAsPython(python: JSONObject, actual: RecordedRequest, basicAuth: Boolean) {
        val pythonUrl = python.getString("url")
        val pathAndQuery = pythonUrl.substringAfter("icloud.com")
        assertEquals("POST", actual.method)
        assertEquals(pathAndQuery, actual.url.encodedPath + (actual.url.encodedQuery?.let { "?$it" } ?: ""))
        val headers = python.getJSONObject("headers")
        for (name in headers.keys()) assertEquals(name, headers.getString(name), actual.headers[name])
        val allowed = headers.keys().asSequence().map { it.lowercase() }.toSet() + setOf("host", "content-length", "connection") +
            (if (basicAuth) setOf("authorization") else emptySet())
        val extra = actual.headers.names().map { it.lowercase() }.toSet() - allowed
        assertEquals("headers the Python does not send", emptySet<String>(), extra)
        if (basicAuth) {
            val auth = python.getJSONArray("auth")
            assertEquals(Credentials.basic(auth.getString(0), auth.getString(1)), actual.headers["Authorization"])
        }
        val body = actual.body?.toByteArray() ?: ByteArray(0)
        assertEquals(python.getString("body"), if (body.isEmpty()) "" else hex(gunzip(body)))
    }

    @Test fun theWholeReadFlowSendsExactlyWhatPythonSends() = ckTest {
        standardRoutes()
        val client = client()
        val flow = fixture.getJSONObject("flow")
        val zones = client.zoneRetrieve()
        val changes = client.iterRecords(CloudKitConstants.BEACON_STORE_ZONE).toList()
        val result = client.functionInvoke("Cuttlefish", "fetchViableBottles", hex("0a0170"))

        assertEquals(flow.getJSONArray("zones").strings(), zones.map { hex(it.toByteArray()) })
        assertEquals(flow.getJSONArray("changes").strings(), changes.map { hex(it.toByteArray()) })
        assertEquals(flow.getString("invoke_result"), hex(result))
        val requests = flow.getJSONArray("requests").objects()
        assertEquals(requests.size, seen.size)
        requests.zip(seen).forEachIndexed { i, (p, a) -> assertSameAsPython(p, a, basicAuth = i == 0) }

        val info = client.containerInfo!!
        val container = flow.getJSONObject("container")
        assertEquals(container.getString("user_id"), info.userId)
        assertEquals(container.getString("partition"), info.partition)
        assertEquals(11, info.raw.size)
    }

    @Test fun aResumedPageCarriesTheTokenAndPageSize() = ckTest {
        val resumed = fixture.getJSONObject("resumed")
        route("/setup/setup/ck/v1/ckAppInit", json(200, appInit()))
        route("/ckdatabase/api/client/record/sync", bytes(200, hex(fixture.getJSONObject("flow").getJSONObject("replies").getString("page2")).let {
            // page2 holds two frames; the Python's single-page reply held only the first
            Delimited.decode(it).first().let { op -> frame(op) }
        }))
        val page = client(CountingIds(100, 100)).recordSync(CloudKitConstants.BEACON_STORE_ZONE, "resume".toByteArray(), 50)
        assertEquals(resumed.getString("token"), hex(page.continuationToken!!))
        assertEquals(resumed.getInt("status"), page.status)
        assertEquals(resumed.getBoolean("complete"), page.complete)
        val requests = resumed.getJSONArray("requests").objects()
        requests.zip(seen).forEachIndexed { i, (p, a) -> assertSameAsPython(p, a, basicAuth = i == 0) }
    }

    @Test fun clientIdentityAndFramingMatchPython() {
        val identities = fixture.getJSONObject("identities")
        for (s in identities.keys()) {
            val e = identities.getJSONObject(s)
            val got = ClientIdentity.parse(s)
            assertEquals(s, e.getString("model"), got.model)
            assertEquals(s, e.getString("os_version"), got.osVersion)
            assertEquals(s, e.getString("prefix"), got.prefix)
            assertEquals(s, e.getString("cloudkit_client_info"), got.cloudKitClientInfo)
        }
        val varints = fixture.getJSONObject("varints")
        for (n in varints.keys()) assertEquals(n, varints.getString(n), hex(Delimited.encodeVarint(java.math.BigInteger(n).toLong())))
        val delimited = fixture.getJSONObject("delimited")
        for (name in delimited.keys()) {
            val c = delimited.getJSONObject(name)
            var count = -1
            val error = try { count = Delimited.decode(hex(c.getString("data"))).size; null } catch (e: OpenFinderException) { e.error }
            if (c.isNull("error")) assertEquals(name, c.getInt("count"), count) else assertTrue(name, error is OpenFinderError.Backend)
        }
    }

    @Test fun resultsAreCheckedAsPythonChecksThem() {
        val results = fixture.getJSONObject("results")
        for (name in results.keys()) {
            val c = results.getJSONObject(name)
            val result = Result.parseFrom(hex(c.getString("result")))
            val error = try { CloudKitClient.checkResult(result); null } catch (e: OpenFinderException) { e.error }
            if (!c.getBoolean("raises")) { assertNull(name, error); continue }
            val message = c.getString("message")
            when (val e = error!!) {
                is OpenFinderError.Throttled -> { assertEquals(6, c.getInt("client_error")); assertTrue(e.message.startsWith(message)); assertTrue(e.message.contains("30 s")) }
                is OpenFinderError.Rejected -> {
                    assertEquals(name, message, e.message)
                    val code = if (!c.isNull("client_error")) c.getInt("client_error") else if (!c.isNull("server_error")) c.getInt("server_error") else c.getInt("code")
                    assertEquals(name, code.toLong(), e.ec)
                }
                else -> error("unexpected $e for $name")
            }
        }
    }

    // ------------------------------------------------------------------------------------------------- errors

    @Test fun anExpiredTokenOnOpeningIsAnAuthenticationError() = ckTest {
        route("/setup/setup/ck/v1/ckAppInit", json(401, ""))
        expectError(OpenFinderError.Authentication::class.java) { client().zoneRetrieve() }
    }

    @Test fun anExpiredTokenOnAnOperationIsAnAuthenticationError() = ckTest {
        route("/setup/setup/ck/v1/ckAppInit", json(200, appInit()))
        route("/ckdatabase/api/client/zone/retrieve", json(401, ""))
        expectError(OpenFinderError.Authentication::class.java) { client().zoneRetrieve() }
    }

    @Test fun throttlingStartsTheCooldownAndNothingMoreIsSent() = ckTest {
        val store = MemoryCooldown()
        val cooldown = Cooldown(store, Clock.fixed(Instant.parse("2026-10-18T10:00:00Z"), ZoneOffset.UTC))
        route("/setup/setup/ck/v1/ckAppInit", json(200, appInit()))
        route("/ckdatabase/api/client/zone/retrieve", MockResponse.Builder().code(429).addHeader("Retry-After", "120").build())
        val client = client(cooldown = cooldown)
        val error = expectError(OpenFinderError.Throttled::class.java) { client.zoneRetrieve() }
        assertTrue(error.message.contains("120 s"))
        assertTrue(store.last429EpochSeconds != null)
        val before = seen.size
        expectError(OpenFinderError.Throttled::class.java) { client.zoneRetrieve() }
        assertEquals(before, seen.size)
    }

    @Test fun throttlingWhileOpeningIsThrottlingToo() = ckTest {
        route("/setup/setup/ck/v1/ckAppInit", json(429, ""))
        expectError(OpenFinderError.Throttled::class.java) { client().zoneRetrieve() }
    }

    @Test fun anEmpty500MeansTheRequestDidNotParse() = ckTest {   // [observed] shape, observed.json "empty_500"
        assertTrue(observed.getJSONObject("empty_500").getString("_source").contains("[observed]"))
        route("/setup/setup/ck/v1/ckAppInit", json(200, appInit()))
        route("/ckdatabase/api/client/zone/retrieve", json(500, ""))
        val error = expectError(OpenFinderError.Backend::class.java) { client().zoneRetrieve() }
        assertTrue(error.message.contains("did not parse"))
    }

    @Test fun otherHttpFailuresAreTyped() = ckTest {
        route("/setup/setup/ck/v1/ckAppInit", json(200, appInit()))
        route("/ckdatabase/api/client/zone/retrieve", json(503, "busy"), json(403, "no"))
        val client = client()
        expectError(OpenFinderError.Backend::class.java) { client.zoneRetrieve() }
        val rejected = expectError(OpenFinderError.Rejected::class.java) { client.zoneRetrieve() } as OpenFinderError.Rejected
        assertEquals(403, rejected.http)
        route("/setup/setup/ck/v1/ckAppInit", json(404, ""))
        val opening = expectError(OpenFinderError.Rejected::class.java) { client().openContainer() } as OpenFinderError.Rejected
        assertEquals(404, opening.http)
    }

    @Test fun malformedProtobufIsABackendError() = ckTest {
        route("/setup/setup/ck/v1/ckAppInit", json(200, appInit()))
        val client = client()
        for (body in listOf(hex("02ffff"), hex("05616263"), hex("80"), ByteArray(0))) {
            route("/ckdatabase/api/client/zone/retrieve", bytes(200, body))
            expectError(OpenFinderError.Backend::class.java) { client.zoneRetrieve() }
        }
    }

    @Test fun aRejectedOperationCarriesApplesCodeAndText() = ckTest {   // [observed] shape, observed.json "bad_syntax"
        val bad = observed.getJSONObject("bad_syntax")
        val failure = ResponseOperation.newBuilder().setResult(Result.newBuilder().setCode(bad.getInt("result_code")).setError(
            Error.newBuilder().setClientError(Error.ClientError.newBuilder().setCode(bad.getInt("client_error")))
                .setErrorDescription(bad.getString("error_description")).setErrorKey(bad.getString("error_key")),
        )).build()
        route("/setup/setup/ck/v1/ckAppInit", json(200, appInit()))
        route("/ckdatabase/api/client/zone/retrieve", bytes(200, frame(failure)))
        val error = expectError(OpenFinderError.Rejected::class.java) { client().zoneRetrieve() } as OpenFinderError.Rejected
        assertEquals(4L, error.ec)
        assertEquals("CloudKit operation failed (BAD_SYNTAX): deviceHardwareID is required field [ABCD1234]", error.message)
    }

    @Test fun aThrottledResultAndABadTokenResultAreTyped() = ckTest {   // [observed] wrapper shape, observed.json "error_wrappers"
        val throttled = ResponseOperation.newBuilder().setResult(Result.parseFrom(hex(observed.getJSONObject("error_wrappers").getString("result_hex")))).build()
        val badToken = ResponseOperation.newBuilder().setResult(Result.newBuilder().setCode(3).setError(
            Error.newBuilder().setClientError(Error.ClientError.newBuilder().setCode(ClientErrorCode.BAD_AUTH_TOKEN)))).build()
        route("/setup/setup/ck/v1/ckAppInit", json(200, appInit()))
        route("/ckdatabase/api/client/zone/retrieve", bytes(200, frame(throttled)), bytes(200, frame(badToken)))
        val client = client()
        assertTrue(expectError(OpenFinderError.Throttled::class.java) { client.zoneRetrieve() }.message.contains("30 s"))
        expectError(OpenFinderError.Authentication::class.java) { client.zoneRetrieve() }
    }

    @Test fun aPartialResultIsNotAFailure() = ckTest {
        val partial = ResponseOperation.newBuilder().setResult(Result.newBuilder().setCode(ResultCode.PARTIAL))
            .setZoneRetrieveResponse(ZoneRetrieveResponse.newBuilder().addZoneSummary(ZoneSummary.getDefaultInstance())).build()
        route("/setup/setup/ck/v1/ckAppInit", json(200, appInit()))
        route("/ckdatabase/api/client/zone/retrieve", bytes(200, frame(partial)))
        assertEquals(1, client().zoneRetrieve().size)
    }

    @Test fun aGzippedReplyIsDecompressed() = ckTest {
        route("/setup/setup/ck/v1/ckAppInit", json(200, appInit()))
        route("/ckdatabase/api/client/zone/retrieve", bytes(200, hex(fixture.getJSONObject("flow").getJSONObject("replies").getString("zone")), gzip = true))
        assertEquals(2, client().zoneRetrieve().size)
    }

    @Test fun openingWithoutAUserIdOrJsonFails() = ckTest {
        route("/setup/setup/ck/v1/ckAppInit", json(200, "{}"), json(200, "not json"), json(200, ""))
        repeat(3) { expectError(OpenFinderError.Backend::class.java) { client().openContainer() } }
    }

    @Test fun missingTokensSendNothing() = ckTest {
        route("/setup/setup/ck/v1/ckAppInit", json(200, appInit()))
        for (missing in listOf("mmeAuthToken", "cloudKitToken")) {
            val acct = CkFakeAccount(tokens = mapOf("mmeAuthToken" to "m", "cloudKitToken" to "c") - missing)
            expectError(OpenFinderError.Authentication::class.java) { client(account = acct).zoneRetrieve() }
        }
        assertEquals(0, seen.size)
    }

    @Test fun aDeviceIdThatIsNotAUuidSendsNothing() = ckTest {
        standardRoutes()
        expectError(OpenFinderError.Backend::class.java) { client(account = CkFakeAccount(deviceUuid = "00006000-0123456789ABCDEF")).zoneRetrieve() }
        assertEquals(0, seen.size)
    }

    @Test fun anUnreachableServerIsANetworkError() = ckTest {
        val client = client()
        server.close()
        expectError(OpenFinderError.Network::class.java) { client.openContainer() }
    }

    @Test fun theContainerIsOpenedOnceUnlessRefreshed() = ckTest {
        standardRoutes()
        val client = client()
        client.zoneRetrieve()
        client.zoneRetrieve()
        assertEquals(1, seen.count { it.url.encodedPath.endsWith("ckAppInit") })
        client.openContainer(refresh = true)
        assertEquals(2, seen.count { it.url.encodedPath.endsWith("ckAppInit") })
    }

    @Test fun noCodeGatewayMeansNoFunctionInvoke() = ckTest {
        val init = JSONObject(appInit()).apply { remove("cloudKitCodeGatewayUrl") }
        route("/setup/setup/ck/v1/ckAppInit", json(200, init.toString()))
        expectError(OpenFinderError.Backend::class.java) { client().functionInvoke("Cuttlefish", "x", ByteArray(0)) }
    }

    private fun page(token: String?, status: Int?, vararg etags: String): ResponseOperation {
        val r = RetrieveChangesResponse.newBuilder()
        etags.forEach { r.addRecordChange(RecordChange.newBuilder().setEtag(it)) }
        token?.let { r.setSyncContinuationToken(ByteString.copyFromUtf8(it)) }
        status?.let { r.setStatus(it) }
        return ok(ResponseOperation.newBuilder().setRetrieveChangesResponse(r))
    }

    @Test fun pagingStopsWhenItCannotContinueOrAtTheBackstop() = ckTest {
        route("/setup/setup/ck/v1/ckAppInit", json(200, appInit()))
        route("/ckdatabase/api/client/record/sync", bytes(200, frame(page("t1", 1, "a"))), bytes(200, frame(page("t1", 1, "b"))))
        assertEquals(listOf("a", "b"), client().iterRecords("BeaconStore").toList().map { it.etag })   // same token twice: stop
        seen.clear()
        route("/ckdatabase/api/client/record/sync", bytes(200, frame(page(null, null, "c"))))
        assertEquals(listOf("c"), client().iterRecords("BeaconStore").toList().map { it.etag })   // no token: stop
        seen.clear()
        var n = 0
        routes["/ckdatabase/api/client/record/sync"] = MutableList(10) { bytes(200, frame(page("t${n++}", 1, "x"))) }
        assertEquals(3, client().iterRecords("BeaconStore", maxPages = 3).toList().size)
        assertEquals(3, seen.count { it.url.encodedPath.endsWith("record/sync") })
        // The page's token is sent back verbatim on the next request.
        val second = RequestOperation.parseFrom(gunzip(seen.filter { it.url.encodedPath.endsWith("record/sync") }[1].body!!.toByteArray()).let { it.copyOfRange(2, it.size) })
        assertEquals("t0", second.retrieveChangesRequest.syncContinuationToken.toStringUtf8())
    }

    @Test fun aFinalPageThatStillCarriesChangesLosesNone() = ckTest {   // [observed], observed.json "record_sync"
        val o = observed.getJSONObject("record_sync")
        val last = RetrieveChangesResponse.newBuilder()
        repeat(o.getInt("changes_on_final_page")) { last.addRecordChange(RecordChange.newBuilder().setEtag("e$it")) }
        last.setStatus(o.getInt("first_page_status")).setSyncContinuationToken(ByteString.copyFromUtf8("t"))
            .setClientChangeToken(ByteString.copyFromUtf8("c")).addChangedShares(ByteString.EMPTY)
            .setZoneAttributesChanges(ByteString.copyFrom(ByteArray(o.getInt("zone_attributes_changes_length"))))
        route("/setup/setup/ck/v1/ckAppInit", json(200, appInit()))
        route("/ckdatabase/api/client/record/sync", bytes(200, frame(ok(ResponseOperation.newBuilder().setRetrieveChangesResponse(last)))))
        assertEquals(3, client().iterRecords("BeaconStore").toList().size)
        assertEquals(1, seen.count { it.url.encodedPath.endsWith("record/sync") })
    }

    @Test fun theObservedContainerAndZoneShapesAreRead() = ckTest {
        val init = JSONObject(observed.getJSONObject("ck_app_init").getJSONObject("body").toString())
        route("/setup/setup/ck/v1/ckAppInit", json(200, appInit(init)))
        val zones = ZoneRetrieveResponse.newBuilder()
        for (z in observed.getJSONObject("zone_retrieve").getJSONArray("zones").objects()) {
            val zone = Zone.newBuilder().setZoneIdentifier(RecordZoneIdentifier.newBuilder().setValue(Identifier.newBuilder().setName(z.getString("name"))))
            if (z.getBoolean("protection_info")) zone.setProtectionInfo(ProtectionInfo.newBuilder().setProtectionInfo(ByteString.copyFrom(byteArrayOf(0x61, 0))))
            val summary = ZoneSummary.newBuilder().setTargetZone(zone)
            if (!z.isNull("device_count")) summary.setDeviceCount(z.getLong("device_count"))
            if (z.getBoolean("continuation_token")) summary.setCurrentServerContinuationToken(ByteString.copyFromUtf8("tok"))
            zones.addZoneSummary(summary)
        }
        route("/ckdatabase/api/client/zone/retrieve", bytes(200, frame(ok(ResponseOperation.newBuilder().setZoneRetrieveResponse(zones)))))
        val client = client()
        val got = client.zoneRetrieve()
        val beaconStore = got.first { it.targetZone.zoneIdentifier.value.name == "BeaconStore" }
        assertTrue(beaconStore.targetZone.hasProtectionInfo())
        assertFalse(beaconStore.targetZone.hasRecordProtectionInfo())
        assertEquals(10, beaconStore.deviceCount)
        assertEquals(observed.getJSONObject("ck_app_init").getString("partition"), client.containerInfo!!.partition)
        assertEquals(11, client.containerInfo!!.raw.size)
    }

    @Test fun theRequestEnvelopeDeclaresTheOperationTwiceAndKeepsTheZeros() = ckTest {
        standardRoutes()
        client().zoneRetrieve()
        val body = gunzip(seen.last().body!!.toByteArray())
        val request = RequestOperation.parseFrom(body.copyOfRange(2, body.size))   // a 2-byte varint length prefix
        assertEquals(OperationType.ZONE_RETRIEVE, request.request.type)
        assertTrue(request.hasZoneRetrieveRequest())
        assertTrue(request.header.hasUnknown29() && request.header.hasUnknown34())
        assertEquals(1, request.header.unknown35)
        assertFalse(request.header.hasUserToken())
        assertEquals("0F1E2D3C4B5A69788796A5B4C3D2E1F0", request.header.deviceHardwareId)
        assertArrayEquals(Delimited.encodeVarint((body.size - 2).toLong()), body.copyOfRange(0, 2))
    }
}
