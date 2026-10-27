package com.sacca.openfinder.apple

import com.sacca.openfinder.anisette.MachineMint
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import kotlinx.coroutines.runBlocking
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64

/** JUnit 4 needs void test methods, so every test body goes through this Unit-returning wrapper. */
private fun runTest(block: suspend () -> Unit) = runBlocking { block() }

private class MemoryCooldownStore(override var last429EpochSeconds: Long? = null) : CooldownStore

class GsaClientTest {
    private lateinit var server: MockWebServer
    private val device = GsaDevice("00006000-AAAAAAAAAAAAAAAA", "<Mac> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>", "ABCDEF0123456789ABCDEF0123456789", "C02ABCDEFGHJ")
    private val b64 = Base64.getEncoder()
    private var startReply: () -> MockResponse = { plist(mapOf("Response" to mapOf("spim" to b64.encodeToString("SPIM".toByteArray())))) }
    private var finishReply: () -> MockResponse = {
        plist(mapOf("Response" to mapOf("ptm" to b64.encodeToString("PTM".toByteArray()), "tk" to b64.encodeToString("TK".toByteArray()), "X-Apple-I-MD-RINFO" to "1234")))
    }
    private var syncReply: () -> MockResponse = { plist(mapOf("Response" to mapOf("Status" to mapOf("ec" to 0L, "em" to "")))) }
    private val seen = mutableListOf<RecordedRequest>()
    private var bag: (String) -> Map<String, Any?> = { base ->
        mapOf("urls" to mapOf("midStartProvisioning" to "$base/start", "midFinishProvisioning" to "$base/finish", "midSyncMachine" to "$base/sync"))
    }

    private fun plist(root: Map<String, Any?>, code: Int = 200) = MockResponse.Builder().code(code).body(okio.Buffer().write(Plist.toXml(root))).build()

    @Before fun start() {
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                seen += request
                val base = server.url("/").toString().trimEnd('/')
                return when (request.url.encodedPath) {
                    "/lookup" -> plist(bag(base))
                    "/start" -> startReply()
                    "/finish" -> finishReply()
                    "/sync" -> syncReply()
                    else -> MockResponse.Builder().code(404).build()
                }
            }
        }
        server.start()
    }

    @After fun stop() = server.close()

    private fun client(cooldown: Cooldown? = null, clock: Clock = Clock.fixed(Instant.parse("2026-10-17T12:34:56Z"), ZoneOffset.UTC)) =
        GsaClient(device, cooldown, lookupUrl = server.url("/lookup").toString(), clock = clock)

    private inline fun <reified E : OpenFinderError> assertFails(block: () -> Unit): E {
        try { block() } catch (e: OpenFinderException) { assertTrue("expected ${E::class.simpleName} but got ${e.error}", e.error is E); return e.error as E }
        fail("expected a OpenFinderException"); throw IllegalStateException()
    }

    @Test fun fullProvisioningExchange() = runTest {
        val c = client()
        assertEquals(3, c.loadUrlBag().size)
        assertArrayEquals("SPIM".toByteArray(), c.startProvisioning())
        val r = c.finishProvisioning("CPIM".toByteArray())
        assertArrayEquals("PTM".toByteArray(), r.ptm); assertArrayEquals("TK".toByteArray(), r.tk); assertEquals(1234L, r.routing)
    }

    @Test fun routingMayComeAsANumberToo() = runTest {
        finishReply = { plist(mapOf("Response" to mapOf("ptm" to b64.encodeToString(byteArrayOf(1)), "tk" to b64.encodeToString(byteArrayOf(2)), "X-Apple-I-MD-RINFO" to 99L))) }
        val c = client(); c.loadUrlBag(); c.startProvisioning()
        assertEquals(99L, c.finishProvisioning(byteArrayOf(7)).routing)
    }

    @Test fun lookupIsAGetWithDeviceHeadersAndNoClientTime() = runTest {
        client().loadUrlBag()
        val r = seen.single()
        assertEquals("GET", r.method)
        assertEquals(GsaClient.USER_AGENT, r.headers["User-Agent"])
        assertEquals(device.uniqueDeviceId, r.headers["X-Mme-Device-Id"]); assertEquals(device.clientInfo, r.headers["X-MMe-Client-Info"])
        assertEquals(device.localUserUuid, r.headers["X-Apple-I-MD-LU"]); assertEquals("Setup", r.headers["X-Apple-Client-App-Name"])
        assertEquals("C02ABCDEFGHJ", r.headers["X-Apple-I-SRL-NO"])
        assertNull(r.headers["X-Apple-I-Client-Time"])
    }

    @Test fun postsAreUrlencodedPlistsWithClientTimeAndTheRightShape() = runTest {
        val c = client(); c.loadUrlBag(); c.startProvisioning(); c.finishProvisioning("CPIM".toByteArray())
        val start = seen.first { it.url.encodedPath == "/start" }
        val finish = seen.first { it.url.encodedPath == "/finish" }
        for (r in listOf(start, finish)) {
            assertEquals("POST", r.method)
            assertEquals("application/x-www-form-urlencoded", r.headers["Content-Type"]?.substringBefore(';'))
            assertEquals("2026-10-17T12:34:56Z", r.headers["X-Apple-I-Client-Time"])
        }
        val sent = Plist.parseDict(finish.body!!.toByteArray())
        assertEquals(emptyMap<String, Any?>(), sent["Header"])
        assertEquals(mapOf("cpim" to b64.encodeToString("CPIM".toByteArray())), sent["Request"])
        assertEquals(emptyMap<String, Any?>(), (Plist.parseDict(start.body!!.toByteArray()))["Request"])
    }

    @Test fun serialHeaderIsOmittedWhenThereIsNone() = runTest {
        GsaClient(device.copy(serial = null), null, lookupUrl = server.url("/lookup").toString()).loadUrlBag()
        assertNull(seen.single().headers["X-Apple-I-SRL-NO"])
    }

    @Test fun syncMachineSendsSrmAndMidAndRouting() = runTest {
        val c = client(); c.loadUrlBag()
        val reply = c.syncMachine("MID", "SRM", 55L)
        assertNotNull(reply["Status"])
        val sent = Plist.parseDict(seen.last().body!!.toByteArray())["Request"] as Map<*, *>
        assertEquals("SRM", sent["srm"]); assertEquals("MID", sent["X-Apple-I-MD-M"]); assertEquals(55L, sent["X-Apple-I-MD-RINFO"])
        c.syncMachine("MID", "SRM", null)
        assertFalse((Plist.parseDict(seen.last().body!!.toByteArray())["Request"] as Map<*, *>).containsKey("X-Apple-I-MD-RINFO"))
    }

    @Test fun http429IsAThrottleStartsTheCooldownAndBlocksFurtherRequests() = runTest {
        val store = MemoryCooldownStore()
        val cooldown = Cooldown(store, Clock.fixed(Instant.parse("2026-10-17T12:00:00Z"), ZoneOffset.UTC))
        startReply = { MockResponse.Builder().code(429).build() }
        val c = client(cooldown); c.loadUrlBag()
        assertFails<OpenFinderError.Throttled> { runBlocking { c.startProvisioning() } }
        assertNotNull(store.last429EpochSeconds)
        val before = server.requestCount
        assertFails<OpenFinderError.Throttled> { runBlocking { c.startProvisioning() } }
        assertEquals("nothing may be sent during the cooldown", before, server.requestCount)
    }

    @Test fun anotherHttpErrorCarriesApplesOwnStatus() = runTest {
        finishReply = { plist(mapOf("Response" to mapOf("Status" to mapOf("ec" to -29002L, "em" to "already provisioned"))), code = 433) }
        val c = client(); c.loadUrlBag(); c.startProvisioning()
        val e = assertFails<OpenFinderError.Rejected> { runBlocking { c.finishProvisioning(byteArrayOf(1)) } }
        assertEquals(433, e.http); assertEquals(-29002L, e.ec); assertTrue(e.message.contains("-29002"))
    }

    @Test fun anHttpErrorWithAnUnreadableBodyIsStillATypedRejection() = runTest {
        startReply = { MockResponse.Builder().code(500).body("oops").build() }
        val c = client(); c.loadUrlBag()
        val e = assertFails<OpenFinderError.Rejected> { runBlocking { c.startProvisioning() } }
        assertEquals(500, e.http); assertNull(e.ec)
    }

    @Test fun unparseableAndIncompleteRepliesAreBackendErrors() = runTest {
        val c = client(); c.loadUrlBag()
        startReply = { MockResponse.Builder().body("not a plist").build() }
        assertFails<OpenFinderError.Backend> { runBlocking { c.startProvisioning() } }
        startReply = { plist(mapOf("Response" to mapOf("nothing" to "here"))) }
        assertFails<OpenFinderError.Backend> { runBlocking { c.startProvisioning() } }
        finishReply = { plist(mapOf("Response" to mapOf("ptm" to b64.encodeToString(byteArrayOf(1))))) }   // no tk
        assertFails<OpenFinderError.Backend> { runBlocking { c.finishProvisioning(byteArrayOf(1)) } }
    }

    @Test fun missingUrlsAreBackendErrors() = runTest {
        bag = { mapOf("urls" to emptyMap<String, Any?>()) }
        assertFails<OpenFinderError.Backend> { runBlocking { client().loadUrlBag() } }
        bag = { base -> mapOf("urls" to mapOf("midSyncMachine" to "$base/sync")) }
        val c = client(); c.loadUrlBag()
        assertFails<OpenFinderError.Backend> { runBlocking { c.startProvisioning() } }
    }

    @Test fun anUnreachableServerIsANetworkError() = runTest {
        val c = GsaClient(device, null, lookupUrl = "http://127.0.0.1:1/lookup")
        assertFails<OpenFinderError.Network> { runBlocking { c.loadUrlBag() } }
    }
}

class CooldownTest {
    private val t0 = Instant.parse("2026-10-17T12:00:00Z")
    @Test fun noMemoryMeansNoWait() { assertEquals(0, Cooldown(MemoryCooldownStore()).remainingSeconds()) }
    @Test fun fortyFiveMinutesFromTheLast429() {
        val store = MemoryCooldownStore()
        Cooldown(store, Clock.fixed(t0, ZoneOffset.UTC)).noteThrottled()
        assertEquals(45 * 60L, Cooldown(store, Clock.fixed(t0, ZoneOffset.UTC)).remainingSeconds())
        assertEquals(15 * 60L, Cooldown(store, Clock.fixed(t0.plusSeconds(30 * 60), ZoneOffset.UTC)).remainingSeconds())
        assertEquals(0, Cooldown(store, Clock.fixed(t0.plusSeconds(46 * 60), ZoneOffset.UTC)).remainingSeconds())
    }
}

class PlistAndMintTest {
    @Test fun plistRoundTripKeepsTypes() {
        val original = mapOf("s" to "text", "i" to 42L, "d" to 1.5, "b" to true, "data" to byteArrayOf(1, 2, 3), "list" to listOf("a", 7L), "nested" to mapOf("k" to "v"))
        val back = Plist.parseDict(Plist.toXml(original))
        assertEquals("text", back["s"]); assertEquals(42L, back["i"]); assertEquals(1.5, back["d"]); assertEquals(true, back["b"])
        assertArrayEquals(byteArrayOf(1, 2, 3), back["data"] as ByteArray); assertEquals(listOf("a", 7L), back["list"]); assertEquals(mapOf("k" to "v"), back["nested"])
    }
    @Test fun plistRejectsGarbageAndNonDictionaryRoots() {
        try { Plist.parseDict("garbage".toByteArray()); fail() } catch (_: IllegalArgumentException) {}
        try { Plist.parseDict("<?xml version=\"1.0\"?><plist version=\"1.0\"><string>x</string></plist>".toByteArray()); fail() } catch (_: IllegalArgumentException) {}
    }
    @Test fun mintedIdentityHasTheShapesAppleUses() {
        repeat(20) {
            val id = MachineMint.identity()
            assertTrue(id.deviceId, Regex("00006000-[0-9A-F]{16}").matches(id.deviceId))
            assertTrue(Regex("[0-9A-F]{32}").matches(id.localUserUuid))
            assertTrue(id.serial, Regex("C02[0-9A-HJ-NP-Z]{9}").matches(id.serial!!))
            assertEquals(16, MachineMint.hostUuid().size)
        }
        assertFalse(MachineMint.identity().deviceId == MachineMint.identity().deviceId)
    }
}
