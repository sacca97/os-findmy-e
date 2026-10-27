package com.sacca.openfinder.apple.login

import com.sacca.openfinder.apple.CooldownStore
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertTrue
import java.util.Base64

/** JUnit 4 needs void test methods, so every test body goes through this Unit-returning wrapper. */
internal fun runTest(block: suspend () -> Unit) = runBlocking { block() }

internal fun fixture(name: String): String =
    requireNotNull(LoginTestSupport::class.java.getResource("/fixtures/login/$name")) { "missing fixture $name" }.readText()

internal fun unhex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
internal fun hex(b: ByteArray): String = GsaCrypto.hex(b)
internal fun b64d(s: String): ByteArray = Base64.getDecoder().decode(s)

internal object LoginTestSupport {
    /** The oracle's JSON form of plist values (bytes as {"$data": base64}) back to what [com.sacca.openfinder.apple.Plist] yields. */
    fun fromOracle(v: Any?): Any? = when (v) {
        is JSONObject -> if (v.length() == 1 && v.has("\$data")) b64d(v.getString("\$data")) else v.keys().asSequence().associateWith { fromOracle(v.get(it)) }
        is JSONArray -> (0 until v.length()).map { fromOracle(v.get(it)) }
        is Int -> v.toLong()
        JSONObject.NULL -> null
        else -> v
    }

    fun stringMap(o: JSONObject): Map<String, String> = o.keys().asSequence().associateWith { o.getString(it) }

    /** Structural equality of plist values with strict types: data is bytes, numbers are Long, booleans are Boolean. */
    fun assertPlistEquals(path: String, expected: Any?, actual: Any?) {
        when (expected) {
            is Map<*, *> -> {
                assertTrue("$path: expected a dictionary, got ${actual?.javaClass?.simpleName}", actual is Map<*, *>)
                actual as Map<*, *>
                assertTrue("$path: keys differ: ${expected.keys} vs ${actual.keys}", expected.keys == actual.keys)
                expected.forEach { (k, v) -> assertPlistEquals("$path.$k", v, actual[k]) }
            }
            is List<*> -> {
                assertTrue("$path: expected an array", actual is List<*> && actual.size == expected.size)
                expected.forEachIndexed { i, v -> assertPlistEquals("$path[$i]", v, (actual as List<*>)[i]) }
            }
            is ByteArray -> assertTrue("$path: expected data ${hex(expected)}, got $actual", actual is ByteArray && actual.contentEquals(expected))
            else -> {
                assertTrue("$path: expected ${expected?.javaClass?.simpleName} $expected, got ${actual?.javaClass?.simpleName} $actual", expected == actual)
            }
        }
    }
}

/** The oracle's fixed device: the identity and pair `tools/oracle/login_vectors.py` logs in as. */
internal object OracleDevice {
    private val h = JSONObject(fixture("headers.json"))
    val uid: String = h.getString("uid")
    val devid: String = h.getString("devid")
    val serial: String = h.getString("serial")
    val identity = DeviceIdentity.MAC_13_1
    val hostUuid = ByteArray(16) { (0xA0 + it).toByte() }
    val device = LoginDevice(uid, devid, serial, identity, LoginDevice.cloudKitUuid(devid, hostUuid))
    val anisette: Map<String, String> = LoginTestSupport.stringMap(h.getJSONObject("get_headers"))
}

/** An [AnisetteSource] that hands out a fixed header set and records resync requests. */
internal class FakeAnisette(
    private val headers: Map<String, String> = OracleDevice.anisette,
    var onResync: (String) -> Unit = {},
) : AnisetteSource {
    val sims = mutableListOf<String>()
    var headerCalls = 0
    override suspend fun headers(): Map<String, String> { headerCalls++; return headers }
    override suspend fun resync(sim: String) { sims += sim; onResync(sim) }
}

internal class MemoryBlobs : SecretBlobs {
    val map = mutableMapOf<String, ByteArray>()
    override fun read(name: String) = map[name]?.copyOf()
    override fun write(name: String, plaintext: ByteArray) { map[name] = plaintext.copyOf() }
    override fun delete(name: String) { map.remove(name) }
}

internal class MemoryCooldownStore(override var last429EpochSeconds: Long? = null) : CooldownStore
