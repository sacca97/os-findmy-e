package com.sacca.openfinder.apple.cloudkit

import com.sacca.openfinder.apple.AppleAccountContext
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec

/** JUnit 4 needs void test methods, so every suspending test body goes through this Unit-returning wrapper. */
internal fun ckTest(block: suspend () -> Unit) = runBlocking { block() }

internal object CkFixtures {
    fun json(name: String): JSONObject {
        val stream = CkFixtures::class.java.getResourceAsStream("/fixtures/cloudkit/$name") ?: error("missing fixture $name")
        return JSONObject(stream.bufferedReader().use { it.readText() })
    }

    fun hex(s: String): ByteArray {
        require(s.length % 2 == 0)
        return ByteArray(s.length / 2) { ((Character.digit(s[2 * it], 16) shl 4) or Character.digit(s[2 * it + 1], 16)).toByte() }
    }

    fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    /** `{"curve": "secp256r1", "d": "<hex>"}`, as the oracle writes keys. */
    fun key(o: JSONObject): PcsKey {
        val curve = PcsCurve.entries.first { it.curveName == o.getString("curve") }
        return PcsKey(curve, BigInteger(1, hex(o.getString("d"))))
    }

    fun keys(a: JSONArray): List<PcsKey> = a.objects().map { key(it) }

    fun keyJson(k: PcsKey): String = "${k.curve.curveName}:${hex(k.scalarBytes())}"
    fun keyJson(o: JSONObject): String = "${o.getString("curve")}:${o.getString("d")}"

    /** A JCA key, as the keychain piece hands them over. */
    fun jca(k: PcsKey): ECPrivateKey {
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec(k.curve.curveName)) }
        val spec = params.getParameterSpec(ECParameterSpec::class.java)
        return KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, k.scalarBytes()), spec)) as ECPrivateKey
    }
}

internal fun JSONArray.objects(): List<JSONObject> = (0 until length()).map { getJSONObject(it) }
internal fun JSONArray.strings(): List<String> = (0 until length()).map { getString(it) }
internal fun JSONObject.optStringOrNull(key: String): String? = if (isNull(key)) null else getString(key)

/** The name the Python used for an exception, mapped to ours. */
internal fun pythonErrorOf(e: Throwable): String = when (e) {
    is MissingKeyException -> "MissingKeyError"
    is BeaconExportException -> "BeaconExportError"
    is PcsException -> "PCSError"
    is DerException -> "DerError"
    is KeyBlobException -> "KeyBlobError"
    is ServiceKeyException -> "ServiceKeyError"
    else -> e.javaClass.simpleName
}

internal inline fun errorOf(block: () -> Unit): String? = try {
    block(); null
} catch (e: Exception) {
    pythonErrorOf(e)
}

internal suspend fun expectError(kind: Class<out OpenFinderError>, block: suspend () -> Unit): OpenFinderError {
    try {
        block()
    } catch (e: OpenFinderException) {
        assertTrue("expected ${kind.simpleName}, got ${e.error}", kind.isInstance(e.error))
        return e.error
    }
    fail("expected ${kind.simpleName}")
    error("unreachable")
}

/** A signed-in account with synthetic credentials, matching the oracle's `_FakeAccount`. Nothing here is real. */
internal class CkFakeAccount(
    override val http: OkHttpClient = OkHttpClient(),
    var tokens: Map<String, String> = mapOf("mmeAuthToken" to "SYNTHETIC-MME-TOKEN", "cloudKitToken" to "SYNTHETIC-CK-TOKEN"),
    override val deviceUuid: String = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
    override val serial: String? = "C02SYNTHETIC",
) : AppleAccountContext {
    override val accountName = "synthetic@example.invalid"
    override val dsid = "1234567890"
    override val adsid = "000000-00-synthetic"
    override val clientInfo = "<MacBookPro18,3> <Mac OS X;13.4.1;22F82> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>"
    override val timeoutSeconds = 10L
    override val localUserUuid = "LU"
    val anisette = linkedMapOf("X-Apple-I-MD" to "otp-synthetic", "X-Apple-I-MD-M" to "machine-synthetic", "X-Mme-Device-Id" to "DEVICE-SYNTHETIC")
    var anisetteCalls = 0
    override suspend fun serviceToken(name: String): String? = tokens[name]
    override suspend fun anisetteHeaders(): Map<String, String> { anisetteCalls++; return anisette }
    override suspend fun requestPet(): String? = null
}

/** The oracle's patched id generators: operation ids count up as `%032X`, request uuids as `...-8000-%012X`. */
internal class CountingIds(var op: Int = 0, var uuid: Int = 0) : CloudKitIds {
    override fun operationId(): String { op++; return "%032X".format(op) }
    override fun requestUuid(): String { uuid++; return "00000000-0000-4000-8000-%012X".format(uuid) }
}
