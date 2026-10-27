package com.sacca.openfinder.apple.reports

import com.sacca.openfinder.apple.AppleAccountContext
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import org.json.JSONArray
import org.json.JSONObject
import java.util.Base64

/** JUnit 4 needs void test methods, so every test body goes through this Unit-returning wrapper. */
internal fun runTest(block: suspend () -> Unit) = runBlocking { block() }

internal object ReportFixtures {
    fun json(name: String): JSONObject {
        val stream = ReportFixtures::class.java.getResourceAsStream("/fixtures/reports/$name") ?: error("missing fixture $name")
        return JSONObject(stream.bufferedReader().use { it.readText() })
    }

    fun hex(s: String) = AccessoryKeys.unhex(s)
    fun b64(s: String): ByteArray = Base64.getDecoder().decode(s)
}

internal fun JSONArray.objects(): List<JSONObject> = (0 until length()).map { getJSONObject(it) }

/** A signed-in account with synthetic credentials: nothing here is real. */
internal class FakeAccount(
    var token: String? = "SYNTHETIC-SEARCH-PARTY-TOKEN",
    override val dsid: String = "1234567890",
    var headers: Map<String, String> = mapOf(
        "X-Apple-I-MD" to "otp-synthetic", "X-Apple-I-MD-M" to "machine-synthetic", "X-Apple-I-MD-LU" to "bHU=",
        "X-Apple-I-MD-RINFO" to "17106176", "X-Mme-Device-Id" to "DEVICE-UUID", "X-Apple-I-SRL-NO" to "C02SYNTHETIC",
        "X-Apple-I-Client-Time" to "2026-10-17T12:00:00Z", "X-Apple-Locale" to "en_US", "X-Apple-I-TimeZone" to "UTC", "loc" to "en_US",
    ),
) : AppleAccountContext {
    override val accountName = "synthetic@example.invalid"
    override val adsid = "000000-00-synthetic"
    override val deviceUuid = "DEVICE-UUID"
    override val clientInfo = "<Mac> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
    override val serial: String? = "C02SYNTHETIC"
    override val timeoutSeconds = 10L
    override val localUserUuid = "LU"
    var anisetteCalls = 0
    override suspend fun serviceToken(name: String): String? = if (name == "searchPartyToken") token else null
    override suspend fun anisetteHeaders(): Map<String, String> { anisetteCalls++; return headers }
    override suspend fun requestPet(): String? = null
    override val http: OkHttpClient = OkHttpClient()
}
