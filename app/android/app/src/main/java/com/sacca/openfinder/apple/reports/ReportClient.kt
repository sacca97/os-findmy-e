package com.sacca.openfinder.apple.reports

import com.sacca.openfinder.apple.AppleAccountContext
import com.sacca.openfinder.apple.Cooldown
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import com.sacca.openfinder.domain.LocationReport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.Credentials
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException
import java.time.Clock
import java.time.Duration
import java.util.Base64
import java.util.concurrent.TimeUnit

/** One `fetch` entry of the request: hashed advertisement keys (base64) queried as primary and as secondary ids. */
data class KeyIds(val primary: List<String>, val secondary: List<String> = emptyList())

/**
 * What a fetch produced. [reports] are valid, deduplicated, oldest first. The counters say what was dropped, so a caller can
 * tell "no reports" from "reports we could not use": [undecryptable] (MAC/size/key failures, which Python turns into an
 * exception for the whole fetch), [invalid] (rejected by `LocationReport.isValid`), [unknownKey] (Apple answered for an id
 * we did not ask about). [emptyResponse] is true when Apple kept answering HTTP 200 with an empty body (FindMy.py#185).
 * [alignmentMoved] means the accessory's alignment changed and it should be saved again.
 */
data class ReportFetchResult(
    val reports: List<LocationReport>,
    val requests: Int,
    val undecryptable: Int = 0,
    val invalid: Int = 0,
    val unknownKey: Int = 0,
    val emptyResponse: Boolean = false,
    val alignmentMoved: Boolean = false,
)

/**
 * Fetches and decrypts location reports from Apple's search-party service (port of `AsyncAppleAccount.fetch_raw_reports`
 * and `LocationReportsFetcher`: `fetch_location`, `fetch_location_history`).
 *
 * The request is the library's own: `POST https://gateway.icloud.com/findmyservice/v2/fetch` with HTTP Basic auth
 * `dsid:searchPartyToken`, the account's Anisette headers (fresh for every attempt), and a JSON body with a window (7 days by default, as Python) in
 * milliseconds. A rolling accessory is queried in one `fetch` entry with its primary and secondary hashed keys for every index
 * it could be at, walking back from the newest index, at most 290 ids of each kind per request; the first request that yields
 * reports ends the walk (the library's `only_latest`).
 *
 * Errors: HTTP 401 -> [OpenFinderError.Authentication] (after one [reauthenticate] attempt if given, as Python re-logs in), 429 ->
 * [OpenFinderError.Throttled] (and the optional shared [cooldown] starts), other 4xx or an answer whose `statusCode` is not 200 ->
 * [OpenFinderError.Rejected], 5xx or a 200 whose body is not JSON -> [OpenFinderError.Backend], transport errors -> [OpenFinderError.Network], no
 * `searchPartyToken` -> [OpenFinderError.Authentication].
 *
 * Differences from the Python, all deliberate: a report that cannot be decrypted is counted and skipped instead of aborting
 * the fetch; ids Apple answers with that we did not ask for are skipped instead of raising `KeyError`; reports are filtered by
 * `LocationReport.isValid` (no (0, 0) fix, no timestamp more than 5 minutes ahead); when an empty reply cuts a non-`onlyLatest`
 * walk short the reports gathered so far are returned (Python returns an empty list).
 */
class ReportClient(
    private val account: AppleAccountContext,
    private val endpoint: String = ENDPOINT,
    private val clock: Clock = Clock.systemUTC(),
    private val cooldown: Cooldown? = null,
    private val reauthenticate: (suspend () -> Boolean)? = null,
    private val pause: suspend (millis: Long) -> Unit = { delay(it) },
    /** How far back reports are requested. Python always uses 7 days; longer windows were never tried against Apple. */
    private val window: Duration = WINDOW,
) {
    init { require(!window.isNegative && !window.isZero) { "window must be positive" } }

    private val http: OkHttpClient by lazy { account.http.newBuilder().callTimeout(account.timeoutSeconds, TimeUnit.SECONDS).build() }

    /** Newest report of [accessory] in the window (7 days), or null (`fetch_location`). Updates the accessory's alignment. */
    suspend fun fetchLocation(accessory: AccessoryKeys): LocationReport? = fetchLocationHistory(accessory).reports.lastOrNull()

    /**
     * Reports of a rolling accessory (`fetch_location_history`): the newest batch when [onlyLatest] (the Python's behaviour),
     * everything in the window otherwise. Moves [accessory]'s alignment forward; save it afterwards.
     */
    suspend fun fetchLocationHistory(accessory: AccessoryKeys, onlyLatest: Boolean = true): ReportFetchResult {
        val now = clock.instant()
        val start = now.minus(window)
        val accessoryId = accessory.id

        val keyToIndices = HashMap<String, MutableSet<Int>>()
        val idToKey = HashMap<String, KeyPair>()
        val curPrimary = LinkedHashSet<String>()
        val curSecondary = LinkedHashSet<String>()
        val found = LinkedHashMap<DecryptedReport, KeyPairType>()
        var curIndex = accessory.maxIndex(now)
        var requests = 0
        var undecryptable = 0
        var unknownKey = 0
        var moved = false
        var empty = false

        /** Fetch the current keys and add what decrypts to [found]. Returns false when Apple answered with nothing at all. */
        suspend fun flush(): Boolean {
            val raw = try {
                requests++
                fetchRawOrEmpty(listOf(KeyIds(curPrimary.toList(), curSecondary.toList())))
            } catch (e: EmptyReportsResponse) {
                empty = true
                return false
            }
            for (report in raw) {
                val id = Base64.getEncoder().encodeToString(report.hashedAdvKey)
                val key = idToKey[id]
                if (key == null) { unknownKey++; continue }
                val decrypted = try { report.decrypt(key) } catch (e: ReportDecryptException) { undecryptable++; continue }
                found.putIfAbsent(decrypted, key.keyType)
                // The LOWEST index this key could be at: a secondary key spans up to 192 primary indices, and aligning to the
                // top of that window runs ahead of the truth, which `updateAlignment` never takes back (see the Python).
                val lowest = keyToIndices.getValue(id).min()
                if (accessory.updateAlignment(decrypted.timestamp, lowest)) moved = true
            }
            curPrimary.clear()
            curSecondary.clear()
            return true
        }

        fun result(): ReportFetchResult {
            val sorted = found.entries.sortedBy { it.key.timestamp }
            val valid = sorted.filter { toDomain(it.key, accessoryId, it.value).isValid(now) }
            return ReportFetchResult(
                reports = valid.map { toDomain(it.key, accessoryId, it.value) },
                requests = requests, undecryptable = undecryptable, invalid = sorted.size - valid.size,
                unknownKey = unknownKey, emptyResponse = empty, alignmentMoved = moved,
            )
        }

        // `get_min_index` is re-read each turn: a fetch may have moved the alignment.
        while (curIndex >= accessory.minIndex(start)) {
            val batch = accessory.keysAt(curIndex)
            val newPrimary = batch.filter { it.keyType == KeyPairType.PRIMARY }.mapTo(LinkedHashSet()) { it.hashedAdvKeyB64 }
            val newSecondary = batch.filter { it.keyType != KeyPairType.PRIMARY }.mapTo(LinkedHashSet()) { it.hashedAdvKeyB64 }

            // 290 ids of a kind is the most Apple accepts in one request.
            if ((curPrimary + newPrimary).size > MAX_IDS || (curSecondary + newSecondary).size > MAX_IDS) {
                if (!flush()) return result()
                if (onlyLatest && found.isNotEmpty()) return result()
            }

            for (key in batch) {
                keyToIndices.getOrPut(key.hashedAdvKeyB64) { HashSet() }.add(curIndex)
                idToKey[key.hashedAdvKeyB64] = key
            }
            curPrimary += newPrimary
            curSecondary += newSecondary
            curIndex--
        }

        if (curPrimary.isNotEmpty() || curSecondary.isNotEmpty()) flush()
        return result()
    }

    /** `fetch_location_history` for several accessories: each is queried in turn (rolling keys cannot share a request). */
    suspend fun fetchLocationHistories(accessories: List<AccessoryKeys>, onlyLatest: Boolean = true): Map<AccessoryKeys, ReportFetchResult> {
        val out = LinkedHashMap<AccessoryKeys, ReportFetchResult>()
        for (a in accessories) out[a] = fetchLocationHistory(a, onlyLatest)
        return out
    }

    /** `fetch_location` for several accessories: the newest report of each, or null. */
    suspend fun fetchLocations(accessories: List<AccessoryKeys>): Map<AccessoryKeys, LocationReport?> =
        fetchLocationHistories(accessories).mapValues { it.value.reports.lastOrNull() }

    /**
     * Reports of keys that do not roll (`_fetch_key_reports`): one `fetch` entry per key, all as primary ids, decrypted
     * with the key itself. Python does not chunk this call and neither do we: pass what fits in one request.
     */
    suspend fun fetchKeyHistory(keys: List<KeyPair>, idOf: (KeyPair) -> String = { it.name ?: it.advKeyB64 }): Map<KeyPair, ReportFetchResult> {
        if (keys.isEmpty()) return emptyMap()
        val now = clock.instant()
        val raw = try { fetchRawOrEmpty(keys.map { KeyIds(listOf(it.hashedAdvKeyB64)) }) } catch (e: EmptyReportsResponse) { emptyList() }
        return keys.associateWith { key ->
            var undecryptable = 0
            val found = LinkedHashSet<DecryptedReport>()
            for (r in raw.filter { it.canDecrypt(key) }) {
                try { found += r.decrypt(key) } catch (e: ReportDecryptException) { undecryptable++ }
            }
            val sorted = found.sortedBy { it.timestamp }
            val mapped = sorted.map { toDomain(it, idOf(key), key.keyType) }.filter { it.isValid(now) }
            ReportFetchResult(mapped, requests = 1, undecryptable = undecryptable, invalid = sorted.size - mapped.size)
        }
    }

    /**
     * The raw call (`fetch_raw_reports`): one request (plus empty-body retries) for [devices], undecrypted.
     * @throws OpenFinderException with [OpenFinderError.ReportsUnavailable] when Apple keeps answering 200 with an empty body.
     */
    suspend fun fetchRaw(devices: List<KeyIds>): List<EncryptedReport> = try {
        fetchRawOrEmpty(devices)
    } catch (e: EmptyReportsResponse) {
        throw OpenFinderException(OpenFinderError.ReportsUnavailable("Apple answered the report request with an empty body repeatedly (FindMy.py#185)."))
    }

    private suspend fun fetchRawOrEmpty(devices: List<KeyIds>): List<EncryptedReport> {
        val now = clock.instant()
        val startMs = now.minus(window).epochSecond * 1000
        val endMs = now.epochSecond * 1000
        val body = JSONObject().apply {
            put("clientContext", JSONObject().put("clientBundleIdentifier", "com.apple.icloud.searchpartyuseragent").put("policy", "foregroundClient"))
            put("fetch", JSONArray().also { arr ->
                for (d in devices) arr.put(JSONObject().apply {
                    put("ownedDeviceIds", JSONArray())
                    put("keyType", 1)
                    put("startDate", startMs)
                    put("startDateSecondary", startMs)
                    put("endDate", endMs)
                    put("primaryIds", JSONArray(d.primary))
                    put("secondaryIds", JSONArray(d.secondary))
                })
            })
        }.toString()

        var answer = post(body)
        if (answer.code == 401 && reauthenticate?.invoke() == true) answer = post(body)
        return parse(answer)
    }

    private class Answer(val code: Int, val body: String, val retryAfter: String?)

    /** One POST, retrying an empty 200 up to 5 times at 2, 4, ... 10 s (FindMy.py#185). */
    private suspend fun post(body: String): Answer {
        val token = account.serviceToken("searchPartyToken")
            ?: throw OpenFinderException(OpenFinderError.Authentication("No search-party token: sign in again."))
        val authorization = Credentials.basic(account.dsid, token)
        var retry = 1
        while (true) {
            val answer = send(body, authorization)
            if (answer.code != 200 || answer.body.isNotBlank()) return answer
            if (retry > MAX_EMPTY_RETRIES) throw EmptyReportsResponse()
            pause(2000L * retry)
            retry++
        }
    }

    private suspend fun send(body: String, authorization: String): Answer {
        cooldown?.guard()
        val headers = account.anisetteHeaders()
        return withContext(Dispatchers.IO) {
            val builder = Request.Builder().url(endpoint).header("Authorization", authorization)
            for ((k, v) in headers) builder.header(k, v)
            builder.post(body.toByteArray(Charsets.UTF_8).toRequestBody(JSON))   // bytes: a String body would append "; charset=utf-8"
            try {
                http.newCall(builder.build()).execute().use { Answer(it.code, it.body.string(), it.header("Retry-After")) }
            } catch (e: IOException) {
                throw OpenFinderException(OpenFinderError.Network("Could not reach Apple's report service: ${e.javaClass.simpleName}"))
            }
        }
    }

    private fun parse(answer: Answer): List<EncryptedReport> {
        val json = try { JSONObject(answer.body) } catch (e: JSONException) { null }
        when {
            answer.code == 401 -> throw OpenFinderException(OpenFinderError.Authentication("Apple rejected the report request: sign in again."))
            answer.code == 429 -> {
                cooldown?.noteThrottled()
                val wait = answer.retryAfter?.trim()?.toLongOrNull()?.let { " Apple asked for $it s." } ?: ""
                throw OpenFinderException(OpenFinderError.Throttled("Apple is rate-limiting report requests (HTTP 429).$wait"))
            }
            answer.code >= 500 -> throw OpenFinderException(OpenFinderError.Backend("Apple's report service is unavailable (HTTP ${answer.code})."))
        }
        if (json == null && answer.code < 400) throw OpenFinderException(OpenFinderError.Backend("Apple's report answer is not JSON."))
        val block = json?.optJSONObject("acsnLocations")
        val status = block?.opt("statusCode")?.toString()
        if (answer.code >= 400 || status != "200") {
            val apple = json?.opt("statusCode")?.toString() ?: status
            throw OpenFinderException(OpenFinderError.Rejected(answer.code, apple?.toLongOrNull(), "Apple's report service refused the request (HTTP ${answer.code}, status ${apple ?: "none"})."))
        }
        try {
            val out = ArrayList<EncryptedReport>()
            val payloads = block.optJSONArray("locationPayload") ?: JSONArray()
            for (i in 0 until payloads.length()) {
                val entry = payloads.getJSONObject(i)
                val id = Base64.getDecoder().decode(entry.getString("id"))
                val infos = entry.optJSONArray("locationInfo") ?: continue
                for (j in 0 until infos.length()) out += EncryptedReport(Base64.getDecoder().decode(infos.getString(j)), id)
            }
            return out
        } catch (e: JSONException) {
            throw OpenFinderException(OpenFinderError.Backend("Unexpected shape of the report answer."))
        } catch (e: IllegalArgumentException) {
            throw OpenFinderException(OpenFinderError.Backend("Unexpected encoding in the report answer."))
        }
    }

    /** Apple answered 200 with an empty body 6 times in a row. */
    private class EmptyReportsResponse : Exception()

    companion object {
        const val ENDPOINT = "https://gateway.icloud.com/findmyservice/v2/fetch"
        const val MAX_IDS = 290
        private const val MAX_EMPTY_RETRIES = 5
        private val WINDOW: Duration = Duration.ofDays(7)
        private val JSON = "application/json".toMediaType()

        /** The app's report for one decrypted one; Apple's raw fields stay in `metadata`. */
        internal fun toDomain(r: DecryptedReport, accessoryId: String, keyType: KeyPairType) = LocationReport(
            accessoryId = accessoryId,
            latitude = r.latitude,
            longitude = r.longitude,
            observedAt = r.timestamp,
            horizontalAccuracyMeters = r.horizontalAccuracy.toDouble(),
            metadata = mapOf(
                "source" to "apple-findmy",
                "confidence" to r.confidence.toString(),
                "status" to r.status.toString(),
                "keyType" to keyType.name.lowercase(),
            ),
        )
    }
}
