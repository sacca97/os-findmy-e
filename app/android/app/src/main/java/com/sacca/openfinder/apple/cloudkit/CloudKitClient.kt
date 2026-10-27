package com.sacca.openfinder.apple.cloudkit

import com.google.protobuf.ByteString
import com.google.protobuf.InvalidProtocolBufferException
import com.sacca.openfinder.apple.AppleAccountContext
import com.sacca.openfinder.apple.Cooldown
import com.sacca.openfinder.apple.proto.cloudkit.ContainerEnvironment
import com.sacca.openfinder.apple.proto.cloudkit.Database
import com.sacca.openfinder.apple.proto.cloudkit.Identifier
import com.sacca.openfinder.apple.proto.cloudkit.IsolationLevel
import com.sacca.openfinder.apple.proto.cloudkit.Operation
import com.sacca.openfinder.apple.proto.cloudkit.RecordChange
import com.sacca.openfinder.apple.proto.cloudkit.RecordZoneIdentifier
import com.sacca.openfinder.apple.proto.cloudkit.RequestOperation
import com.sacca.openfinder.apple.proto.cloudkit.ResponseOperation
import com.sacca.openfinder.apple.proto.cloudkit.Result
import com.sacca.openfinder.apple.proto.cloudkit.RetrieveChangesRequest
import com.sacca.openfinder.apple.proto.cloudkit.ZoneRetrieveRequest
import com.sacca.openfinder.apple.proto.cloudkit.ZoneSummary
import com.sacca.openfinder.apple.proto.cloudkit.FunctionInvokeRequest
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.Credentials
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONException
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URLEncoder
import java.security.SecureRandom
import java.util.Locale
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

/** The device this client claims to be, parsed from the account's `X-Mme-Client-Info` (`_ClientIdentity`). */
internal class ClientIdentity(val model: String, val osVersion: String, val prefix: String) {
    /** The client-info string CloudKit requests carry: the device groups, then CloudKit's own daemon as the bundle. */
    val cloudKitClientInfo: String get() = "$prefix<$CLIENT_INFO_BUNDLE>"

    companion object {
        const val CLIENT_INFO_BUNDLE = "com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)"

        /** `<MODEL> <OS;VERSION;BUILD> <BUNDLE>`; falls back to empty values rather than failing. */
        fun parse(clientInfo: String): ClientIdentity {
            val parsed = clientInfo.split("<").filter { '>' in it }.map { it.substringBefore('>') }
            val model = parsed.getOrElse(0) { "" }
            val osVersion = parsed.getOrNull(1)?.split(";")?.getOrNull(1) ?: ""
            val prefix = parsed.take(2).joinToString("") { "<$it> " }
            return ClientIdentity(model, osVersion, prefix)
        }
    }
}

/** The random correlation values CloudKit requests carry; replaceable so tests can reproduce the Python's exact bytes. */
internal interface CloudKitIds {
    /** 32 uppercase hex characters (`_random_operation_id`). */
    fun operationId(): String

    /** An uppercase v4 UUID (`_random_request_uuid`). */
    fun requestUuid(): String

    object Random : CloudKitIds {
        private val rng = SecureRandom()
        override fun operationId(): String = ByteArray(16).also { rng.nextBytes(it) }.joinToString("") { "%02X".format(it) }
        override fun requestUuid(): String = UUID.randomUUID().toString().uppercase(Locale.ROOT)
    }
}

/** Length-delimited protobuf framing (`encode_delimited`/`decode_delimited`). */
internal object Delimited {
    fun encodeVarint(value: Long): ByteArray {
        val out = ByteArrayOutputStream()
        var v = value
        while (true) {
            val b = (v and 0x7f).toInt()
            v = v ushr 7
            out.write(if (v != 0L) b or 0x80 else b)
            if (v == 0L) return out.toByteArray()
        }
    }

    fun encode(message: RequestOperation): ByteArray {
        val payload = message.toByteArray()
        return encodeVarint(payload.size.toLong()) + payload
    }

    /** @throws OpenFinderException [OpenFinderError.Backend] on a truncated frame or a message that does not parse. */
    fun decode(data: ByteArray): List<ResponseOperation> {
        val out = ArrayList<ResponseOperation>()
        var offset = 0
        while (offset < data.size) {
            var length = 0L
            var shift = 0
            while (true) {
                if (offset >= data.size) throw backend("Truncated varint in CloudKit response")
                val b = data[offset].toInt() and 0xff
                offset++
                if (shift < 63) length = length or ((b and 0x7f).toLong() shl shift)
                if (b and 0x80 == 0) break
                shift += 7
            }
            val available = data.size - offset
            if (length > available) throw backend("Truncated CloudKit response: wanted $length bytes, got $available")
            val chunk = data.copyOfRange(offset, offset + length.toInt())
            offset += length.toInt()
            out += try {
                ResponseOperation.parseFrom(chunk)
            } catch (e: InvalidProtocolBufferException) {
                throw backend("CloudKit returned a response operation that does not parse")
            }
        }
        return out
    }

    private fun backend(message: String) = OpenFinderException(OpenFinderError.Backend(message))
}

/**
 * A read-only client for one private CloudKit container (port of `findmy.cloudkit.client.AsyncCloudKitClient`, minus
 * `record_save`). Opening the container (`ckAppInit`, HTTP Basic `dsid:mmeAuthToken` plus `x-cloudkit-authtoken`) learns the
 * CloudKit user id and the service URLs; operations are gzipped, length-delimited `RequestOperation`s sent to the database or
 * code gateway with `x-cloudkit-userid`/`x-cloudkit-authtoken`. All HTTP goes through `account.http`; nothing here persists.
 *
 * Errors, all [OpenFinderException]: missing tokens or HTTP 401 -> [OpenFinderError.Authentication]; HTTP 429 -> [OpenFinderError.Throttled]
 * (and the optional shared [cooldown] starts); other 4xx -> [OpenFinderError.Rejected] with the HTTP code; 5xx, an empty 500
 * ("the request did not parse"), a body that does not decode, no operation in the reply, no user id -> [OpenFinderError.Backend];
 * a CloudKit result that is not SUCCESS/PARTIAL -> [OpenFinderError.Rejected] whose `ec` is Apple's client (else server, else result)
 * code, except client errors THROTTLED -> [OpenFinderError.Throttled] and BAD_AUTH_TOKEN/NEEDS_AUTHENTICATION ->
 * [OpenFinderError.Authentication]; transport failures -> [OpenFinderError.Network].
 *
 * Deliberate differences from the Python (which raises a generic `UnhandledProtocolError` or lets a decoder error escape):
 * the typed mapping above, 429 on `ckAppInit` handled like 429 on an operation, and gzip replies decompressed explicitly
 * (OkHttp does not do it when the caller sets `accept-encoding` itself, as CloudKit's header set requires).
 */
class CloudKitClient internal constructor(
    private val account: AppleAccountContext,
    private val container: String,
    private val bundle: String,
    private val environment: String,
    private val databaseScope: String,
    private val deviceName: String,
    deviceSerial: String?,
    private val appInitUrl: String,
    private val cooldown: Cooldown?,
    private val ids: CloudKitIds,
) : CloudKitApi {

    constructor(
        account: AppleAccountContext,
        container: String = CloudKitConstants.SEARCHPARTY_CONTAINER,
        bundle: String = CloudKitConstants.SEARCHPARTY_BUNDLE,
        cooldown: Cooldown? = null,
    ) : this(account, container, bundle, "Production", "PRIVATE", DEFAULT_DEVICE_NAME, null, CloudKitConstants.CK_APP_INIT_URL, cooldown, CloudKitIds.Random)

    /** Never a different serial from the account's: a second one registers a second device. */
    private val deviceSerial: String? = deviceSerial ?: account.serial
    private val identity = ClientIdentity.parse(account.clientInfo)
    private val http: OkHttpClient by lazy { account.http.newBuilder().callTimeout(account.timeoutSeconds, TimeUnit.SECONDS).build() }
    private val openLock = Mutex()

    @Volatile private var info: CloudKitContainerInfo? = null

    /** What opening the container returned, or null before [openContainer]. */
    val containerInfo: CloudKitContainerInfo? get() = info

    /** The 32-hex-character device identifier CloudKit requires even for a read, from the account's persisted UUID. */
    private val deviceHardwareId: String
        get() {
            val hex = account.deviceUuid.replace("urn:", "").replace("uuid:", "").trim('{', '}').replace("-", "")
            if (hex.length != 32 || !hex.all { Character.digit(it, 16) >= 0 && it.code < 128 }) {
                throw OpenFinderException(OpenFinderError.Backend("This account's CloudKit device id is not a UUID; nothing was sent."))
            }
            return hex.uppercase(Locale.ROOT)
        }

    override fun close() { /* account.http is shared and owned by the account */ }

    private suspend fun token(name: String): String =
        account.serviceToken(name) ?: throw OpenFinderException(OpenFinderError.Authentication("No $name for this account: sign in again."))

    private suspend fun cloudKitHeaders(): LinkedHashMap<String, String> {
        val headers = linkedMapOf(
            "x-cloudkit-containerid" to container,
            "x-cloudkit-bundleid" to bundle,
            "x-cloudkit-databasescope" to databaseScope,
            "x-cloudkit-environment" to environment,
            "x-cloudkit-duetpreclearedmode" to "None",
            "x-apple-operation-group-id" to ids.operationId(),
            "x-apple-operation-id" to ids.operationId(),
            "x-apple-request-uuid" to ids.requestUuid(),
            "x-apple-c2-metric-triggers" to "0",
            "user-agent" to USER_AGENT,
            "x-mme-client-info" to identity.cloudKitClientInfo,
            "accept" to "application/x-protobuf",
            "accept-encoding" to "gzip",
            "accept-language" to "en-US,en;q=0.9",
            "cache-control" to "no-transform",
        )
        headers.putAll(account.anisetteHeaders())
        return headers
    }

    override suspend fun openContainer(refresh: Boolean): CloudKitContainerInfo = openLock.withLock {
        info?.takeIf { !refresh }?.let { return@withLock it }
        val authorization = Credentials.basic(account.dsid, token("mmeAuthToken"))
        val headers = cloudKitHeaders()
        headers["x-cloudkit-authtoken"] = token("cloudKitToken")
        val url = "$appInitUrl?container=${pyQuote(container)}"
        val answer = send(url, headers + ("Authorization" to authorization), ByteArray(0), contentType = null)
        when {
            answer.code == 401 -> throw OpenFinderException(OpenFinderError.Authentication("CloudKit rejected the iCloud token; signing in again obtains a fresh one."))
            answer.code == 429 -> throttled(answer, "opening the CloudKit container")
            answer.code >= 500 -> throw OpenFinderException(OpenFinderError.Backend("Failed to open the CloudKit container: HTTP ${answer.code}"))
            answer.code !in 200..299 -> throw OpenFinderException(OpenFinderError.Rejected(answer.code, null, "Failed to open the CloudKit container: HTTP ${answer.code}"))
        }
        val json = try { JSONObject(String(answer.body, Charsets.UTF_8)) } catch (e: JSONException) {
            throw OpenFinderException(OpenFinderError.Backend("CloudKit's container answer is not JSON"))
        }
        val userId = json.optString("cloudKitUserId").takeIf { json.opt("cloudKitUserId") is String && it.isNotEmpty() }
            ?: throw OpenFinderException(OpenFinderError.Backend("CloudKit did not return a user id; cannot address any private zone"))
        val raw = LinkedHashMap<String, Any?>()
        for (key in json.keys()) raw[key] = json.opt(key).takeIf { it != JSONObject.NULL }
        CloudKitContainerInfo(
            userId = userId,
            databaseUrl = raw["cloudKitDatabaseUrl"] as? String,
            databaseGatewayUrl = raw["cloudKitDatabaseGatewayUrl"] as? String,
            codeGatewayUrl = raw["cloudKitCodeGatewayUrl"] as? String,
            shareGatewayUrl = raw["cloudKitShareGatewayUrl"] as? String,
            raw = raw,
        ).also { info = it }
    }

    private fun header(): RequestOperation.Header {
        val b = RequestOperation.Header.newBuilder()
            .setApplicationContainer(container)
            .setApplicationBundle(bundle)
            .setDeviceIdentifier(Identifier.newBuilder().setName(account.deviceUuid.uppercase(Locale.ROOT)).setType(Identifier.Type.DEVICE))
            .setDeviceSoftwareVersion(identity.osVersion)
            .setDeviceHardwareVersion(identity.model)
            .setDeviceLibraryName(LIBRARY_NAME)
            .setDeviceLibraryVersion(LIBRARY_VERSION)
            .setMmcsProtocolVersion(MMCS_PROTOCOL_VERSION)
            .setApplicationContainerEnvironment(ContainerEnvironment.PRODUCTION)
            .setDeviceAssignedName(deviceName)
            .setDeviceHardwareId(deviceHardwareId)
            .setTargetDatabase(Database.PRIVATE_DB)
            .setIsolationLevel(IsolationLevel.ZONE)
            .setGroup(ids.operationId())
        deviceSerial?.let { b.setDeviceSerial(it) }
        return b.setUnknown29(0).setUnknown34(0).setUnknown35(1).build()
    }

    /** The envelope for one operation: header (with its own group id), then the operation with a fresh uuid. */
    private fun request(operation: Int): RequestOperation.Builder {
        val header = header()
        return RequestOperation.newBuilder()
            .setHeader(header)
            .setRequest(Operation.newBuilder().setOperationUuid(ids.requestUuid()).setType(operation).setSynchronousMode(false).setLast(true))
    }

    private fun zoneIdentifier(zoneName: String): RecordZoneIdentifier {
        val userId = info?.userId ?: throw OpenFinderException(OpenFinderError.Backend("Container has not been opened; call openContainer() first"))
        return RecordZoneIdentifier.newBuilder()
            .setValue(Identifier.newBuilder().setName(zoneName).setType(Identifier.Type.RECORD_ZONE))
            .setOwnerIdentifier(Identifier.newBuilder().setName(userId).setType(Identifier.Type.USER))
            .setEnvironment(ContainerEnvironment.PRODUCTION)
            .build()
    }

    private suspend fun postOperation(path: String, request: RequestOperation, baseUrl: String? = null): ResponseOperation {
        val opened = openContainer()
        val base = baseUrl ?: opened.databaseGatewayUrl
        if (base.isNullOrEmpty()) throw OpenFinderException(OpenFinderError.Backend("Container did not return a database gateway URL"))
        val headers = cloudKitHeaders()
        headers["content-encoding"] = "gzip"
        headers["x-cloudkit-userid"] = opened.userId
        headers["x-cloudkit-authtoken"] = token("cloudKitToken")
        val answer = send(base.trimEnd('/') + path, headers, gzip(Delimited.encode(request)), CloudKitConstants.PROTOBUF_CONTENT_TYPE)
        when {
            answer.code == 401 -> throw OpenFinderException(OpenFinderError.Authentication("CloudKit rejected the token for this operation; sign in again."))
            answer.code == 429 -> throttled(answer, "a CloudKit operation")
            answer.code == 500 && String(answer.body, Charsets.UTF_8).isBlank() -> throw OpenFinderException(OpenFinderError.Backend(
                "CloudKit returned an empty HTTP 500, which means the request did not parse (a protobuf schema mismatch)."))
            answer.code >= 500 -> throw OpenFinderException(OpenFinderError.Backend("CloudKit operation failed: HTTP ${answer.code}"))
            answer.code !in 200..299 -> throw OpenFinderException(OpenFinderError.Rejected(answer.code, null, "CloudKit operation failed: HTTP ${answer.code}"))
        }
        val responses = Delimited.decode(answer.body)
        val response = responses.firstOrNull() ?: throw OpenFinderException(OpenFinderError.Backend("CloudKit returned no operations in its response"))
        checkResult(response.result)
        return response
    }

    override suspend fun zoneRetrieve(): List<ZoneSummary> {
        // As the Python: the request is built before the container is opened (the first operation opens it).
        val request = request(OperationType.ZONE_RETRIEVE).setZoneRetrieveRequest(ZoneRetrieveRequest.getDefaultInstance()).build()
        return postOperation(CloudKitConstants.PATH_ZONE_RETRIEVE, request).zoneRetrieveResponse.zoneSummaryList
    }

    override suspend fun recordSync(zoneName: String, continuationToken: ByteArray?, maxChanges: Int?): RecordSyncPage {
        openContainer()   // naming a private zone needs the user id, before the request is built
        val changes = RetrieveChangesRequest.newBuilder().setZoneIdentifier(zoneIdentifier(zoneName))
        continuationToken?.let { changes.setSyncContinuationToken(ByteString.copyFrom(it)) }
        maxChanges?.let { changes.setMaxChanges(it) }
        val request = request(OperationType.RECORD_RETRIEVE_CHANGES).setRetrieveChangesRequest(changes).build()
        val payload = postOperation(CloudKitConstants.PATH_RECORD_SYNC, request).retrieveChangesResponse
        return RecordSyncPage(
            changes = payload.recordChangeList,
            continuationToken = if (payload.hasSyncContinuationToken()) payload.syncContinuationToken.toByteArray() else null,
            status = if (payload.hasStatus()) payload.status else null,
        )
    }

    override fun iterRecords(zoneName: String, continuationToken: ByteArray?, maxPages: Int): Flow<RecordChange> = flow {
        var token = continuationToken
        for (page in 0 until maxPages) {
            val result = recordSync(zoneName, token)
            for (change in result.changes) emit(change)
            if (result.complete) return@flow
            val next = result.continuationToken
            // No way to continue: Python warns and stops (some records may be missing).
            if (next == null || (token != null && next.contentEquals(token))) return@flow
            token = next
        }
    }

    override suspend fun functionInvoke(service: String, name: String, parameters: ByteArray): ByteArray {
        val opened = openContainer()
        val code = opened.codeGatewayUrl
        if (code.isNullOrEmpty()) throw OpenFinderException(OpenFinderError.Backend("Container did not return a code gateway URL; cannot invoke functions"))
        val request = request(OperationType.FUNCTION_INVOKE).setFunctionInvokeRequest(
            FunctionInvokeRequest.newBuilder().setService(service).setName(name).setParameters(ByteString.copyFrom(parameters)),
        ).build()
        return postOperation(CloudKitConstants.PATH_CODE_INVOKE, request, baseUrl = code).functionInvokeResponse.serializedResult.toByteArray()
    }

    private class Answer(val code: Int, val body: ByteArray, val retryAfter: String?)

    private suspend fun send(url: String, headers: Map<String, String>, body: ByteArray, contentType: String?): Answer {
        cooldown?.guard()
        return withContext(Dispatchers.IO) {
            val builder = Request.Builder().url(url)
            for ((k, v) in headers) builder.header(k, v)
            contentType?.let { builder.header("content-type", it) }
            builder.post(body.toRequestBody(null))   // no media type: the content-type header above is sent verbatim
            try {
                http.newCall(builder.build()).execute().use { response ->
                    val raw = response.body.bytes()
                    val decoded = if (response.header("Content-Encoding")?.trim()?.equals("gzip", ignoreCase = true) == true) gunzip(raw) else raw
                    Answer(response.code, decoded, response.header("Retry-After"))
                }
            } catch (e: IOException) {
                throw OpenFinderException(OpenFinderError.Network("Could not reach CloudKit: ${e.javaClass.simpleName}"))
            }
        }
    }

    private fun throttled(answer: Answer, what: String): Nothing {
        cooldown?.noteThrottled()
        val wait = answer.retryAfter?.trim()?.toLongOrNull()?.let { " Apple asked for $it s." } ?: ""
        throw OpenFinderException(OpenFinderError.Throttled("CloudKit is throttling this account ($what, HTTP 429).$wait"))
    }

    private fun gunzip(data: ByteArray): ByteArray = try {
        GZIPInputStream(ByteArrayInputStream(data)).use { it.readBytes() }
    } catch (e: IOException) {
        throw OpenFinderException(OpenFinderError.Backend("CloudKit's gzip reply does not decompress"))
    }

    companion object {
        private const val LIBRARY_NAME = "com.apple.cloudkit.CloudKitDaemon"
        private const val LIBRARY_VERSION = "1970"
        private const val USER_AGENT = "CloudKit/1970 (19H384)"
        private const val MMCS_PROTOCOL_VERSION = "5.0"
        private const val DEFAULT_DEVICE_NAME = "FindMy.py"

        internal fun gzip(data: ByteArray): ByteArray = ByteArrayOutputStream().also { out -> GZIPOutputStream(out).use { it.write(data) } }.toByteArray()

        /** Python's `urllib.parse.quote` with its default safe set (`/` and the unreserved characters). */
        internal fun pyQuote(s: String): String =
            URLEncoder.encode(s, "UTF-8").replace("+", "%20").replace("%2F", "/").replace("*", "%2A").replace("%7E", "~")

        /**
         * Raise unless a result worked; PARTIAL passes (a batch can half-succeed) (`_check_result`). The message is the Python's:
         * `CloudKit operation failed (NAME): description [errorKey]`.
         */
        internal fun checkResult(result: Result) {
            if (result.code == ResultCode.SUCCESS || result.code == ResultCode.PARTIAL) return
            val error = result.error
            val clientCode = if (error.hasClientError()) error.clientError.code else null
            val name = clientCode?.let { " (${ClientErrorCode.name(it) ?: "client error $it"})" } ?: ""
            var message = "CloudKit operation failed$name: ${error.errorDescription.ifEmpty { "no description given" }}"
            if (error.errorKey.isNotEmpty()) message = "$message [${error.errorKey}]"
            when (clientCode) {
                ClientErrorCode.THROTTLED -> {
                    val wait = if (error.hasRetryAfterSeconds()) " Apple asked for ${error.retryAfterSeconds} s." else ""
                    throw OpenFinderException(OpenFinderError.Throttled("$message$wait"))
                }
                ClientErrorCode.BAD_AUTH_TOKEN, ClientErrorCode.NEEDS_AUTHENTICATION -> throw OpenFinderException(OpenFinderError.Authentication(message))
            }
            val code = clientCode ?: (if (error.hasServerError()) error.serverError.code else null) ?: result.code
            throw OpenFinderException(OpenFinderError.Rejected(200, code.toLong(), message))
        }
    }
}
