package com.sacca.openfinder.data

import com.sacca.openfinder.anisette.CoreAdiImageSource
import com.sacca.openfinder.anisette.MachineFile
import com.sacca.openfinder.anisette.MachineMint
import com.sacca.openfinder.anisette.MachineStorage
import com.sacca.openfinder.apple.Cooldown
import com.sacca.openfinder.domain.Accessory
import com.sacca.openfinder.domain.AccessoryType
import com.sacca.openfinder.domain.AccountSetup
import com.sacca.openfinder.domain.AuthResult
import com.sacca.openfinder.domain.AuthState
import com.sacca.openfinder.domain.GrandSlamStep
import com.sacca.openfinder.domain.OpenFinderBackend
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import com.sacca.openfinder.domain.LocationReport
import com.sacca.openfinder.domain.RecoveryRecord
import com.sacca.openfinder.security.SecretStore
import com.sacca.openfinder.lib.OpenFinderLib
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant
import java.util.Base64
import java.util.concurrent.Executors

/**
 * The real backend: every Apple-side step (login, 2FA, reports, tag discovery, Anisette) runs in the Rust library
 * (`libsacca_openfinderlib.so`, source in `native/`) through [OpenFinderLib]. Kotlin keeps what only Android can do: the Keystore-backed
 * storage and the typed errors the UI understands.
 *
 * The library never persists. Each reply that touched Apple carries a `state` blob (the signed-in session) and the machine's
 * `store_export_b64`; both are saved here, encrypted, before the call returns. One dedicated thread makes every native call,
 * so nothing runs on the main thread and the machine's emulated sessions never overlap.
 */
class RustOpenFinderBackend(
    private val machines: MachineStorage,
    private val images: CoreAdiImageSource,
    private val secrets: SecretStore,
    private val cooldown: Cooldown,
) : OpenFinderBackend, AccountSetup {
    private val dispatcher = Executors.newSingleThreadExecutor { Thread(it, "findmy-rust").apply { isDaemon = true } }.asCoroutineDispatcher()

    // Touched only on [dispatcher].
    private var handle: OpenFinderLib? = null
    private var machine: MachineFile? = null

    // ---- OpenFinderBackend ----

    override suspend fun getAuthState(): AuthState = onNative {
        if (!machines.hasMachine()) return@onNative AuthState.AuthenticationRequired
        when (open().loginState()) {
            "logged_in", "authenticated" -> AuthState.Authenticated
            "require_2fa" -> AuthState.TwoFactorRequired(pendingChallenge ?: TRUSTED_DEVICE)
            else -> AuthState.SignedOut
        }
    }

    override suspend fun startLogin(username: String, password: String): AuthResult {
        val pw = password.toCharArray()
        return try {
            onNative {
                val reply = call(JSONObject().put("cmd", "login").put("username", username).put("password_b64", b64(pw)), touchesApple = true)
                loginResult(reply)
            }
        } catch (e: OpenFinderException) {
            AuthResult.Failure(e.error)
        } finally {
            pw.fill('\u0000')
        }
    }

    override suspend fun submitTwoFactor(challengeId: String, code: String): AuthResult = try {
        onNative {
            val reply = if (challengeId.startsWith(SMS)) {
                call(JSONObject().put("cmd", "submit_sms").put("id", challengeId.removePrefix(SMS).toLong()).put("code", code), touchesApple = true)
            } else {
                call(JSONObject().put("cmd", "submit_trusted_device").put("code", code), touchesApple = true)
            }
            loginResult(reply)
        }
    } catch (e: OpenFinderException) {
        AuthResult.Failure(e.error)
    }

    override suspend fun getAccessories(): List<Accessory> = onNative {
        requireSignedIn()
        val rolling = loadTags().map { it.toAccessory() }
        val static = loadStaticKeys()
        if (static.isEmpty()) return@onNative rolling
        // The static tag's stable id is its hashed advertising key, derived natively from the private key.
        val req = JSONArray().also { a -> static.forEach(a::put) }
        val reply = call(JSONObject().put("cmd", "static_keys_info").put("keys", req), touchesApple = false)
        val infos = reply.getJSONArray("keys")
        rolling + List(infos.length()) { i ->
            val o = infos.getJSONObject(i)
            val name = if (o.isNull("name")) "Static tag" else o.optString("name").ifBlank { "Static tag" }
            Accessory(id = o.getString("hashed_adv_key_b64"), name = name)
        }
    }

    override suspend fun fetchReports(accessoryIds: List<String>): List<LocationReport> = onNative {
        requireSignedIn()
        val wanted = accessoryIds.toSet()
        val tags = loadTags()
        val staticKeys = loadStaticKeys()
        val out = ArrayList<LocationReport>()
        var firstError: OpenFinderException? = null
        // Rolling and static legs run through different Apple calls; one leg failing must not
        // take the reports of the other down with it (an error surfaces only when nothing fetched).
        val rollingWanted = tags.filter { it.id in wanted }.map { it.json }
        if (rollingWanted.isNotEmpty()) {
            try { out += withSessionRenewal { fetchRollingReports(rollingWanted, tags) } } catch (e: OpenFinderException) { firstError = e }
        }
        if (staticKeys.isNotEmpty()) {
            try { out += withSessionRenewal { fetchStaticReports(staticKeys, wanted) } } catch (e: OpenFinderException) { firstError = firstError ?: e }
        }
        if (out.isEmpty()) firstError?.let { throw it }
        out
    }

    /** CONTACTS APPLE: one attempt to renew the Apple session without a password (Rust `refresh`). The
     *  passwordless-session path is unverified upstream — when it can't renew, the error propagates. */
    private fun renewSession() {
        call(JSONObject().put("cmd", "refresh"), touchesApple = true)
    }

    /** Runs [block]; on Apple's HTTP 401 renews the session once and retries [block] a single time. */
    private fun <T> withSessionRenewal(block: () -> T): T = try {
        block()
    } catch (e: OpenFinderException) {
        if ((e.error as? OpenFinderError.Rejected)?.http == 401) { renewSession(); block() } else throw e
    }

    private fun fetchRollingReports(wanted: List<JSONObject>, tags: List<Tag>): List<LocationReport> {        val arr = JSONArray().also { a -> wanted.forEach(a::put) }
        val reply = call(JSONObject().put("cmd", "fetch_reports").put("accessories", arr), touchesApple = true)
        val results = reply.getJSONArray("results")
        val out = ArrayList<LocationReport>()
        val updated = tags.associate { it.id to it.json }.toMutableMap()
        for (i in 0 until results.length()) {
            val r = results.getJSONObject(i)
            val id = r.getString("id")
            r.optJSONObject("accessory")?.let { updated[id] = it }        // keeps the rolling-key alignment current
            out += parseReports(r.getJSONArray("reports"), id)
        }
        saveTags(updated.values.toList())
        return out
    }

    /** One batched `fetch_key_reports` call for all static keys; reports are filtered to the requested ids. */
    private fun fetchStaticReports(keys: List<JSONObject>, wanted: Set<String>): List<LocationReport> {
        val arr = JSONArray().also { a -> keys.forEach(a::put) }
        val reply = call(JSONObject().put("cmd", "fetch_key_reports").put("keys", arr), touchesApple = true)
        val results = reply.getJSONArray("results")
        val out = ArrayList<LocationReport>()
        for (i in 0 until results.length()) {
            val r = results.getJSONObject(i)
            val id = r.getString("hashed_adv_key_b64")
            if (com.sacca.openfinder.BuildConfig.DEBUG) android.util.Log.i("StaticFetch",
                "reports=${r.getJSONArray("reports").length()} selected=${id in wanted} " +
                    "undecryptable=${r.optInt("undecryptable")} invalid=${r.optInt("invalid")}")
            if (id in wanted) out += parseReports(r.getJSONArray("reports"), id)
        }
        return out
    }

    private fun parseReports(reports: JSONArray, id: String): List<LocationReport> {
        val out = ArrayList<LocationReport>(reports.length())
        for (j in 0 until reports.length()) {
            val rep = reports.getJSONObject(j)
            out += LocationReport(
                accessoryId = id,
                latitude = rep.getDouble("lat"), longitude = rep.getDouble("lon"),
                observedAt = Instant.ofEpochSecond(rep.getLong("observed_at")),
                horizontalAccuracyMeters = if (rep.isNull("accuracy")) null else rep.getDouble("accuracy"),
            )
        }
        return out
    }

    /** Signs out and forgets the accessories' keys. The machine stays: Apple allows one provisioning per device id.
     *  The static tag blob is deliberately kept too: those keys are the user's own credentials, re-importing them means another trip to the computer. */
    override suspend fun logout() = onNative {
        secrets.delete(SESSION_FILE)
        secrets.delete(TAGS_FILE)
        closeHandle()
    }

    // ---- AccountSetup ----

    override suspend fun hasMachine() = onNative { machines.hasMachine() }

    override suspend fun hasAccessories() = onNative {
        (secrets.exists(TAGS_FILE) && loadTags().isNotEmpty()) || (secrets.exists(STATIC_FILE) && loadStaticKeys().isNotEmpty())
    }

    override suspend fun needsPassword() = onNative {
        !nativeCall(open(), JSONObject().put("cmd", "status"), touchesApple = false).optBoolean("has_password")
    }

    override suspend fun provisionMachine() = onNative {
        if (machines.hasMachine()) throw OpenFinderException(OpenFinderError.Backend("A machine is already installed."))
        cooldown.guard()
        val minted = MachineFile(MachineMint.hostUuid(), MachineMint.identity(), ByteArray(0))
        val image = images.load() ?: throw OpenFinderException(OpenFinderError.Backend("The CoreADI file is not available in this build."))
        val fm = openHandle(minted, image, state = null)
        try {
            val reply = nativeCall(fm, JSONObject().put("cmd", "provision"), touchesApple = true)
            val store = Base64.getDecoder().decode(reply.getString("store_export_b64"))
            val routing = reply.optLong("routing")
            machines.save(MachineFile(minted.hostUuid, minted.identity.copy(routing = routing), store))
        } finally {
            fm.close()
        }
    }

    override suspend fun recoveryRecords(password: CharArray?): List<RecoveryRecord> = onNative {
        requireSignedIn()
        val req = JSONObject().put("cmd", "recovery_options")
        password?.let { req.put("password_b64", b64(it)) }
        val reply = call(req, touchesApple = true)
        val arr = reply.getJSONArray("records")
        List(arr.length()) { RecoveryRecord(arr.getJSONObject(it).getInt("index"), arr.getJSONObject(it).getString("description")) }
    }

    override suspend fun discoverAccessories(index: Int, passcode: CharArray, password: CharArray?): Int = onNative {
        requireSignedIn()
        val req = JSONObject().put("cmd", "discover").put("index", index).put("passcode_b64", b64(passcode))
        password?.let { req.put("password_b64", b64(it)) }
        passcode.fill('\u0000')
        val reply = call(req, touchesApple = true)
        val found = reply.getJSONArray("accessories")
        saveTags(List(found.length()) { found.getJSONObject(it) })
        found.length()
    }

    override suspend fun importAccessories(json: String): Int = onNative {
        val arr = try { JSONArray(json) } catch (e: Exception) { throw OpenFinderException(OpenFinderError.Backend("Not a JSON array of accessories.")) }
        saveTags(List(arr.length()) { arr.getJSONObject(it) })
        arr.length()
    }

    /** Imports static single-key tags: a JSON array of keypairs, or one keypair object. The native side fully
     *  validates before anything is stored; the keys live in their own encrypted blob so they can never reach
     *  the rolling-key fetch path. */
    override suspend fun importStaticKeys(json: String): Int = onNative {
        val arr = try {
            if (json.trimStart().startsWith("[")) JSONArray(json) else JSONArray().put(JSONObject(json))
        } catch (e: Exception) { throw OpenFinderException(OpenFinderError.Backend("Not a JSON array (or a single keypair object) of static tag keys.")) }
        if (arr.length() == 0) throw OpenFinderException(OpenFinderError.Backend("The file contains no keys."))
        call(JSONObject().put("cmd", "static_keys_info").put("keys", arr), touchesApple = false)
        saveStaticKeys(List(arr.length()) { arr.getJSONObject(it) })
        arr.length()
    }

    override suspend fun staticKeyHashes(): List<String> = onNative {
        val keys = loadStaticKeys()
        if (keys.isEmpty()) return@onNative emptyList()
        val req = JSONArray().also { a -> keys.forEach(a::put) }
        val reply = call(JSONObject().put("cmd", "static_keys_info").put("keys", req), touchesApple = false)
        val infos = reply.getJSONArray("keys")
        List(infos.length()) { i -> infos.getJSONObject(i).getString("hashed_adv_key_b64") }
    }

    override suspend fun rotateStaticKeys(newJson: String, oldHashB64: String?): Int = onNative {
        // Native validation first, exactly like the import path: a bad key must not reach the blob.
        val arr = try { JSONArray(newJson) } catch (e: Exception) { JSONArray().put(JSONObject(newJson)) }
        if (arr.length() == 0) throw OpenFinderException(OpenFinderError.Backend("empty rotation payload"))
        call(JSONObject().put("cmd", "static_keys_info").put("keys", arr), touchesApple = false)
        val keys = loadStaticKeys().toMutableList()
        // Keep one active key entry per tag. Match the superseded hash first (multi-tag safe);
        // fallback for a reclaim after a foreign write: the tag no longer advertises any blob key,
        // so retire same-named current entries.
        if (keys.isNotEmpty()) {
            val existing = JSONArray().also { a -> keys.forEach(a::put) }
            val infos = call(JSONObject().put("cmd", "static_keys_info").put("keys", existing), touchesApple = false)
                .getJSONArray("keys")
            val byHash = List(infos.length()) { i -> infos.getJSONObject(i).getString("hashed_adv_key_b64") }
            val freshName = arr.getJSONObject(0).optString("name").ifEmpty { "Static tag" }
            val toRemove = (0 until keys.size).filter { i ->
                (oldHashB64 != null && byHash.getOrNull(i) == oldHashB64) ||
                    (oldHashB64 == null && keys[i].optString("name") == freshName)
            }.ifEmpty {
                (0 until keys.size).filter { keys[it].optString("name") == freshName }
            }
            for (i in toRemove.sortedDescending()) keys.removeAt(i)
        }
        for (i in 0 until arr.length()) keys.add(arr.getJSONObject(i))
        saveStaticKeys(keys)
        keys.size
    }

    /** Opens the library in the background so the first request is not slow; no machine is fine. */
    suspend fun warmUp() {
        try { onNative { if (machines.hasMachine()) open() } } catch (_: OpenFinderException) { /* not ready yet */ }
    }

    // ---- native plumbing (dispatcher only) ----

    private var pendingChallenge: String? = null

    private suspend fun <T> onNative(block: () -> T): T = withContext(dispatcher) { block() }

    private fun open(): OpenFinderLib = handle ?: run {
        val m = machines.load() ?: throw OpenFinderException(OpenFinderError.Authentication("No machine installed. Create one in Account."))
        val image = images.load() ?: throw OpenFinderException(OpenFinderError.Backend("The CoreADI file is not available in this build."))
        val state = secrets.read(SESSION_FILE)?.toString(Charsets.UTF_8)
        openHandle(m, image, state).also { handle = it; machine = m }
    }

    private fun openHandle(m: MachineFile, image: ByteArray, state: String?): OpenFinderLib {
        val json = JSONObject(m.toJson())
        json.put("timezone", java.util.TimeZone.getDefault().getDisplayName(true, java.util.TimeZone.SHORT))
        json.put("locale", java.util.Locale.getDefault().toString().ifEmpty { "en_US" })
        if (state != null) json.put("state", state)
        return try {
            OpenFinderLib.openMachine(json.toString(), image)
        } catch (e: com.sacca.openfinder.lib.OpenFinderLibException) {
            throw OpenFinderException(OpenFinderError.Backend(e.message ?: "Could not open the OpenFinder library"))
        } catch (e: UnsatisfiedLinkError) {
            throw OpenFinderException(OpenFinderError.Backend("The native OpenFinder library is not available for this device's CPU."))
        }
    }

    private fun closeHandle() { handle?.close(); handle = null; machine = null }

    private fun OpenFinderLib.loginState(): String = nativeCall(this, JSONObject().put("cmd", "status"), touchesApple = false).getString("login_state")

    private fun requireSignedIn() {
        if (open().loginState() != "logged_in") throw OpenFinderException(OpenFinderError.Authentication("Sign in to see your accessories."))
    }

    private fun call(request: JSONObject, touchesApple: Boolean) = nativeCall(open(), request, touchesApple)

    /** Runs one command; persists what the reply says to persist; maps `{"ok":false}` to a typed [OpenFinderException]. */
    private fun nativeCall(fm: OpenFinderLib, request: JSONObject, touchesApple: Boolean): JSONObject {
        if (touchesApple) cooldown.guard()
        val reply = try {
            JSONObject(fm.call(request.toString()))
        } catch (e: com.sacca.openfinder.lib.OpenFinderLibException) {
            throw OpenFinderException(OpenFinderError.Backend(e.message ?: "The OpenFinder library failed"))
        }
        if (!reply.optBoolean("ok")) throw typed(reply.optJSONObject("error"))
        reply.optString("state").takeIf { it.isNotEmpty() }?.let { secrets.write(SESSION_FILE, it.toByteArray(Charsets.UTF_8)) }
        val store = reply.optString("store_export_b64")
        val m = machine
        if (store.isNotEmpty() && m != null && handle === fm) {
            val updated = m.withStore(Base64.getDecoder().decode(store))
            machines.save(updated)
            machine = updated
        }
        return reply
    }

    private fun typed(error: JSONObject?): OpenFinderException {
        val message = error?.optString("message").orEmpty().ifEmpty { "The OpenFinder library failed" }
        return OpenFinderException(when (error?.optString("kind")) {
            "network" -> OpenFinderError.Network(message)
            "authentication" -> OpenFinderError.Authentication(message)
            "grand_slam_refused" -> {
                val details = error ?: return OpenFinderException(OpenFinderError.Backend(message))
                val step = when (details.optString("step")) {
                    "init" -> GrandSlamStep.INIT
                    "complete" -> GrandSlamStep.COMPLETE
                    else -> return OpenFinderException(OpenFinderError.Backend(message))
                }
                val ec = if (details.isNull("ec")) null else details.optLong("ec")
                val em = if (details.isNull("em")) null else details.optString("em")
                OpenFinderError.GrandSlamRefused(
                    step = step,
                    ec = ec,
                    em = em,
                    message = message,
                )
            }
            "throttled" -> { cooldown.noteThrottled(); OpenFinderError.Throttled(message) }
            "rejected" -> OpenFinderError.Rejected(error.optInt("http"), if (error.has("ec")) error.getLong("ec") else null, message)
            "reports_unavailable" -> OpenFinderError.ReportsUnavailable(message)
            "not_implemented" -> OpenFinderError.NotImplemented(message)
            else -> OpenFinderError.Backend(message)
        })
    }

    private fun loginResult(reply: JSONObject): AuthResult {
        if (reply.optString("result") == "signed_in") { pendingChallenge = null; return AuthResult.Success }
        val methods = reply.optJSONArray("methods") ?: JSONArray()
        var sms: Long? = null
        var trusted = false
        for (i in 0 until methods.length()) {
            val m = methods.getJSONObject(i)
            if (m.getString("kind") == "trusted_device") trusted = true else if (sms == null) sms = m.getLong("id")
        }
        // SMS first: this app runs on Android, so the trusted-device push is only usable
        // when the user happens to own Apple hardware to read the code on; a trusted
        // phone number works for everyone. Revisit if a second-factor chooser UI lands.
        val challenge = when {
            sms != null -> { call(JSONObject().put("cmd", "request_sms").put("id", sms), touchesApple = true); "$SMS$sms" }
            trusted -> { call(JSONObject().put("cmd", "request_trusted_device"), touchesApple = true); TRUSTED_DEVICE }
            else -> throw OpenFinderException(OpenFinderError.Rejected(200, null, "Apple offered no second-factor method."))
        }
        pendingChallenge = challenge
        return AuthResult.TwoFactorRequired(challenge)
    }

    // ---- accessory keys at rest ----

    private class Tag(val json: JSONObject) {
        // org.json's optString turns a JSON null into the text "null": read through str() instead.
        private fun str(key: String): String = if (json.isNull(key)) "" else json.optString(key)
        val id: String = str("identifier").ifEmpty { str("master_key").take(16) }
        fun toAccessory(): Accessory {
            val model = str("model")
            return Accessory(
                id = id,
                name = str("name").ifEmpty { model.ifEmpty { "Accessory" } },
                type = if (model.startsWith("AirTag")) AccessoryType.AIRTAG else AccessoryType.OTHER,
            )
        }
    }

    private fun loadTags(): List<Tag> {
        val raw = secrets.read(TAGS_FILE) ?: return emptyList()
        val arr = try { JSONArray(String(raw, Charsets.UTF_8)) } catch (e: Exception) { return emptyList() }
        return List(arr.length()) { Tag(arr.getJSONObject(it)) }
    }

    private fun saveTags(tags: List<JSONObject>) {
        secrets.write(TAGS_FILE, JSONArray().also { a -> tags.forEach(a::put) }.toString().toByteArray(Charsets.UTF_8))
    }

    private fun loadStaticKeys(): List<JSONObject> {
        val raw = secrets.read(STATIC_FILE) ?: return emptyList()
        val arr = try { JSONArray(String(raw, Charsets.UTF_8)) } catch (e: Exception) { return emptyList() }
        return List(arr.length()) { arr.getJSONObject(it) }
    }

    private fun saveStaticKeys(keys: List<JSONObject>) {
        secrets.write(STATIC_FILE, JSONArray().also { a -> keys.forEach(a::put) }.toString().toByteArray(Charsets.UTF_8))
    }

    private fun b64(chars: CharArray): String {
        val bytes = String(chars).toByteArray(Charsets.UTF_8)
        return Base64.getEncoder().encodeToString(bytes).also { bytes.fill(0) }
    }

    private companion object {
        const val SESSION_FILE = "session.enc"
        const val TAGS_FILE = "tags.enc"
        const val STATIC_FILE = "static_tags.enc"
        const val TRUSTED_DEVICE = "td"
        const val SMS = "sms:"
    }
}
