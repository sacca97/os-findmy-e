package com.sacca.openfinder.apple.login

import com.sacca.openfinder.apple.AppleTls
import com.sacca.openfinder.apple.AppleAccountContext
import com.sacca.openfinder.apple.Cooldown
import com.sacca.openfinder.apple.Plist
import com.sacca.openfinder.domain.GrandSlamStep
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.ConnectionPool
import okhttp3.Credentials
import okhttp3.Headers
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.security.GeneralSecurityException
import java.time.Clock
import java.time.Instant
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.util.concurrent.TimeUnit

/**
 * An Apple account signed in through Grand Slam and the MobileMe delegate (port of `findmy.reports.account.AsyncAppleAccount`:
 * `login`, `_gsa_authenticate`, `_gsa_request`, `_login_mobileme`, `get_2fa_methods`, `sms_2fa_request/submit`,
 * `td_2fa_request/submit`, `request_pet`, `complete_login`; plus two rules our own `auth_probe.py` drives the library with:
 * the hsc-409 second factor and the 434 Anisette resync).
 *
 * Deliberate differences from the Python, each small:
 *  * the password is never held: [login] keeps only SHA-256(password) in memory (enough for both `s2k` variants), zeroes
 *    the caller's `CharArray`, and nothing password-like is ever persisted. A restored session can therefore not renew a PET
 *    or re-authenticate until [providePassword] is called;
 *  * [login] lists the second-factor methods itself, and a failed phone-number fetch does not hide the trusted-device method
 *    (spec Stage 1 §7.3);
 *  * the trusted-device `validate` reply's `ec` is checked (spec §7.2); the Python ignores that body;
 *  * the delegate reply's HTTP status is checked when its body is not a plist;
 *  * a failed [refreshSession] puts the previous signed-in state back rather than leaving the account half way.
 *
 * Errors are [OpenFinderException]s: HTTP 429 -> Throttled (the shared [Cooldown] starts), other HTTP refusals and Apple's
 * `ec`/`em` -> Rejected, ec -22406 and a refused credential -> Authentication, malformed replies -> Backend, transport ->
 * Network. A call in the wrong [loginState] is a programming error: [IllegalStateException].
 *
 * @param ephemeral the SRP secret `a` for each authentication (tests fix it; the default is pysrp's 256 random bytes).
 */
class AppleAccount(
    private val device: LoginDevice,
    private val anisette: AnisetteSource,
    private val cooldown: Cooldown? = null,
    private val endpoints: LoginEndpoints = LoginEndpoints(),
    override val timeoutSeconds: Long = DEFAULT_TIMEOUT_SECONDS,
    baseHttp: OkHttpClient? = null,
    private val ephemeral: () -> ByteArray = { SrpClient.randomEphemeral() },
    private val clock: Clock = Clock.systemUTC(),
) : AppleAccountContext, RefreshableAccount {

    override val http: OkHttpClient = (baseHttp ?: AppleTls.apply(OkHttpClient.Builder()).build()).newBuilder()
        .callTimeout(timeoutSeconds, TimeUnit.SECONDS)
        .build()

    /** For [LoginEndpoints.noConnectionReuseHosts]: a fresh connection per request. */
    private val unpooled: OkHttpClient = http.newBuilder()
        .connectionPool(ConnectionPool(0, 1, TimeUnit.SECONDS))
        .protocols(listOf(Protocol.HTTP_1_1))
        .build()

    private val mutex = Mutex()

    /**
     * Python's `(login_state, _login_state_data, _account_info)`, as ONE immutable value swapped atomically. Readers on other
     * coroutines (CloudKit, reports) never see a half-updated session, and a PET renewal never touches it.
     */
    private data class Session(val state: LoginState = LoginState.LOGGED_OUT, val data: StateData = StateData(), val info: AccountInfo? = null)

    @Volatile private var session = Session()

    val loginState: LoginState get() = session.state

    /** What `spd` said about the account holder; null before authentication. */
    val accountInfo: AccountInfo? get() = session.info

    @Volatile private var username: String? = null
    private var passwordDigest: ByteArray? = null

    /** Python's `_login_state_data`, typed. Credentials: never logged. */
    private data class StateData(
        val adsid: String? = null,
        val idmsToken: String? = null,
        val idmsPet: String? = null,
        val idmsHb: String? = null,
        val dsid: String? = null,
        val tokens: Map<String, String> = emptyMap(),
        /** When the delegate exchange produced [tokens]. */
        val obtainedAt: Instant? = null,
    ) {
        override fun toString() = "StateData(<redacted>)"
    }

    // ---------------------------------------------------------------- AppleAccountContext

    /** `acname` from `spd` (the canonical Apple ID), else what was typed. */
    override val accountName: String get() = session.info?.accountName ?: username ?: ""

    override val dsid: String get() = session.data.dsid ?: throw IllegalStateException("Not signed in: no dsid")

    /** The authentication's account id; empty when unknown (a session saved before it was kept). */
    override val adsid: String get() = session.data.adsid ?: ""

    override val deviceUuid: String get() = device.cloudKitDeviceUuid

    /** Python's `account.client_info` (the provider's `client`, Xcode bundle). CloudKit reads only its platform prefix. */
    override val clientInfo: String get() = device.identity.clientInfo(LoginBundles.XCODE)

    override val serial: String? get() = device.serial

    override val localUserUuid: String get() = device.localUserUuid

    override suspend fun serviceToken(name: String): String? =
        session.let { if (it.state == LoginState.LOGGED_IN) it.data.tokens[name] else null }

    /** All service token names, for diagnostics (values stay inside). */
    fun serviceTokenNames(): Set<String> = session.data.tokens.keys

    override suspend fun anisetteHeaders(): Map<String, String> = LoginMessages.withoutClientInfo(anisette.headers())

    /**
     * A fresh PET (`request_pet`): authenticates again and returns the new token without spending it. The signed-in session
     * is never touched while this runs. Every call is a real SRP exchange (two Grand Slam requests); the token lives about
     * five minutes.
     *
     * @throws OpenFinderException Authentication when no password is in memory (a restored session: see [providePassword]) or
     *   when Apple demands a second factor.
     */
    override suspend fun requestPet(): String = mutex.withLock {
        requireState(LoginState.LOGGED_IN)
        requirePassword("renew the PET")
        val fresh = authenticate()
        if (fresh.state != LoginState.AUTHENTICATED) {
            throw OpenFinderException(OpenFinderError.Authentication("Apple asked for a second factor to renew the PET, so none was issued. Sign in again."))
        }
        val pet = fresh.data.idmsPet?.takeIf { it.isNotEmpty() } ?: throw backend("Re-authentication succeeded but returned no PET")
        // Python takes the chance to record the adsid for a session saved before it was kept.
        if (session.data.adsid == null && fresh.data.adsid != null) session = session.copy(data = session.data.copy(adsid = fresh.data.adsid))
        pet
    }

    // ---------------------------------------------------------------- login and second factor

    /**
     * Signs in (`login`). [password] is hashed at once and then zeroed; only the digest is kept, in memory, for the second
     * SRP pass after a code and for PET renewals.
     *
     * @param listPhoneNumbers whether to fetch the trusted phone numbers when a second factor is required. Off saves a
     *   request (and seconds of the machine's acceptance window) when the trusted-device push will be used.
     */
    suspend fun login(username: String, password: CharArray, listPhoneNumbers: Boolean = true): LoginResult = mutex.withLock {
        requireState(LoginState.LOGGED_OUT)
        val digest = try { GsaCrypto.passwordDigest(password) } finally { password.fill('\u0000') }
        this.username = username
        setDigest(digest)
        try {
            session = authenticate()
            if (session.state == LoginState.REQUIRE_2FA) {
                return@withLock LoginResult.SecondFactorRequired(listMethods(listPhoneNumbers))
            }
            session = loginMobileme(session)
            LoginResult.SignedIn
        } catch (e: Throwable) {
            if (session.state == LoginState.LOGGED_OUT) forgetPasswordLocked()
            throw e
        }
    }

    /** `get_2fa_methods`: the trusted-device push when `au` offered it, then every trusted phone number. */
    suspend fun secondFactorMethods(): List<SecondFactorMethod> = mutex.withLock {
        requireState(LoginState.REQUIRE_2FA)
        listMethods(listPhoneNumbers = true)
    }

    suspend fun requestSmsCode(phoneNumberId: Long) = mutex.withLock {
        requireState(LoginState.REQUIRE_2FA)
        twoFactorRequest("PUT", endpoints.smsRequest, LoginMessages.smsRequestBody(phoneNumberId))
        Unit
    }

    suspend fun submitSmsCode(phoneNumberId: Long, code: String): LoginResult = mutex.withLock {
        requireState(LoginState.REQUIRE_2FA)
        twoFactorRequest("POST", endpoints.smsSubmit, LoginMessages.smsSubmitBody(phoneNumberId, checkedCode(code)))
        finishSecondFactor()
    }

    /**
     * Asks Apple to push a code to the trusted devices. Our `auth_probe.py` does this by default (the push Apple announces
     * with hsc 409 does not arrive on its own) and treats a failure as non-fatal: the UI should still ask for the code.
     */
    suspend fun requestTrustedDeviceCode() = mutex.withLock {
        requireState(LoginState.REQUIRE_2FA)
        twoFactorRequest("GET", endpoints.trustedDeviceRequest, extra = PLIST_NEGOTIATION)
        Unit
    }

    suspend fun submitTrustedDeviceCode(code: String): LoginResult = mutex.withLock {
        requireState(LoginState.REQUIRE_2FA)
        val reply = twoFactorRequest("GET", endpoints.trustedDeviceSubmit, extra = mapOf("security-code" to checkedCode(code)) + PLIST_NEGOTIATION)
        validateReplyStatus(reply)
        finishSecondFactor()
    }

    /** `complete_login`: repeat the delegate exchange after it failed once authentication had succeeded. */
    suspend fun completeLogin(): LoginResult = mutex.withLock {
        requireState(LoginState.AUTHENTICATED)
        session = loginMobileme(session)
        LoginResult.SignedIn
    }

    /**
     * Authenticates again and repeats the delegate exchange, for a service that answered 401 (`fetch_raw_reports`'s recovery).
     * The live session is replaced only when both succeed; on failure it stays as it was.
     */
    override suspend fun refreshSession() = mutex.withLock {
        requireState(LoginState.LOGGED_IN)
        requirePassword("sign in again")
        val fresh = authenticate()
        if (fresh.state != LoginState.AUTHENTICATED) {
            throw OpenFinderException(OpenFinderError.Authentication("Apple asks for a second factor again. Sign in again."))
        }
        session = loginMobileme(fresh)
    }

    /** Holds the password (as its digest) for PET renewal and re-authentication of a restored session. Zeroes [password]. */
    suspend fun providePassword(password: CharArray) = mutex.withLock {
        val digest = try { GsaCrypto.passwordDigest(password) } finally { password.fill('\u0000') }
        setDigest(digest)
    }

    suspend fun forgetPassword() = mutex.withLock { forgetPasswordLocked() }

    suspend fun hasPassword(): Boolean = mutex.withLock { passwordDigest != null }

    /** The signed-in state to persist with [SessionStore]; `savedAt` is when the tokens were obtained. No password, no PET. */
    fun snapshot(): SavedSession {
        val s = session
        check(s.state == LoginState.LOGGED_IN) { "Invalid login state: ${s.state}, but should be LOGGED_IN" }
        return SavedSession(
            username = username ?: "", localUserUuid = device.localUserUuid, deviceId = device.deviceId,
            cloudKitDeviceUuid = device.cloudKitDeviceUuid, accountName = s.info?.accountName,
            firstName = s.info?.firstName, lastName = s.info?.lastName, dsid = s.data.dsid ?: "", adsid = s.data.adsid,
            idmsHb = s.data.idmsHb, serviceTokens = s.data.tokens, savedAt = s.data.obtainedAt ?: clock.instant(),
        )
    }

    override fun toString() = "AppleAccount(state=$loginState)"

    // ---------------------------------------------------------------- Grand Slam

    /**
     * `_gsa_authenticate`: SRP init/complete, `spd`, and the second-factor verdict. Returns the resulting session state and
     * assigns nothing: each caller decides whether it becomes the live session. Called with [mutex] held.
     */
    private suspend fun authenticate(): Session {
        val user = username ?: throw IllegalStateException("No username")
        val digest = passwordDigest ?: throw OpenFinderException(OpenFinderError.Authentication("No password is available to authenticate with."))
        val srp = SrpClient(user, ephemeral())

        var r = gsaRequest(mapOf("A2k" to srp.publicA, "u" to user, "ps" to listOf(GsaCrypto.S2K, GsaCrypto.S2K_FO), "o" to "init"))
        checkStatus(r, GrandSlamStep.INIT)
        val sp = r["sp"] as? String
        if (sp != GsaCrypto.S2K && sp != GsaCrypto.S2K_FO) throw backend("This implementation only supports s2k and s2k_fo; the server chose ${sp ?: "nothing"}")
        val salt = r["s"] as? ByteArray ?: throw backend("The init reply has no salt")
        val serverB = r["B"] as? ByteArray ?: throw backend("The init reply has no B")
        val iterations = (r["i"] as? Number)?.toInt()?.takeIf { it > 0 } ?: throw backend("The init reply has no iteration count")
        val c = r["c"] as? String ?: throw backend("The init reply has no continuation")

        val p = GsaCrypto.derivePassword(digest, salt, iterations, sp)
        val m1 = try { srp.processChallenge(salt, serverB, p) } finally { p.fill(0) } ?: throw backend("Failed to process challenge")

        r = gsaRequest(mapOf("c" to c, "M1" to m1, "u" to user, "o" to "complete"))
        val status = checkStatus(r, GrandSlamStep.COMPLETE)
        if (!srp.verifySession(r["M2"] as? ByteArray)) throw backend("Failed to verify session: Apple's proof did not match")

        val spd = try {
            Plist.parseDict(GsaCrypto.withPlistProlog(GsaCrypto.decryptSpd(srp.sessionKey!!, r["spd"] as? ByteArray ?: throw backend("The complete reply has no spd"))))
        } catch (e: GeneralSecurityException) {
            throw backend("The session payload could not be decrypted")
        } catch (e: IllegalArgumentException) {
            throw backend("The session payload is not a property list")
        }

        var au = status["au"] as? String
        // auth_probe.py: since 2026-10-12 Apple pushes the prompt itself and answers `complete` with hsc 409 and no `au`.
        // Without this rule the second factor is skipped and the delegate answers status 1.
        if (au == null && (status["hsc"] as? Number)?.toLong() == 409L) au = TRUSTED_DEVICE_AU
        val info = AccountInfo(spd["acname"] as? String, spd["fn"] as? String, spd["ln"] as? String, trustedDevice2fa = au == TRUSTED_DEVICE_AU)
        val adsid = spd["adsid"] as? String ?: throw backend("The session payload has no adsid")

        return when (au) {
            "secondaryAuth", TRUSTED_DEVICE_AU -> {
                val idms = spd["GsIdmsToken"] as? String ?: throw backend("The session payload has no GsIdmsToken")
                Session(LoginState.REQUIRE_2FA, StateData(adsid = adsid, idmsToken = idms), info)
            }
            null -> {
                @Suppress("UNCHECKED_CAST")
                val t = spd["t"] as? Map<String, Any?> ?: emptyMap()
                fun token(name: String) = ((t[name] as? Map<*, *>)?.get("token") as? String) ?: ""
                Session(LoginState.AUTHENTICATED, StateData(adsid = adsid, idmsPet = token("com.apple.gs.idms.pet"), idmsHb = token("com.apple.gs.idms.hb")), info)
            }
            else -> throw backend("Unknown auth value: $au")
        }
    }

    /**
     * `_gsa_request`, with `auth_probe.install_auto_resync`: a reply of hsc 434 carrying a SIM is answered through
     * [AnisetteSource.resync] and the same parameters are sent once more with fresh Anisette. Never more than once.
     */
    private suspend fun gsaRequest(parameters: Map<String, Any?>): Map<String, Any?> {
        val first = gsaExchange(parameters)
        val sim = first.sim
        if (!first.wantsResync || sim == null) return first.response
        anisette.resync(sim)
        return gsaExchange(parameters).response
    }

    private class GsaReply(val response: Map<String, Any?>, val wantsResync: Boolean, val sim: String?)

    private suspend fun gsaExchange(parameters: Map<String, Any?>): GsaReply {
        val body = LoginMessages.gsaBody(parameters, LoginMessages.cpd(LoginMessages.withoutClientInfo(anisette.headers())))
        val reply = send("POST", endpoints.gsa, LoginMessages.gsaHeaders(device.identity), body)
        val headerSim = reply.headers["X-Apple-I-MD-DATA"]
        if (reply.code == 434 && headerSim != null) return GsaReply(emptyMap(), true, headerSim)
        if (reply.code !in 200..299) {
            // A 434 whose SIM is in the plist body is still a resync request.
            if (reply.code == 434) parseGsa(reply.body)?.let { r -> simOf(r)?.let { return GsaReply(r, true, it) } }
            throw httpFailure(reply, "The Grand Slam request")
        }
        val response = parseGsa(reply.body) ?: throw backend("The Grand Slam reply is not a property list with a Response")
        val status = response["Status"] as? Map<*, *>
        val sim = simOf(response) ?: headerSim
        return GsaReply(response, (status?.get("hsc") as? Number)?.toLong() == 434L && sim != null, sim)
    }

    private fun parseGsa(body: ByteArray): Map<String, Any?>? = try {
        @Suppress("UNCHECKED_CAST")
        Plist.parseDict(body)["Response"] as? Map<String, Any?>
    } catch (e: IllegalArgumentException) { null }

    private fun simOf(response: Map<String, Any?>): String? = ((response["Status"] as? Map<*, *>)?.get("X-Apple-I-MD-DATA") as? String)?.takeIf { it.isNotEmpty() }

    /** `Status.ec` must be 0; keep the SRP step because `init` has not sent a password-derived proof. */
    @Suppress("UNCHECKED_CAST")
    private fun checkStatus(response: Map<String, Any?>, step: GrandSlamStep): Map<String, Any?> {
        val what = if (step == GrandSlamStep.INIT) "Email verification failed" else "Password authentication failed"
        val status = response["Status"] as? Map<String, Any?> ?: throw backend("$what: the reply has no Status")
        val ec = (status["ec"] as? Number)?.toLong()
        if (ec == 0L) return status
        val em = status["em"] as? String
        val code = ec?.toString() ?: "missing"
        val detail = em?.takeIf { it.isNotEmpty() } ?: "no message"
        val context = when {
            step == GrandSlamStep.INIT -> ". The password was not sent in this step"
            step == GrandSlamStep.COMPLETE && ec == EC_BAD_CREDENTIALS ->
                ". Apple may also return this for a machine it no longer accepts"
            else -> ""
        }
        throw OpenFinderException(
            OpenFinderError.GrandSlamRefused(step, ec, em, "$what (ec=$code): $detail$context")
        )
    }

    // ---------------------------------------------------------------- MobileMe delegate

    /**
     * `_login_mobileme`: exchanges the PET of an AUTHENTICATED [from] for the service tokens and returns the LOGGED_IN
     * session. Assigns nothing. Called with [mutex] held.
     */
    private suspend fun loginMobileme(from: Session): Session {
        val user = username ?: ""
        val adsid = from.data.adsid ?: throw backend("No adsid to log into the delegate with")
        val pet = from.data.idmsPet ?: ""
        val reply = send(
            "POST", endpoints.loginDelegates,
            LoginMessages.loginDelegatesHeaders(device.identity, adsid, anisette.headers()),
            LoginMessages.loginDelegatesBody(user, pet, device.localUserUuid),
            contentType = "application/octet-stream",
            basicAuth = user to pet,
        )
        if (reply.code == 429) throw httpFailure(reply, "The delegate request")
        val plist = try { Plist.parseDict(reply.body) } catch (e: IllegalArgumentException) {
            if (reply.code !in 200..299) throw httpFailure(reply, "The delegate request")
            throw backend("The delegate reply is not a property list")
        }
        val localizedError = plist["localizedError"]?.toString()
        val status = plist["status"]
        val failed = localizedError != null || (status != null && !(status is Number && status.toLong() == 0L))
        val mobileme = (plist["delegates"] as? Map<*, *>)?.get("com.apple.mobileme") as? Map<*, *>
        val serviceData = mobileme?.get("service-data") as? Map<*, *>
        if (failed || serviceData == null) {
            throw delegateError(reply.code, localizedError, plist["description"]?.toString(), if (failed) status else mobileme?.get("status"), mobileme?.get("status-message")?.toString())
        }
        val dsid = plist["dsid"]?.toString() ?: throw backend("The delegate reply has no dsid")
        val tokens = (serviceData["tokens"] as? Map<*, *>)?.entries?.mapNotNull { (k, v) -> if (k is String && v is String) k to v else null }?.toMap().orEmpty()
        return Session(LoginState.LOGGED_IN, StateData(adsid = adsid, idmsHb = from.data.idmsHb, dsid = dsid, tokens = tokens, obtainedAt = clock.instant()), from.info)
    }

    /** `MobileMeDelegateError`, typed: UNAUTHORIZED is a refused (usually expired) credential; anything else is reported verbatim. */
    private fun delegateError(http: Int, localizedError: String?, description: String?, status: Any?, statusMessage: String?): OpenFinderException {
        val said = listOfNotNull(
            localizedError?.let { "localizedError=$it" }, description?.let { "description=$it" },
            status?.let { "status=$it" }, statusMessage?.let { "status-message=$it" },
        ).joinToString(", ").ifEmpty { "nothing about why" }
        if (localizedError == "UNAUTHORIZED") {
            return OpenFinderException(OpenFinderError.Authentication("The com.apple.mobileme delegate refused the credential ($said); usually an expired PET. Sign in again."))
        }
        val remedy = if (localizedError != null) "If the account has unaccepted iCloud terms, accepting them is the remedy." else
            "No localizedError came back, so this is not the terms channel: the delegate refused the account itself (reported for Apple IDs never used on an Apple device)."
        return OpenFinderException(OpenFinderError.Rejected(http, (status as? Number)?.toLong(), "The com.apple.mobileme delegate request failed, reporting $said. $remedy"))
    }

    // ---------------------------------------------------------------- second factor

    private suspend fun listMethods(listPhoneNumbers: Boolean): List<SecondFactorMethod> {
        val info = session.info ?: return emptyList()
        val methods = mutableListOf<SecondFactorMethod>()
        if (info.trustedDevice2fa) methods += SecondFactorMethod.TrustedDevice
        if (!listPhoneNumbers) return methods
        try {
            methods += LoginMessages.extractPhoneNumbers(twoFactorRequest("GET", endpoints.twoFactorMethods))
        } catch (e: IllegalArgumentException) {
            // No boot_args element: the Python logs this and carries on with what it has.
        } catch (e: OpenFinderException) {
            // Deliberate difference: the push needs no phone number, so a failed page does not hide it.
            if (methods.isEmpty() || e.error is OpenFinderError.Throttled) throw e
        }
        return methods
    }

    /** `_sms_2fa_request`: one request to the two-factor web endpoints. Returns the body text. */
    private suspend fun twoFactorRequest(method: String, url: String, json: String? = null, extra: Map<String, String> = emptyMap()): String {
        val adsid = session.data.adsid ?: throw backend("No adsid for the two-factor request")
        val idms = session.data.idmsToken ?: throw backend("No identity token for the two-factor request")
        val headers = LoginMessages.twoFactorHeaders(device.identity, LoginMessages.identityToken(adsid, idms), anisette.headers(), extra)
        val reply = send(method, url, headers, json?.toByteArray(Charsets.UTF_8), contentType = "application/json")
        if (reply.code !in 200..299) throw httpFailure(reply, "The two-factor request")
        return String(reply.body, Charsets.UTF_8)
    }

    /** The `validate` reply is a plist with `ec`/`em` (spec §7.2); a non-zero `ec` means the code was refused. */
    private fun validateReplyStatus(body: String) {
        val response = try {
            Plist.parseDict(body.toByteArray(Charsets.UTF_8)).let { (it["Response"] as? Map<*, *>) ?: it }
        } catch (e: IllegalArgumentException) { return }          // not a plist: the Python never reads it either
        val status = (response["Status"] as? Map<*, *>) ?: response
        val ec = (status["ec"] as? Number)?.toLong() ?: return
        if (ec != 0L) throw OpenFinderException(OpenFinderError.Rejected(200, ec, "The code was not accepted: ${status["em"] ?: ""} (ec $ec)"))
    }

    /** After a code: SRP again (no `au` this time), then the delegate. */
    private suspend fun finishSecondFactor(): LoginResult {
        val fresh = authenticate()
        if (fresh.state != LoginState.AUTHENTICATED) {
            if (fresh.state == LoginState.REQUIRE_2FA) session = fresh        // as Python: the new challenge replaces the old
            throw OpenFinderException(OpenFinderError.Authentication("Apple still asks for a second factor after the code was submitted; the code was probably not accepted."))
        }
        session = fresh
        session = loginMobileme(fresh)
        return LoginResult.SignedIn
    }

    // ---------------------------------------------------------------- HTTP

    private class Reply(val code: Int, val body: ByteArray, val headers: Headers, val host: String)

    private suspend fun send(
        method: String,
        url: String,
        headers: Map<String, String>,
        body: ByteArray?,
        contentType: String? = null,
        basicAuth: Pair<String, String>? = null,
    ): Reply = withContext(Dispatchers.IO) {
        val host = url.toHttpUrl().host
        if (host in endpoints.cooldownHosts) cooldown?.guard()
        val builder = Request.Builder().url(url)
        var mediaType = contentType
        for ((k, v) in headers) {
            // With a body, the body's media type is the Content-Type (OkHttp would replace a header anyway).
            if (body != null && k.equals("Content-Type", ignoreCase = true)) mediaType = v else builder.header(k, v)
        }
        basicAuth?.let { (u, p) -> builder.header("Authorization", Credentials.basic(u, p, Charsets.ISO_8859_1)) }
        builder.method(method, body?.toRequestBody(mediaType?.toMediaType()))
        val client = if (host in endpoints.noConnectionReuseHosts) unpooled else http
        if (client === unpooled) builder.header("Connection", "close")
        try {
            client.newCall(builder.build()).execute().use { Reply(it.code, it.body.bytes(), it.headers, host) }
        } catch (e: IOException) {
            throw OpenFinderException(OpenFinderError.Network("Could not reach $host: ${e.javaClass.simpleName}"))
        }
    }

    /** HTTP refusals: 429 is a rate limit (on Grand Slam the cooldown starts); anything else carries the status and any `Retry-After`. */
    private fun httpFailure(reply: Reply, what: String): OpenFinderException {
        if (reply.code == 429) {
            if (reply.host in endpoints.cooldownHosts) cooldown?.noteThrottled()
            return OpenFinderException(OpenFinderError.Throttled("Apple is rate-limiting this device (HTTP 429). This is a rate limit, not a verdict: the identical request works after a cooldown."))
        }
        val wait = retryAfterSeconds(reply.headers["Retry-After"])?.let { " Apple asked to wait $it s before trying again." } ?: ""
        return OpenFinderException(OpenFinderError.Rejected(reply.code, null, "$what was refused with HTTP ${reply.code}.$wait"))
    }

    /** `errors.parse_retry_after`: seconds, or an HTTP date (a past date is 0); null when absent or unreadable. */
    private fun retryAfterSeconds(raw: String?): Long? {
        val v = raw?.trim() ?: return null
        if (v.isNotEmpty() && v.all { it.isDigit() }) return v.toLongOrNull()
        return try {
            val at = ZonedDateTime.parse(v, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant()
            maxOf(0L, at.epochSecond - clock.instant().epochSecond)
        } catch (e: DateTimeParseException) { null }
    }

    // ---------------------------------------------------------------- helpers

    private fun requireState(vararg states: LoginState) {
        val state = session.state
        check(state in states) { "Invalid login state: $state, but should be one of ${states.toList()}" }
    }

    private fun requirePassword(forWhat: String) {
        if (passwordDigest == null) {
            throw OpenFinderException(OpenFinderError.Authentication("The password is needed to $forWhat: this session was restored without it."))
        }
    }

    private fun setDigest(digest: ByteArray) {
        passwordDigest?.fill(0)
        passwordDigest = digest
    }

    private fun forgetPasswordLocked() {
        passwordDigest?.fill(0)
        passwordDigest = null
    }

    private fun checkedCode(code: String): String {
        val c = code.trim()
        require(c.isNotEmpty() && c.none { it.isWhitespace() || it.isISOControl() }) { "not a verification code" }
        return c
    }

    private fun backend(message: String) = OpenFinderException(OpenFinderError.Backend(message))

    companion object {
        const val DEFAULT_TIMEOUT_SECONDS = 30L
        private const val TRUSTED_DEVICE_AU = "trustedDeviceSecondaryAuth"
        private const val EC_BAD_CREDENTIALS = -22406L
        private val PLIST_NEGOTIATION = mapOf("Content-Type" to "text/x-xml-plist", "Accept" to "text/x-xml-plist")

        /**
         * A saved session on this machine, signed in with no request to Apple (`login_store.restore`). Refuses a session saved
         * on a different machine: a login only works with the machine that made it. No password: see [providePassword].
         */
        fun restore(
            saved: SavedSession,
            device: LoginDevice,
            anisette: AnisetteSource,
            cooldown: Cooldown? = null,
            endpoints: LoginEndpoints = LoginEndpoints(),
            timeoutSeconds: Long = DEFAULT_TIMEOUT_SECONDS,
            baseHttp: OkHttpClient? = null,
            ephemeral: () -> ByteArray = { SrpClient.randomEphemeral() },
            clock: Clock = Clock.systemUTC(),
        ): AppleAccount {
            if (saved.deviceId != device.deviceId || saved.localUserUuid != device.localUserUuid) {
                throw OpenFinderException(OpenFinderError.Authentication("The saved sign-in belongs to a different machine. Sign in again."))
            }
            return AppleAccount(device, anisette, cooldown, endpoints, timeoutSeconds, baseHttp, ephemeral, clock).apply {
                username = saved.username
                session = Session(
                    LoginState.LOGGED_IN,
                    StateData(adsid = saved.adsid, idmsHb = saved.idmsHb, dsid = saved.dsid, tokens = saved.serviceTokens, obtainedAt = saved.savedAt),
                    AccountInfo(saved.accountName, saved.firstName, saved.lastName, trustedDevice2fa = false),
                )
            }
        }
    }
}
