package com.sacca.openfinder.apple.login

import com.sacca.openfinder.apple.Plist
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.util.Base64

/**
 * Request bodies and header sets of the login, as `AsyncAppleAccount` composes them (`_gsa_request`, `_login_mobileme`,
 * `_sms_2fa_request`, `get_cpd`, `get_headers(with_client_info=True)`), and the parsing of the 2FA page. Pure functions:
 * the oracle tests compare them with the Python's output.
 */
object LoginMessages {
    /** `get_cpd`: Python's five capability flags plus the Anisette set. (Spec §5 lists more keys; the Python sends these.) */
    fun cpd(anisette: Map<String, String>): Map<String, Any?> = buildMap {
        put("bootstrap", true)
        put("icscrec", true)
        put("pbe", false)
        put("prkgen", true)
        put("svct", "iCloud")
        putAll(anisette)
    }

    /** The GsService2 envelope: `{Header: {Version: 1.0.1}, Request: {cpd, ...parameters}}` as an XML plist. */
    fun gsaBody(parameters: Map<String, Any?>, cpd: Map<String, Any?>): ByteArray =
        Plist.toXml(mapOf("Header" to mapOf("Version" to "1.0.1"), "Request" to mapOf("cpd" to cpd) + parameters))

    /** GsService2 headers. Anisette travels in `cpd`, not here. */
    fun gsaHeaders(identity: DeviceIdentity): Map<String, String> = mapOf(
        "Content-Type" to "text/x-xml-plist",
        "Accept" to "*/*",
        "User-Agent" to LoginBundles.GSA_USER_AGENT,
        "X-MMe-Client-Info" to identity.clientInfo(LoginBundles.AKD),
    )

    /** The legacy (no validation data) delegate request body. `client-id` is the local user uuid, as the Python sends. */
    fun loginDelegatesBody(username: String, pet: String, localUserUuid: String): ByteArray = Plist.toXml(
        mapOf(
            "apple-id" to username,
            "delegates" to mapOf("com.apple.mobileme" to emptyMap<String, Any?>()),
            "password" to pet,
            "client-id" to localUserUuid,
        ),
    )

    fun loginDelegatesHeaders(identity: DeviceIdentity, adsid: String, anisette: Map<String, String>): Map<String, String> =
        linkedMapOf(
            "X-Apple-ADSID" to adsid,
            "User-Agent" to identity.userAgent(LoginBundles.ICLOUD_HELPER),
            "X-Mme-Client-Info" to identity.clientInfo(LoginBundles.ACCOUNTSD),
        ).apply { putAll(withoutClientInfo(anisette)) }

    /** `X-Apple-Identity-Token`: base64(adsid ":" GsIdmsToken). A credential. */
    fun identityToken(adsid: String, idmsToken: String): String =
        Base64.getEncoder().encodeToString("$adsid:$idmsToken".toByteArray(Charsets.UTF_8))

    /** `_sms_2fa_request`'s header set: the endpoint's own, the Xcode identity, the token and Anisette with client info. */
    fun twoFactorHeaders(
        identity: DeviceIdentity,
        identityToken: String,
        anisette: Map<String, String>,
        extra: Map<String, String> = emptyMap(),
    ): Map<String, String> = LinkedHashMap(extra).apply {
        put("User-Agent", LoginBundles.TWO_FACTOR_USER_AGENT)
        put("Accept-Language", "en-us")
        put("X-Apple-Identity-Token", identityToken)
        putAll(withoutClientInfo(anisette))
        put("X-Mme-Client-Info", identity.clientInfo(LoginBundles.XCODE))
        put("X-Apple-App-Info", LoginBundles.TWO_FACTOR_APP_INFO)
        put("X-Xcode-Version", LoginBundles.TWO_FACTOR_XCODE_VERSION)
    }

    /** `{"phoneNumber": {"id": N}, "mode": "sms"}`, byte-for-byte as Python's `json.dumps`. */
    fun smsRequestBody(phoneNumberId: Long): String = """{"phoneNumber": {"id": $phoneNumberId}, "mode": "sms"}"""

    fun smsSubmitBody(phoneNumberId: Long, code: String): String =
        """{"phoneNumber": {"id": $phoneNumberId}, "securityCode": {"code": ${pyJsonString(code)}}, "mode": "sms"}"""

    /**
     * `_extract_phone_numbers`: the JSON in `<script class="boot_args">` of the `/auth` page, then
     * `direct.phoneNumberVerification.trustedPhoneNumbers`. Each becomes an SMS method with Python's fallbacks
     * (`id or -1`, `numberWithDialCode or "-"`).
     *
     * @throws IllegalArgumentException when the page has no such script (Python: `RuntimeError`).
     */
    fun extractPhoneNumbers(html: String): List<SecondFactorMethod.Sms> {
        val script = SCRIPT.findAll(html).firstOrNull { m ->
            val cls = CLASS_ATTR.find(m.groupValues[1])?.let { it.groupValues[2].ifEmpty { it.groupValues[3] } } ?: ""
            cls.split(Regex("\\s+")).contains("boot_args")
        } ?: throw IllegalArgumentException("Could not find HTML element containing phone numbers")
        val data = try { JSONObject(script.groupValues[2]) } catch (e: JSONException) {
            throw IllegalArgumentException("The phone-number element is not JSON")
        }
        val numbers: JSONArray = data.optJSONObject("direct")?.optJSONObject("phoneNumberVerification")
            ?.optJSONArray("trustedPhoneNumbers") ?: return emptyList()
        return (0 until numbers.length()).mapNotNull { numbers.optJSONObject(it) }.map { n ->
            val id = n.opt("id").let { if (it is Number && it.toLong() != 0L) it.toLong() else -1L }
            val number = n.opt("numberWithDialCode").let { if (it is String && it.isNotEmpty()) it else "-" }
            SecondFactorMethod.Sms(id, number)
        }
    }

    private val SCRIPT = Regex("<script\\b([^>]*)>(.*?)</script\\s*>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
    private val CLASS_ATTR = Regex("\\bclass\\s*=\\s*(\"([^\"]*)\"|'([^']*)')", RegexOption.IGNORE_CASE)

    /** Anisette must not bring a client info of its own: each endpoint names its daemon. */
    internal fun withoutClientInfo(h: Map<String, String>): Map<String, String> = h.filterKeys { !it.equals("X-MMe-Client-Info", ignoreCase = true) }

    /** A JSON string literal as Python's `json.dumps` (ensure_ascii) writes it. */
    internal fun pyJsonString(s: String): String = buildString {
        append('"')
        for (c in s) when {
            c == '"' -> append("\\\"")
            c == '\\' -> append("\\\\")
            c == '\n' -> append("\\n")
            c == '\r' -> append("\\r")
            c == '\t' -> append("\\t")
            c == '\b' -> append("\\b")
            c == '\u000c' -> append("\\f")
            c.code < 0x20 || c.code > 0x7e -> append("\\u%04x".format(c.code))
            else -> append(c)
        }
        append('"')
    }
}
