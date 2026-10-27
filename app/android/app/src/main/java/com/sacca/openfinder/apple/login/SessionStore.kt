package com.sacca.openfinder.apple.login

import com.sacca.openfinder.security.SecretStore
import org.json.JSONException
import org.json.JSONObject
import java.time.Duration
import java.time.Instant

/** Named encrypted blobs. [SecretStore] in the app; an in-memory map in JVM tests (SecretStore needs the Android Keystore). */
interface SecretBlobs {
    fun read(name: String): ByteArray?
    fun write(name: String, plaintext: ByteArray)
    fun delete(name: String)
}

class SecretStoreBlobs(private val store: SecretStore) : SecretBlobs {
    override fun read(name: String) = store.read(name)
    override fun write(name: String, plaintext: ByteArray) = store.write(name, plaintext)
    override fun delete(name: String) = store.delete(name)
}

/**
 * A signed-in account as saved (port of `tools/machoadi/login_store.py`, without the password: the hard rule is that a
 * password is never persisted). Enough to use the account again with no login and no second factor; renewing a PET or
 * re-authenticating afterwards needs the password typed again ([AppleAccount.providePassword]).
 *
 * Holds credentials (service tokens, the heartbeat token): [toString] redacts them.
 *
 * @property idmsHb the heartbeat token (`com.apple.gs.idms.hb`). Issued only by the authentication and not re-requestable.
 * @property savedAt when the delegate exchange produced [serviceTokens]. Apple states no expiry for them; a reference client
 *   refreshes them weekly (spec Stage 2 §5.1), see [olderThan].
 */
data class SavedSession(
    val username: String,
    val localUserUuid: String,
    val deviceId: String,
    val cloudKitDeviceUuid: String,
    val accountName: String?,
    val firstName: String?,
    val lastName: String?,
    val dsid: String,
    val adsid: String?,
    val idmsHb: String?,
    val serviceTokens: Map<String, String>,
    val savedAt: Instant,
) {
    fun olderThan(age: Duration, now: Instant = Instant.now()): Boolean = savedAt.plus(age).isBefore(now)

    override fun toString() = "SavedSession(dsid=<redacted>, tokens=${serviceTokens.keys.sorted()}, savedAt=$savedAt)"

    fun toJson(): String = JSONObject().apply {
        put("version", VERSION)
        put("username", username)
        put("ids", JSONObject().put("uid", localUserUuid).put("devid", deviceId).put("cloudkit_device_uuid", cloudKitDeviceUuid))
        put("info", JSONObject().apply {
            accountName?.let { put("account_name", it) }
            firstName?.let { put("first_name", it) }
            lastName?.let { put("last_name", it) }
        })
        put("login", JSONObject().apply {
            put("dsid", dsid)
            adsid?.let { put("adsid", it) }
            idmsHb?.let { put("idms_hb", it) }
            put("tokens", JSONObject().also { t -> serviceTokens.forEach { (k, v) -> t.put(k, v) } })
        })
        put("saved_at", savedAt.epochSecond)
    }.toString()

    companion object {
        const val VERSION = 1

        /** @throws IllegalArgumentException when [json] is not a saved session this version understands. */
        fun fromJson(json: String): SavedSession = try {
            val o = JSONObject(json)
            require(o.getInt("version") == VERSION) { "unsupported saved-session version" }
            val ids = o.getJSONObject("ids")
            val info = o.optJSONObject("info") ?: JSONObject()
            val login = o.getJSONObject("login")
            val tokens = login.getJSONObject("tokens")
            SavedSession(
                username = o.getString("username"),
                localUserUuid = ids.getString("uid"),
                deviceId = ids.getString("devid"),
                cloudKitDeviceUuid = ids.getString("cloudkit_device_uuid"),
                accountName = info.optString("account_name").ifEmpty { null },
                firstName = info.optString("first_name").ifEmpty { null },
                lastName = info.optString("last_name").ifEmpty { null },
                dsid = login.getString("dsid"),
                adsid = login.optString("adsid").ifEmpty { null },
                idmsHb = login.optString("idms_hb").ifEmpty { null },
                serviceTokens = tokens.keys().asSequence().associateWith { tokens.getString(it) },
                savedAt = Instant.ofEpochSecond(o.getLong("saved_at")),
            )
        } catch (e: JSONException) {
            throw IllegalArgumentException("not a saved session")
        }
    }
}

/**
 * Persists the signed-in state through [SecretBlobs] (in the app: [SecretStore], AES-256-GCM under a Keystore key).
 * A blob that cannot be read or parsed reads as "no session": the user signs in again, nothing half-restores.
 */
class SessionStore(private val blobs: SecretBlobs, private val name: String = "apple_session.json") {
    fun save(session: SavedSession) = blobs.write(name, session.toJson().toByteArray(Charsets.UTF_8))

    fun load(): SavedSession? {
        val raw = blobs.read(name) ?: return null
        return try { SavedSession.fromJson(String(raw, Charsets.UTF_8)) } catch (_: IllegalArgumentException) { null } finally { raw.fill(0) }
    }

    fun clear() = blobs.delete(name)
}
