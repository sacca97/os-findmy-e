package com.sacca.openfinder.anisette

import org.json.JSONException
import org.json.JSONObject
import java.util.Base64

/** Who the machine says it is to Apple's servers (the HTTP side needs these next to the Anisette headers). */
data class MachineIdentity(
    val deviceId: String,
    val localUserUuid: String,
    val clientInfo: String,
    val serial: String?,
    val routing: Long?,
    /** Unix time of provisioning (seconds), when known: used to judge the machine's age. */
    val provisionedAt: Double? = null,
)

/**
 * A provisioned machine, as exchanged in `.machine.json` files (README, "Machine file"). It is a CREDENTIAL: the host UUID
 * and store together are the machine Apple knows. Never log it; [toString] redacts everything.
 */
class MachineFile(
    val hostUuid: ByteArray,
    val identity: MachineIdentity,
    /** The `CoreAdi.exportStore()` format; replaced after every call that changes the store. */
    val storeExport: ByteArray,
) {
    init {
        require(hostUuid.size == 16) { "host_uuid must be 16 bytes" }
    }

    fun withStore(newStore: ByteArray) = MachineFile(hostUuid, identity, newStore)

    fun toJson(): String = JSONObject().apply {
        put("version", 1)
        put("host_uuid", hostUuid.joinToString("") { "%02x".format(it) })
        put("identity", JSONObject().apply {
            put("device_id", identity.deviceId)
            put("local_user_uuid", identity.localUserUuid)
            put("client_info", identity.clientInfo)
            identity.serial?.let { put("serial", it) }
            identity.routing?.let { put("routing", it) }
            identity.provisionedAt?.let { put("provisioned_at", it) }
        })
        put("store_export_b64", Base64.getEncoder().encodeToString(storeExport))
    }.toString()

    override fun toString() = "MachineFile(<redacted>)"

    companion object {
        /** @throws IllegalArgumentException with a message that is safe to show (it never contains file contents). */
        fun parse(json: String): MachineFile {
            try {
                val o = JSONObject(json)
                require(o.optInt("version", -1) == 1) { "Unsupported machine file version" }
                val hex = o.getString("host_uuid")
                require(hex.length == 32 && hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) { "host_uuid must be 32 hex characters" }
                val uuid = ByteArray(16) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
                val id = o.getJSONObject("identity")
                val identity = MachineIdentity(
                    deviceId = id.getString("device_id"),
                    localUserUuid = id.getString("local_user_uuid"),
                    clientInfo = id.getString("client_info"),
                    serial = id.optString("serial").takeIf { it.isNotEmpty() },
                    routing = if (id.has("routing") && !id.isNull("routing")) id.getLong("routing") else null,
                    provisionedAt = if (id.has("provisioned_at") && !id.isNull("provisioned_at")) id.getDouble("provisioned_at") else null,
                )
                val store = try { Base64.getDecoder().decode(o.getString("store_export_b64")) } catch (e: IllegalArgumentException) {
                    throw IllegalArgumentException("store_export_b64 is not valid base64")
                }
                return MachineFile(uuid, identity, store)
            } catch (e: JSONException) {
                throw IllegalArgumentException("Not a valid machine file")
            }
        }
    }
}
