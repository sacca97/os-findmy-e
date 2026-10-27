package com.sacca.openfinder.anisette

import java.security.SecureRandom
import java.time.Instant

/**
 * Makes a fresh machine identity in the shapes Apple's own client uses (port of `mac_anisette._mint_identity`). The values
 * are minted, not read from hardware: the MID derives from the host UUID, so the identity is at least consistent with itself.
 */
object MachineMint {
    private const val UDID_PREFIX = "00006000"                       // a Mac's provisioning UDID: 8 hex, a dash, 16 hex
    private const val SERIAL_ALPHABET = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ" // 12 alphanumerics, no I or O

    fun hostUuid(random: SecureRandom = SecureRandom()): ByteArray = ByteArray(16).also(random::nextBytes)

    fun identity(random: SecureRandom = SecureRandom(), now: Instant = Instant.now()): MachineIdentity {
        fun hex(bytes: Int) = ByteArray(bytes).also(random::nextBytes).joinToString("") { "%02X".format(it) }
        return MachineIdentity(
            deviceId = "$UDID_PREFIX-${hex(8)}",
            localUserUuid = hex(16),
            clientInfo = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
            serial = "C02" + String(CharArray(9) { SERIAL_ALPHABET[random.nextInt(SERIAL_ALPHABET.length)] }),
            routing = null,
            provisionedAt = now.epochSecond.toDouble(),
        )
    }
}
