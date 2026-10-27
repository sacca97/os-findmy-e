package com.sacca.openfinder.domain

/** One iCloud device whose screen-lock passcode can unlock the account's keychain (a recovery record). */
data class RecoveryRecord(val index: Int, val description: String)

/**
 * What a live backend needs beyond [OpenFinderBackend] before it has any accessories: the machine, and the accessories' keys.
 * Kept apart from [OpenFinderBackend] because the demo backend has no use for it. Secrets (password, passcode) are passed as
 * [CharArray] and zeroed by the implementation after use.
 */
interface AccountSetup {
    suspend fun hasMachine(): Boolean
    suspend fun hasAccessories(): Boolean

    /** True when the library no longer holds the Apple password (after a restart): only then must the user type it again. */
    suspend fun needsPassword(): Boolean

    /** CONTACTS APPLE: registers a new made-up machine. One provisioning per device id. */
    suspend fun provisionMachine()

    /** Lists the devices whose passcode can unlock the keychain. [password] is only needed when the session lacks it. */
    suspend fun recoveryRecords(password: CharArray?): List<RecoveryRecord>

    /** Sends ONE passcode guess (never retried), reads the BeaconStore and stores the accessories' keys (encrypted). */
    suspend fun discoverAccessories(index: Int, passcode: CharArray, password: CharArray?): Int

    /** Imports accessory keys (a JSON array in the `FindMyAccessory.to_json` format), e.g. made by `findmy beacons`. */
    suspend fun importAccessories(json: String): Int
}
