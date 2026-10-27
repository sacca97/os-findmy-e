package com.sacca.openfinder.apple

import okhttp3.OkHttpClient

/**
 * What the CloudKit and keychain code needs from a signed-in Apple account (the members `FindMy.py`'s `cloudkit/` and
 * `keychain/` modules read from `AsyncAppleAccount`). The login code implements it; those layers depend on this interface only.
 * Implementations never log or persist outside `SecretStore`; tokens are credentials.
 */
interface AppleAccountContext {
    val accountName: String
    val dsid: String
    val adsid: String

    /** CloudKit's device identifier: a real UUID (a Mac's `X-Mme-Device-Id` is not one). */
    val deviceUuid: String
    val clientInfo: String

    /** The machine's serial (`X-Apple-I-SRL-NO`); a different one registers a second device, so use this one everywhere. */
    val serial: String?

    /** Network timeout, seconds, for the calls made on behalf of this account. */
    val timeoutSeconds: Long
    val localUserUuid: String

    /** A service token by name (`searchPartyToken`, `cloudKitToken`, `mmeAuthToken`, ...), or null when the account has none. */
    suspend fun serviceToken(name: String): String?

    /** The Anisette header set for one request (X-Apple-I-MD, X-Apple-I-MD-M, ...). */
    suspend fun anisetteHeaders(): Map<String, String>

    /** A fresh password-escrow token (PET), renewing it when needed. */
    suspend fun requestPet(): String?

    val http: OkHttpClient
}
