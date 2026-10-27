package com.sacca.openfinder.apple.cloudkit

import com.sacca.openfinder.apple.proto.cloudkit.RecordChange
import com.sacca.openfinder.apple.proto.cloudkit.ZoneSummary
import kotlinx.coroutines.flow.Flow

/**
 * The narrow seam between the CloudKit client (`cloudkit/CloudKitClient.kt`) and everything that talks through it: the
 * BeaconStore and the keychain trust circle (Cuttlefish and securityd are reached with [functionInvoke]). It mirrors the
 * public async methods of `findmy.cloudkit.client.AsyncCloudKitClient` one for one; the read-only subset is enough here
 * (the write operation `record_save` is deliberately not part of the app).
 *
 * Failures are `OpenFinderException`s (see `domain/Models.kt`); an HTTP or CloudKit result error carries Apple's own code.
 */
interface CloudKitApi : AutoCloseable {
    /** Learns this account's CloudKit user id and service URLs. Cheap, no side effects; call it first. */
    suspend fun openContainer(refresh: Boolean = false): CloudKitContainerInfo

    /** The zones the container holds. */
    suspend fun zoneRetrieve(): List<ZoneSummary>

    /** One page of record changes from a zone; persist [RecordSyncPage.continuationToken] to resume. */
    suspend fun recordSync(zoneName: String, continuationToken: ByteArray? = null, maxChanges: Int? = null): RecordSyncPage

    /** Every record change in a zone, page by page until the server says the zone is fully synced (or [maxPages]). */
    fun iterRecords(zoneName: String, continuationToken: ByteArray? = null, maxPages: Int = 100): Flow<RecordChange>

    /** Calls a server-side function and returns its serialised result (how Cuttlefish and securityd are reached). */
    suspend fun functionInvoke(service: String, name: String, parameters: ByteArray): ByteArray
}

/** Where CloudKit lives for this account (iCloud partitions accounts across numbered hosts: never hardcode these). */
class CloudKitContainerInfo(
    val userId: String,
    val databaseUrl: String?,
    val databaseGatewayUrl: String?,
    val codeGatewayUrl: String?,
    val shareGatewayUrl: String?,
    val raw: Map<String, Any?>,
) {
    /** The account's iCloud partition, as the bare number of a `p<N>-` host prefix (other services are `p<N>-<service>.icloud.com`). */
    val partition: String?
        get() {
            for (url in listOf(databaseUrl, raw["cloudKitShareUrl"] as? String)) {
                if (url.isNullOrEmpty()) continue
                val host = url.substringAfter("://").substringBefore('/')
                if (host.startsWith("p") && '-' in host) {
                    val candidate = host.drop(1).substringBefore('-')
                    if (candidate.isNotEmpty() && candidate.all { it.isDigit() }) return candidate
                }
            }
            return null
        }
}

/** One page of record changes, the token that continues from it, and its status. */
class RecordSyncPage(
    val changes: List<RecordChange>,
    val continuationToken: ByteArray?,
    val status: Int?,
) {
    /** Whether this page finished the zone (a page with changes can still be the last; an empty page is not the signal). */
    val complete: Boolean get() = status == SYNC_STATUS_COMPLETE

    companion object { const val SYNC_STATUS_COMPLETE = 3 }
}
