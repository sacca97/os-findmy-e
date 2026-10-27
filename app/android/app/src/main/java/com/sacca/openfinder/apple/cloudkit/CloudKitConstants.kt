package com.sacca.openfinder.apple.cloudkit

/**
 * CloudKit's wire constants (port of `findmy/cloudkit/constants.py`). Codes whose enumeration is incomplete are plain ints
 * so that an unknown value still reaches the caller as itself.
 */
object CloudKitConstants {
    const val SEARCHPARTY_CONTAINER = "com.apple.icloud.searchparty"
    const val SEARCHPARTY_BUNDLE = "com.apple.icloud.searchpartyd"
    const val BEACON_STORE_ZONE = "BeaconStore"

    /** Opening a container goes to the gateway; operations go to the URLs it hands back. */
    const val CK_APP_INIT_URL = "https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit"

    const val PATH_ZONE_RETRIEVE = "/api/client/zone/retrieve"
    const val PATH_RECORD_SYNC = "/api/client/record/sync"
    const val PATH_CODE_INVOKE = "/api/client/code/invoke"

    const val PROTOBUF_CONTENT_TYPE = "application/x-protobuf; " +
        "desc=\"https://gateway.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc\"; " +
        "messageType=RequestOperation; delimited=true"

    const val SYNC_STATUS_COMPLETE = 3
}

/** Which operation a request is; the number is also the RequestOperation field carrying it. Read operations only. */
object OperationType {
    const val ZONE_RETRIEVE = 201
    const val RECORD_RETRIEVE_CHANGES = 213
    const val FUNCTION_INVOKE = 1101
}

object ResultCode {
    const val SUCCESS = 1
    const val PARTIAL = 2
    const val FAILURE = 3
    const val INDETERMINATE = 4
}

/** Client-fault codes as far as they are known (`ClientErrorCode`). */
object ClientErrorCode {
    const val BAD_SYNTAX = 4
    const val FORBIDDEN = 5
    const val THROTTLED = 6
    const val NOT_SUPPORTED = 8
    const val EXISTS = 9
    const val BAD_AUTH_TOKEN = 11
    const val NEEDS_AUTHENTICATION = 12

    fun name(code: Int): String? = when (code) {
        BAD_SYNTAX -> "BAD_SYNTAX"
        FORBIDDEN -> "FORBIDDEN"
        THROTTLED -> "THROTTLED"
        NOT_SUPPORTED -> "NOT_SUPPORTED"
        EXISTS -> "EXISTS"
        BAD_AUTH_TOKEN -> "BAD_AUTH_TOKEN"
        NEEDS_AUTHENTICATION -> "NEEDS_AUTHENTICATION"
        else -> null
    }
}

/** What a field's PLAINTEXT is (not what is on the wire). */
object ValueType {
    const val BYTES = 1
    const val DATE = 2
    const val STRING = 3
    const val INT64 = 7
    const val DOUBLE = 8
    const val STRING_LIST = 15
    const val ENCRYPTED_BYTES = 20
}

/** Record types of the BeaconStore zone; wire strings, so an unlisted one passes through. */
object RecordType {
    const val MASTER_BEACON = "MasterBeaconRecord"
    const val BEACON_NAMING = "BeaconNamingRecord"
    const val KEY_ALIGNMENT = "KeyAlignmentRecord"
    const val SAFE_LOCATION = "SafeLocation"
}
