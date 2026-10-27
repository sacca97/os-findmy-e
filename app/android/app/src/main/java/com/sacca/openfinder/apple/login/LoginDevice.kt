package com.sacca.openfinder.apple.login

import com.sacca.openfinder.anisette.MachineIdentity
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import java.util.UUID

/**
 * The device a client claims to be, in parts (port of `findmy.reports.anisette.DeviceIdentity`). The six values describe
 * one real release and move together; every client-info string and user agent is composed from here so no two requests
 * contradict each other about which machine is speaking.
 */
data class DeviceIdentity(
    val model: String,
    val osName: String,
    val osVersion: String,
    val osBuild: String,
    val cfnetwork: String,
    val darwin: String,
) {
    /** `<model> <os;version;build>`, the prefix every client-info string starts with. */
    val platform: String get() = "<$model> <$osName;$osVersion;$osBuild>"

    fun clientInfo(bundle: String): String = "$platform <$bundle>"

    fun userAgent(product: String): String = "$product CFNetwork/$cfnetwork Darwin/$darwin"

    companion object {
        /** `tools/machoadi/provider.py` `IDENTITY`: the release `mac_anisette.py` provisions under. */
        val MAC_13_1 = DeviceIdentity("MacBookPro13,2", "macOS", "13.1", "22C65", "1404.0.5", "22.2.0")

        /** Known releases: (os, version, build) -> (CFNetwork, Darwin). Only versions appear in user agents. */
        private val RELEASES = mapOf(
            Triple("macOS", "13.1", "22C65") to ("1404.0.5" to "22.2.0"),
            Triple("Mac OS X", "13.4.1", "22F8") to ("1408.0.4" to "22.5.0"),
        )

        /**
         * The identity behind a client-info string such as the machine file's
         * `<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>`. The CFNetwork and Darwin versions are
         * not in it; they come from the release table, and an unknown release is refused rather than guessed.
         */
        fun fromClientInfo(clientInfo: String): DeviceIdentity {
            val groups = Regex("<([^>]*)>").findAll(clientInfo).map { it.groupValues[1] }.toList()
            require(groups.size >= 2) { "client info has no <model> <os;version;build> prefix" }
            val os = groups[1].split(';')
            require(os.size == 3) { "client info OS group is not os;version;build" }
            val (cf, darwin) = RELEASES[Triple(os[0], os[1], os[2])]
                ?: throw IllegalArgumentException("unknown release ${os[0]} ${os[1]} (${os[2]}): add its CFNetwork/Darwin versions")
            return DeviceIdentity(groups[0], os[0], os[1], os[2], cf, darwin)
        }
    }
}

/** The bundles and agents the login speaks as (constants of `findmy.reports.account` and `anisette`). */
object LoginBundles {
    /** Grand Slam (`client_akd`). Apple's edge refuses `com.apple.dt.Xcode` on GsService2 since September 2026. */
    const val AKD = "com.apple.AuthKit/1 (com.apple.akd/1.0)"

    /** The library's `client`: used on the two-factor endpoints (`with_client_info=True`) and as the account's client info. */
    const val XCODE = "com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)"

    /** The mobileme delegate is logged into by accountsd. */
    const val ACCOUNTSD = "com.apple.AOSKit/282 (com.apple.accountsd/113)"
    const val ICLOUD_HELPER = "com.apple.iCloudHelper/282"

    /** Deliberately not composed from the identity (Python `_GSA_USER_AGENT`): every session so far was made under it. */
    const val GSA_USER_AGENT = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"

    /** Two-factor requests: Python sends these Xcode-flavoured values (see the report: unverified against today's edge). */
    const val TWO_FACTOR_USER_AGENT = "Xcode"
    const val TWO_FACTOR_APP_INFO = "com.apple.gs.xcode.auth"
    const val TWO_FACTOR_XCODE_VERSION = "11.2 (11B41)"
}

/**
 * Everything about this installation the login needs besides Anisette: the pair the machine was provisioned with
 * (`uid`/`devid` of `AsyncAppleAccount`, which must be the same pair the Anisette source sends), the serial, the identity,
 * and the identifier CloudKit wants.
 *
 * @property cloudKitDeviceUuid a real UUID for CloudKit (`tag_keys.for_cloudkit`): [deviceId] itself when it is one, else
 *   the machine's host UUID, dashed and uppercase. A Mac's provisioning UDID (`00006000-...`) is not a UUID.
 */
data class LoginDevice(
    val localUserUuid: String,
    val deviceId: String,
    val serial: String?,
    val identity: DeviceIdentity,
    val cloudKitDeviceUuid: String,
) {
    companion object {
        /** @throws OpenFinderException Backend when the machine's client info names a release this build does not know. */
        fun fromMachine(machine: MachineIdentity, hostUuid: ByteArray): LoginDevice = try {
            LoginDevice(
                localUserUuid = machine.localUserUuid,
                deviceId = machine.deviceId,
                serial = machine.serial,
                identity = DeviceIdentity.fromClientInfo(machine.clientInfo),
                cloudKitDeviceUuid = cloudKitUuid(machine.deviceId, hostUuid),
            )
        } catch (e: IllegalArgumentException) {
            throw OpenFinderException(OpenFinderError.Backend("The machine's identity cannot be used to sign in: ${e.message}"))
        }

        fun cloudKitUuid(deviceId: String, hostUuid: ByteArray?): String {
            try {
                if (deviceId.length == 36) return UUID.fromString(deviceId).toString().uppercase()
            } catch (_: IllegalArgumentException) { /* not a UUID: fall through to the host UUID */ }
            require(hostUuid != null && hostUuid.size == 16) { "the device id is not a UUID and no host UUID is known" }
            val h = GsaCrypto.hex(hostUuid)
            return "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}".uppercase()
        }
    }
}

/** Where the login sends its requests. Defaults are Apple's; tests point them at a local server. */
data class LoginEndpoints(
    val gsa: String = "https://gsa.apple.com/grandslam/GsService2",
    val loginDelegates: String = "https://setup.icloud.com/setup/iosbuddy/loginDelegates",
    val twoFactorMethods: String = "https://gsa.apple.com/auth",
    val smsRequest: String = "https://gsa.apple.com/auth/verify/phone",
    val smsSubmit: String = "https://gsa.apple.com/auth/verify/phone/securitycode",
    val trustedDeviceRequest: String = "https://gsa.apple.com/auth/verify/trusteddevice",
    val trustedDeviceSubmit: String = "https://gsa.apple.com/grandslam/GsService2/validate",
    /**
     * Hosts that refuse a second request on a connection they already answered (`util.http.NO_CONNECTION_REUSE_HOSTS`):
     * a pooled `complete` after `init` is answered 429. Requests to these hosts go through a client with no connection pool.
     */
    val noConnectionReuseHosts: Set<String> = setOf("gsa.apple.com"),
    /** Hosts the shared [com.sacca.openfinder.apple.Cooldown] guards (Grand Slam, as `GsaClient`); a 429 elsewhere starts no cooldown. */
    val cooldownHosts: Set<String> = setOf("gsa.apple.com"),
) {
    companion object {
        /** Apple's paths under another origin (for tests). */
        fun under(origin: String, noReuse: Set<String>): LoginEndpoints {
            val o = origin.trimEnd('/')
            return LoginEndpoints(
                "$o/grandslam/GsService2", "$o/setup/iosbuddy/loginDelegates", "$o/auth", "$o/auth/verify/phone",
                "$o/auth/verify/phone/securitycode", "$o/auth/verify/trusteddevice", "$o/grandslam/GsService2/validate", noReuse, noReuse,
            )
        }
    }
}

/** What a login attempt ended in. */
sealed interface LoginResult {
    data object SignedIn : LoginResult

    /** Apple wants a second factor. [methods] lists what can be offered; the trusted-device push comes first when available. */
    data class SecondFactorRequired(val methods: List<SecondFactorMethod>) : LoginResult
}

sealed interface SecondFactorMethod {
    /** A code pushed to the account's other Apple devices. */
    data object TrustedDevice : SecondFactorMethod

    /** A code by SMS to a trusted number. [phoneNumber] is Apple's masked display form; use it for display only. */
    data class Sms(val phoneNumberId: Long, val phoneNumber: String) : SecondFactorMethod
}

/** Python's `LoginState`, in order. */
enum class LoginState { LOGGED_OUT, REQUIRE_2FA, AUTHENTICATED, LOGGED_IN }

/** What `spd` says about the account holder (`_AccountInfo`). */
data class AccountInfo(val accountName: String?, val firstName: String?, val lastName: String?, val trustedDevice2fa: Boolean)

/**
 * What the report-fetch piece needs beyond [com.sacca.openfinder.apple.AppleAccountContext]: Python's `fetch_raw_reports`
 * answers a 401 by authenticating again and repeating the delegate exchange. Needs the password in memory
 * ([AppleAccount.providePassword] for a restored session).
 */
interface RefreshableAccount {
    suspend fun refreshSession()
}
