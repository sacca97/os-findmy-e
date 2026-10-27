package com.sacca.openfinder.domain

import java.time.Instant

enum class AccessoryType(val label: String, val emoji: String) {
    AIRTAG("AirTag", "📍"),
    KEYS("Keys", "🔑"),
    BAG("Bag", "🎒"),
    WALLET("Wallet", "👛"),
    BIKE("Bike", "🚲"),
    CAR("Car", "🚗"),
    PET("Pet", "🐾"),
    HEADPHONES("Headphones", "🎧"),
    LAPTOP("Laptop", "💻"),
    OTHER("Accessory", "🏷️"),
}

/** One report of where an accessory was seen. This is a cached sighting, never live tracking. */
data class LocationReport(
    val accessoryId: String,
    val latitude: Double,
    val longitude: Double,
    val observedAt: Instant,
    /** Horizontal accuracy in meters, when the report has one. */
    val horizontalAccuracyMeters: Double? = null,
    /** Extra metadata a backend may attach (confidence, status byte, ...). */
    val metadata: Map<String, String> = emptyMap(),
) {
    /** Coordinates are finite and on Earth, the timestamp is not in the future (clock skew allowed). */
    fun isValid(now: Instant = Instant.now()): Boolean =
        latitude.isFinite() && longitude.isFinite() &&
            latitude in -90.0..90.0 && longitude in -180.0..180.0 &&
            !(latitude == 0.0 && longitude == 0.0) &&
            observedAt.isBefore(now.plusSeconds(300)) &&
            (horizontalAccuracyMeters == null || (horizontalAccuracyMeters.isFinite() && horizontalAccuracyMeters >= 0))
}

data class Accessory(
    val id: String,
    val name: String,
    val type: AccessoryType = AccessoryType.OTHER,
    val latestReport: LocationReport? = null,
)

sealed interface AuthState {
    data object SignedOut : AuthState
    data object AuthenticationRequired : AuthState
    data class TwoFactorRequired(val challengeId: String) : AuthState
    data object Authenticated : AuthState
    data object SessionExpired : AuthState
}

sealed interface AuthResult {
    data object Success : AuthResult
    data class TwoFactorRequired(val challengeId: String) : AuthResult
    data class Failure(val error: OpenFinderError) : AuthResult
}

/** Typed failures every backend reports; the UI maps them to messages, never to stack traces. */
sealed interface OpenFinderError {
    val message: String

    data class Network(override val message: String = "Can't reach Apple. Check your connection.") : OpenFinderError
    data class AccountRestricted(override val message: String = "This account can't use OpenFinder accessories.") : OpenFinderError
    data class Authentication(override val message: String = "Sign in to see your accessories.") : OpenFinderError
    /** Grand Slam refused an SRP step, with Apple's status fields retained for diagnosis. */
    data class GrandSlamRefused(
        val step: GrandSlamStep,
        val ec: Long?,
        val em: String?,
        override val message: String,
    ) : OpenFinderError {
        val beforePassword: Boolean get() = step == GrandSlamStep.INIT
    }
    data class Backend(override val message: String = "Something went wrong in the OpenFinder backend.") : OpenFinderError
    data class ReportsUnavailable(override val message: String = "No recent reports are available yet.") : OpenFinderError
    /** Apple answered HTTP 429: usually an inconsistent request or connection state (see GSA-LOGIN-TRANSPORT.md), not a rate limit. */
    data class Throttled(override val message: String = "Apple answered HTTP 429 (an inconsistent state, not a rate limit). Try again.") : OpenFinderError
    /** Apple understood the request and refused it (`ec`/`em` are Apple's own status). */
    data class Rejected(val http: Int, val ec: Long?, override val message: String) : OpenFinderError
    data class NotImplemented(override val message: String = "Not available in this build yet.") : OpenFinderError
}

enum class GrandSlamStep { INIT, COMPLETE }

class OpenFinderException(val error: OpenFinderError) : Exception(error.message)
