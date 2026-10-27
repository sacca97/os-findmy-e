package com.sacca.openfinder.apple

import android.content.Context
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import java.time.Clock

/** Where the time of the last HTTP 429 is remembered, so the memory survives restarts. */
interface CooldownStore {
    var last429EpochSeconds: Long?
}

class PrefsCooldownStore(context: Context) : CooldownStore {
    private val prefs = context.getSharedPreferences("apple_cooldown", Context.MODE_PRIVATE)
    override var last429EpochSeconds: Long?
        get() = if (prefs.contains("last429")) prefs.getLong("last429", 0) else null
        set(v) { prefs.edit().apply { if (v == null) remove("last429") else putLong("last429", v) }.apply() }
}

/**
 * One shared memory of Apple's HTTP 429 (as `tools/machoadi/cooldown.py`): after a 429 nothing is sent to Apple's
 * Grand Slam / MidService servers until [minutes] have passed. A 429 is a rate limit, not a verdict on this machine.
 */
class Cooldown(private val store: CooldownStore, private val clock: Clock = Clock.systemUTC(), private val minutes: Long = 45) {
    fun noteThrottled() { store.last429EpochSeconds = clock.instant().epochSecond }

    fun remainingSeconds(): Long {
        val seen = store.last429EpochSeconds ?: return 0
        return (seen + minutes * 60 - clock.instant().epochSecond).coerceAtLeast(0)
    }

    /** @throws OpenFinderException with [OpenFinderError.Throttled] during the cooldown. Nothing has been sent when it throws. */
    fun guard() {
        val left = remainingSeconds()
        if (left > 0) throw OpenFinderException(OpenFinderError.Throttled("Apple rate-limited this device. Wait about ${(left + 59) / 60} more minutes; nothing was sent."))
    }
}
