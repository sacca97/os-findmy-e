package com.sacca.openfinder.apple.reports

import org.json.JSONObject
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.TreeMap

/** An accessory JSON that is not what `FindMyAccessory.to_json` writes (missing field, bad hex, bad length, bad date). */
class AccessoryFormatException(message: String) : IllegalArgumentException(message)

/**
 * The secrets and bookkeeping of one findable accessory, with the official 15-minute key rollover (port of
 * `findmy.accessory.FindMyAccessory`, minus plist import, BLE advertising and the scanner helpers).
 *
 * Key `i` is `derive_ps_key(master, SK_i)` where `SK_0` is the shared secret and `SK_i = x963_kdf(SK_{i-1}, "update", 32)`.
 * The primary key at index `i` comes from SKN, secondary keys come from SKS at `i / 96 + 1` and `i / 96 + 2`.
 *
 * **Alignment** (`alignmentDate`, `alignmentIndex`) says which index the accessory was last seen at; it bounds the indices
 * to try for a time range. [updateAlignment] only moves forward, so a caller that fetches reports must persist the
 * accessory (see `TagKeyStore.put`) to keep it.
 *
 * Secrets: [masterKey], [skn], [sks] are credentials. [toString] shows none of them and the name is the only identifying
 * thing in it. Thread-safe: alignment and the key caches are guarded.
 */
class AccessoryKeys(
    masterKey: ByteArray,
    skn: ByteArray,
    sks: ByteArray,
    val pairedAt: OffsetDateTime,
    var name: String? = null,
    val model: String? = null,
    val identifier: String? = null,
    val groupIdentifier: String? = null,
    val serialNumber: String? = null,
    alignmentDate: OffsetDateTime? = null,
    alignmentIndex: Int? = null,
) {
    private val primary = RollingKeyGenerator(masterKey, skn, KeyPairType.PRIMARY)
    private val secondary = RollingKeyGenerator(masterKey, sks, KeyPairType.SECONDARY)
    private val lock = Any()

    private var alignDate: OffsetDateTime = alignmentDate ?: pairedAt
    private var alignIndex: Int = alignmentIndex ?: 0

    val masterKey: ByteArray get() = primary.masterKey.copyOf()
    val skn: ByteArray get() = primary.initialSk.copyOf()
    val sks: ByteArray get() = secondary.initialSk.copyOf()

    val alignmentDate: OffsetDateTime get() = synchronized(lock) { alignDate }
    val alignmentIndex: Int get() = synchronized(lock) { alignIndex }

    /**
     * A stable id for this accessory: its `identifier`, else a short digest of the secrets (so it can be used as a key
     * without exposing them; 8 bytes of SHA-256 do not allow recovering anything).
     */
    val id: String
        get() = identifier ?: MessageDigest.getInstance("SHA-256")
            .digest(masterKey + skn + sks).copyOf(8).joinToString("") { "%02x".format(it) }

    /** Lowest index the accessory could be at, at [dt]: it rolls over at most once per 15 minutes. */
    fun minIndex(dt: Instant): Int = synchronized(lock) {
        val align = alignDate.toInstant()
        if (dt >= align) return alignIndex
        (alignIndex - Duration.between(dt, align).dividedBy(INTERVAL)).toInt()
    }

    /** Highest index the accessory could be at, at [dt]. */
    fun maxIndex(dt: Instant): Int = synchronized(lock) {
        val align = alignDate.toInstant()
        if (dt <= align) return alignIndex
        (alignIndex + Duration.between(align, dt).dividedBy(INTERVAL)).toInt()
    }

    /** Ignores anything that goes backwards in time or index (`update_alignment`). Returns whether it moved. */
    fun updateAlignment(dt: Instant, index: Int): Boolean = synchronized(lock) {
        if (dt < alignDate.toInstant() || index < alignIndex) return false
        alignDate = dt.atOffset(ZoneOffset.UTC)
        alignIndex = index
        true
    }

    fun primaryKeyAt(index: Int): KeyPair = primary.keyAt(index)

    /** The two secondary keys that may be active at primary [index] (one is used after a reboot, the other after an hour). */
    fun secondaryKeysAt(index: Int): Pair<KeyPair, KeyPair> = secondary.keyAt(index / 96 + 1) to secondary.keyAt(index / 96 + 2)

    /** Primary and secondary keys that might be active at [index]; empty for a negative index (`keys_at`). */
    fun keysAt(index: Int): Set<KeyPair> {
        if (index < 0) return emptySet()
        val (s1, s2) = secondaryKeysAt(index)
        return linkedSetOf(primaryKeyAt(index), s1, s2)
    }

    /**
     * Keys that could be active from index [start] to [end] inclusive, each once, with the first index it occurs at
     * (`RollingKeyPairSource.keys_between`).
     */
    fun keysBetween(start: Int, end: Int): List<Pair<Int, KeyPair>> {
        val seen = HashSet<KeyPair>()
        val out = ArrayList<Pair<Int, KeyPair>>()
        for (i in start..end) for (key in keysAt(i)) if (seen.add(key)) out += i to key
        return out
    }

    /** Same, for a time range: from [minIndex] of [start] to [maxIndex] of [end]. */
    fun keysBetween(start: Instant, end: Instant): List<Pair<Int, KeyPair>> = keysBetween(minIndex(start), maxIndex(end))

    /** `FindMyAccessory.to_json`. */
    fun toJson(): JSONObject = JSONObject().apply {
        put("type", "accessory")
        put("master_key", hex(masterKey))
        put("skn", hex(skn))
        put("sks", hex(sks))
        put("paired_at", isoformat(pairedAt))
        put("name", name ?: JSONObject.NULL)
        put("model", model ?: JSONObject.NULL)
        put("identifier", identifier ?: JSONObject.NULL)
        put("group_identifier", groupIdentifier ?: JSONObject.NULL)
        put("serial_number", serialNumber ?: JSONObject.NULL)
        synchronized(lock) {
            put("alignment_date", isoformat(alignDate))
            put("alignment_index", alignIndex)
        }
    }

    override fun equals(other: Any?) =
        other is AccessoryKeys && masterKey.contentEquals(other.masterKey) && skn.contentEquals(other.skn) && sks.contentEquals(other.sks)

    override fun hashCode() = masterKey.contentHashCode() * 31 + skn.contentHashCode() * 17 + sks.contentHashCode()
    override fun toString() = "AccessoryKeys(name=$name, id=${identifier ?: "<derived>"}, secrets=<redacted>)"

    companion object {
        val INTERVAL: Duration = Duration.ofMinutes(15)

        /**
         * `FindMyAccessory.from_json`. Accepts what Python writes. `group_identifier` and `serial_number` may be absent (older
         * exports); a missing `name`, `model`, `identifier`, `alignment_date` or `alignment_index` is an error, as in Python.
         * A date without an offset is read in the system zone, as Python does.
         * @throws AccessoryFormatException never with key material in the message.
         */
        fun fromJson(json: JSONObject): AccessoryKeys {
            try {
                if (json.optString("type") != "accessory") throw AccessoryFormatException("not an accessory")
                for (field in listOf("master_key", "skn", "sks", "paired_at", "name", "model", "identifier", "alignment_date", "alignment_index")) {
                    if (!json.has(field)) throw AccessoryFormatException("missing field $field")
                }
                fun str(field: String): String? = if (json.isNull(field)) null else json.getString(field)
                val alignmentDate = str("alignment_date")?.let { parseIso(it) }
                return AccessoryKeys(
                    masterKey = unhex(json.getString("master_key")),
                    skn = unhex(json.getString("skn")),
                    sks = unhex(json.getString("sks")),
                    pairedAt = parseIso(json.getString("paired_at")),
                    name = str("name"),
                    model = str("model"),
                    identifier = str("identifier"),
                    groupIdentifier = str("group_identifier"),
                    serialNumber = str("serial_number"),
                    alignmentDate = alignmentDate,
                    alignmentIndex = if (json.isNull("alignment_index")) null else json.getInt("alignment_index"),
                )
            } catch (e: AccessoryFormatException) {
                throw e
            } catch (e: Exception) {
                throw AccessoryFormatException("invalid accessory JSON (${e.javaClass.simpleName})")
            }
        }

        fun fromJson(text: String): AccessoryKeys = fromJson(
            try { JSONObject(text) } catch (e: Exception) { throw AccessoryFormatException("invalid accessory JSON") },
        )

        /** `_extract_serial_from_stable_id`: the hardware serial in a plist `stableIdentifier` list, or null. */
        fun serialFromStableIdentifier(stable: List<String>?): String? {
            if (stable.isNullOrEmpty()) return null
            val first = stable[0]
            val tail = first.split("~#").last()
            if (tail.startsWith("¶")) {
                val sections = tail.split("§")
                if (sections.size >= 3) {
                    return try {
                        val raw = unhex(sections[2])
                        if (raw.any { it < 0 }) null else String(raw, Charsets.US_ASCII)
                    } catch (e: IllegalArgumentException) { null }
                }
                return null
            }
            return if (tail != first) tail else null
        }

        internal fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

        internal fun unhex(s: String): ByteArray {
            require(s.length % 2 == 0) { "odd hex" }
            return ByteArray(s.length / 2) {
                val hi = Character.digit(s[2 * it], 16)
                val lo = Character.digit(s[2 * it + 1], 16)
                require(hi >= 0 && lo >= 0) { "bad hex" }
                ((hi shl 4) or lo).toByte()
            }
        }

        /** Python's `datetime.isoformat()` for an aware datetime: `T`, microseconds only when non-zero, `+HH:MM`. */
        internal fun isoformat(dt: OffsetDateTime): String {
            val sb = StringBuilder()
            sb.append("%04d-%02d-%02dT%02d:%02d:%02d".format(dt.year, dt.monthValue, dt.dayOfMonth, dt.hour, dt.minute, dt.second))
            val micros = dt.nano / 1000
            if (micros != 0) sb.append(".%06d".format(micros))
            val total = dt.offset.totalSeconds
            val abs = Math.abs(total)
            sb.append(if (total < 0) '-' else '+').append("%02d:%02d".format(abs / 3600, abs / 60 % 60))
            if (abs % 60 != 0) sb.append(":%02d".format(abs % 60))
            return sb.toString()
        }

        /** `datetime.fromisoformat` for what `isoformat` writes (and `Z`, a space separator, date-only). */
        internal fun parseIso(text: String): OffsetDateTime {
            val s = if (text.length > 10 && text[10] == ' ') text.substring(0, 10) + "T" + text.substring(11) else text
            try { return OffsetDateTime.parse(s) } catch (_: Exception) { /* naive or unusual */ }
            val zone = ZoneId.systemDefault()
            try { return LocalDateTime.parse(s).atZone(zone).toOffsetDateTime() } catch (_: Exception) { /* date only? */ }
            try { return LocalDate.parse(s).atStartOfDay(zone).toOffsetDateTime() } catch (_: Exception) { /* give up */ }
            throw AccessoryFormatException("invalid date")
        }
    }
}

/**
 * Key generator of one kind (`_AccessoryKeyGenerator`): the secret-key chain `SK_i` with a two-tier checkpoint cache
 * (every 4th index up to 672 entries, every 672nd unbounded), so asking for index n+1 after n costs one KDF step, and a
 * small memo of derived key pairs (a secondary key serves 96 consecutive primary indices).
 */
internal class RollingKeyGenerator(val masterKey: ByteArray, val initialSk: ByteArray, private val type: KeyPairType) {
    init {
        require(masterKey.size == 28) { "The master key must be 28 bytes long" }
        require(initialSk.size == 32) { "The sk must be 32 bytes long" }
    }

    private class Tier(val interval: Int, val maxSize: Int?) { val cache = TreeMap<Int, ByteArray>() }

    private val tiers = listOf(Tier(4, 672), Tier(672, null))
    private val memo = HashMap<Int, KeyPair>()

    @Synchronized
    fun keyAt(index: Int): KeyPair {
        require(index >= 0) { "The key index must be non-negative" }
        memo[index]?.let { return it }
        val sk = skAt(index)
        val key = KeyPair(ReportCrypto.derivePsKey(masterKey, sk), type)
        if (memo.size >= MEMO_LIMIT) memo.clear()
        memo[index] = key
        return key
    }

    private fun skAt(index: Int): ByteArray {
        for (t in tiers) t.cache[index]?.let { return it }
        var bestInd = 0
        var bestSk = initialSk
        for (t in tiers) {
            val e = t.cache.lowerEntry(index) ?: continue
            if (e.key > bestInd) { bestInd = e.key; bestSk = e.value }
        }
        var cur = bestSk
        val update = "update".toByteArray(Charsets.US_ASCII)
        for (i in bestInd + 1..index) {
            cur = ReportCrypto.x963Kdf(cur, update, 32)
            remember(i, cur)
        }
        return cur
    }

    private fun remember(index: Int, sk: ByteArray) {
        for (t in tiers) {
            if (index % t.interval != 0 || t.cache.containsKey(index)) continue
            t.cache[index] = sk
            if (t.maxSize != null && t.cache.size > t.maxSize) {
                // A historical key evicts the smallest index, a newer one the largest (as the Python).
                if (index > t.cache.firstKey()) t.cache.pollFirstEntry() else t.cache.pollLastEntry()
            }
        }
    }

    private companion object { const val MEMO_LIMIT = 4096 }
}
