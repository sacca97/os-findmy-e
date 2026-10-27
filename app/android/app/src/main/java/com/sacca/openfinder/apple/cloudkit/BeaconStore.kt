package com.sacca.openfinder.apple.cloudkit

import com.google.protobuf.InvalidProtocolBufferException
import com.sacca.openfinder.apple.proto.cloudkit.EncryptedValue
import com.sacca.openfinder.apple.proto.cloudkit.RecordChange
import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import kotlinx.coroutines.flow.toList
import java.security.interfaces.ECPrivateKey
import java.time.Clock
import java.time.Duration
import java.time.Instant

/** A decrypted record cannot be turned into what it should hold (`beacons.BeaconExportError`). */
class BeaconExportException(message: String) : PcsException(message)

/**
 * A record whose fields were decrypted and interpreted. [values] hold, by the field's declared type: `ByteArray` (bytes and
 * encrypted-bytes fields, and unencrypted fields' `bytes_value`, null when they had none), `String`, `Long`, `Instant`
 * (dates), `Double`, or the raw [EncryptedValue] for a type this does not model. [undecryptable] names every field that could
 * not be read, never silently dropped. Holds secrets: [wipe] when done.
 */
class DecryptedRecord(
    val name: String,
    val recordType: String,
    val values: Map<String, Any?>,
    val rawValues: Map<String, ByteArray> = emptyMap(),
    val undecryptable: Map<String, String> = emptyMap(),
) {
    fun wipe() {
        values.values.forEach { (it as? ByteArray)?.fill(0) }
        rawValues.values.forEach { it.fill(0) }
    }

    override fun toString() = "DecryptedRecord($name, $recordType, fields=${values.keys}, undecryptable=${undecryptable.keys})"
}

/**
 * The records that decrypted, with what did not: [skipped] counts by reason (a record type not wanted, `no key held`,
 * `would not decrypt`) and [firstMiss] is the first "no key held" in full (`beacons.DecryptedRecords`).
 */
class DecryptedRecords(
    val records: List<DecryptedRecord>,
    val skipped: Map<String, Int> = emptyMap(),
    val firstMiss: String? = null,
) : List<DecryptedRecord> by records {
    val skippedTotal: Int get() = skipped.values.sum()
    fun wipe() = records.forEach { it.wipe() }
}

/** One master beacon with the naming and alignment records that join to it (either may be absent). */
class RecordGroup(val beacon: DecryptedRecord, val naming: DecryptedRecord? = null, val alignment: DecryptedRecord? = null)

/**
 * Find My accessories read from the owner's iCloud BeaconStore zone (port of the read path of `findmy/cloudkit/beacons.py`:
 * `AsyncBeaconStore.fetch_records`, `zone_keys`, `zone_record_defaults`, `fetch_accessories`, and the module functions
 * `decrypt_records`, `group_records`, `can_be_located`, `accessories_from_records`). Read-only: nothing here saves, renames or
 * deletes (`save_naming_record`, `find_naming_record`, `build_plaintext` and the plist renderers are not ported).
 *
 * The call sequence is `tools/machoadi/tag_keys.py`'s `read_accessories`: [zoneKeys] with the keychain's PCS keys, then
 * [fetchRecords], [decryptRecords] with [zoneRecordDefaults], then [groupRecords] / [accessoriesFromRecords].
 *
 * Deliberate differences from the Python: a record whose protection structure is not DER is counted as "would not decrypt"
 * (Python's `DerError` escapes `decrypt_records` and aborts the whole fetch); untyped records are counted correctly under
 * `<untyped>` (Python's counter never passes 1); error messages about fields never quote their plaintext; a non-string
 * `name`/`model`/`groupIdentifier` becomes null rather than being passed through.
 */
class BeaconStore(private val client: CloudKitApi, private val clock: Clock = Clock.systemUTC()) : AutoCloseable {

    /** Every record in the BeaconStore zone, still encrypted. Needs no keychain state. */
    suspend fun fetchRecords(continuationToken: ByteArray? = null): List<CloudKitRecord> {
        val changes: List<RecordChange> = client.iterRecords(CloudKitConstants.BEACON_STORE_ZONE, continuationToken).toList()
        return CloudKitRecord.fromChanges(changes, CloudKitConstants.BEACON_STORE_ZONE)
    }

    /**
     * §4 step 0: unwrap the zone's protection structure with the keychain PCS keys into the keys its records name.
     * @throws OpenFinderException [OpenFinderError.Backend] when the zone is absent, unprotected, or not openable with [serviceKeys].
     */
    suspend fun zoneKeys(serviceKeys: List<ECPrivateKey>): List<PcsKey> = zoneKeysFrom(serviceKeys.map { PcsKey.of(it) })

    /** [zoneKeys] for keys already in this package's form. */
    suspend fun zoneKeysFrom(serviceKeys: List<PcsKey>): List<PcsKey> {
        val zones = client.zoneRetrieve()
        val protection = zones.firstOrNull {
            it.targetZone.zoneIdentifier.value.name == CloudKitConstants.BEACON_STORE_ZONE && it.targetZone.hasProtectionInfo()
        }?.targetZone?.protectionInfo?.protectionInfo
        if (protection == null || protection.isEmpty) {
            val names = zones.joinToString(", ") { it.targetZone.zoneIdentifier.value.name.ifEmpty { "<unnamed>" } }
            throw OpenFinderException(OpenFinderError.Backend("The BeaconStore zone carries no protection structure. Zones retrieved: ${names.ifEmpty { "none" }}"))
        }
        return try {
            Pcs.unwrapZone(protection.toByteArray(), serviceKeys)
        } catch (e: MissingKeyException) {
            throw OpenFinderException(OpenFinderError.Backend("The keychain keys do not open the BeaconStore zone. ${e.message}"))
        } catch (e: PcsException) {
            throw OpenFinderException(OpenFinderError.Backend("The BeaconStore zone's protection could not be unwrapped: ${e.message}"))
        } catch (e: DerException) {
            throw OpenFinderException(OpenFinderError.Backend("The BeaconStore zone's protection is not well-formed DER: ${e.message}"))
        }
    }

    /** The zone's `recordProtectionInfo` default keys, or empty when it has none or it does not unwrap ([observed] absent). */
    suspend fun zoneRecordDefaults(zoneKeys: List<PcsKey>): List<ByteArray> {
        val zone = client.zoneRetrieve().firstOrNull { it.targetZone.zoneIdentifier.value.name == CloudKitConstants.BEACON_STORE_ZONE }
        val info = zone?.targetZone?.recordProtectionInfo?.protectionInfo
        if (info == null || info.isEmpty) return emptyList()
        return try {
            Pcs.unwrapZoneRecordDefaults(info.toByteArray(), zoneKeys)
        } catch (e: PcsException) {
            emptyList()
        } catch (e: DerException) {
            emptyList()
        }
    }

    /** `fetch_accessories`: the whole read path in one call. */
    suspend fun fetchAccessories(serviceKeys: List<ECPrivateKey>, continuationToken: ByteArray? = null): List<DecryptedAccessory> {
        val keys = zoneKeys(serviceKeys)
        val records = fetchRecords(continuationToken)
        val decrypted = decryptRecords(records, keys, zoneRecordDefaults(keys), clock)
        try {
            return accessoriesFromRecords(decrypted)
        } finally {
            decrypted.wipe()
        }
    }

    override fun close() = client.close()

    companion object {
        private val APPLE_EPOCH: Instant = Instant.parse("2001-01-01T00:00:00Z")
        private val EARLIEST: Instant = Instant.parse("2019-01-01T00:00:00Z")
        private const val MASTER_KEY_TAIL = 28
        private val WANTED = setOf(RecordType.MASTER_BEACON, RecordType.BEACON_NAMING, RecordType.KEY_ALIGNMENT)
        private val PRIVACY_SENSITIVE = setOf(RecordType.SAFE_LOCATION)

        /**
         * A decrypted date's double as a moment: CloudKit's 2001 epoch, else the Unix epoch, whichever lands between 2019 and
         * tomorrow (`_as_datetime`). Microsecond rounding follows Python's `timedelta(seconds=x)`.
         */
        fun asInstant(seconds: Double, clock: Clock = Clock.systemUTC()): Instant {
            val latest = clock.instant().plus(Duration.ofDays(1))
            if (seconds.isFinite() && kotlin.math.abs(seconds) < 1e14) {
                val whole = if (seconds < 0) kotlin.math.ceil(seconds) else kotlin.math.floor(seconds)
                val micros = whole.toLong() * 1_000_000L + Math.rint((seconds - whole) * 1e6).toLong()
                for (epoch in listOf(APPLE_EPOCH, Instant.EPOCH)) {
                    val moment = epoch.plusSeconds(Math.floorDiv(micros, 1_000_000L)).plusNanos(Math.floorMod(micros, 1_000_000L) * 1000L)
                    if (!moment.isBefore(EARLIEST) && !moment.isAfter(latest)) return moment
                }
            }
            throw BeaconExportException("Decrypted date is not a plausible pairing time under either epoch.")
        }

        /** A decrypted field's bytes as the value its declared type promises (`interpret_plaintext`). */
        fun interpretPlaintext(valueType: Int, data: ByteArray, clock: Clock = Clock.systemUTC()): Any {
            if (valueType == ValueType.BYTES || valueType == ValueType.ENCRYPTED_BYTES) return data
            val wrapper = try {
                EncryptedValue.parseFrom(data)
            } catch (e: InvalidProtocolBufferException) {
                throw BeaconExportException("Decrypted field is not an EncryptedValue")
            }
            return when (valueType) {
                ValueType.STRING -> if (wrapper.hasStringValue()) wrapper.stringValue else throw BeaconExportException("Field declares STRING_TYPE but its plaintext carries no string")
                ValueType.INT64 -> if (wrapper.hasSignedValue()) wrapper.signedValue else throw BeaconExportException("Field declares INT64_TYPE but its plaintext carries no integer")
                ValueType.DATE -> if (wrapper.hasDateValue()) asInstant(wrapper.dateValue.time, clock) else throw BeaconExportException("Field declares DATE_TYPE but its plaintext carries no date")
                ValueType.DOUBLE -> if (wrapper.hasDateValue()) wrapper.dateValue.time else wrapper.signedValue.toDouble()
                else -> wrapper
            }
        }

        /** Decrypt every encrypted field of one record (`decrypt_record`). */
        fun decryptRecord(
            record: CloudKitRecord,
            privateKeys: List<PcsKey>,
            defaultMasterKeys: List<ByteArray> = emptyList(),
            clock: Clock = Clock.systemUTC(),
            allowPrivacySensitive: Boolean = false,
        ): DecryptedRecord {
            if (record.recordType in PRIVACY_SENSITIVE && !allowPrivacySensitive) {
                throw BeaconExportException("Refusing to decrypt a ${record.recordType} record: it holds the user's own locations.")
            }
            val protection = record.protectionInfo ?: return decryptWithZoneDefault(record, defaultMasterKeys, clock)
            return decryptFields(record, Pcs.unwrapProtection(ShareProtection.fromDer(protection), privateKeys), clock)
        }

        private fun decryptWithZoneDefault(record: CloudKitRecord, defaults: List<ByteArray>, clock: Clock): DecryptedRecord {
            if (defaults.isEmpty()) {
                throw BeaconExportException("Record ${record.name} carries no protection info of its own, and the zone offered no recordProtectionInfo to fall back on.")
            }
            val masterKey = Pcs.selectDefaultMasterKey(defaults, record.pcsKey)
                ?: throw MissingKeyException("Record ${record.name} carries no protection info, and its pcsKey names none of the ${defaults.size} default record key(s) the zone offered.")
            return decryptFields(record, UnwrappedProtection.bare(masterKey), clock)
        }

        private fun decryptFields(record: CloudKitRecord, unwrapped: UnwrappedProtection, clock: Clock): DecryptedRecord {
            val values = LinkedHashMap<String, Any?>()
            val raw = LinkedHashMap<String, ByteArray>()
            val undecryptable = LinkedHashMap<String, String>()
            for ((name, field) in record.fields) {
                if (!field.isEncrypted) { values[name] = field.raw; continue }
                val ciphertext = field.raw
                if (ciphertext == null) { undecryptable[name] = "encrypted but carried no bytes"; continue }
                val plaintext = try {
                    Pcs.decryptField(ciphertext, unwrapped, FieldContext(record.zoneName, record.name, name))
                } catch (e: PcsException) {
                    undecryptable[name] = e.message ?: "did not decrypt"
                    continue
                }
                raw[name] = plaintext
                try {
                    values[name] = interpretPlaintext(field.valueType, plaintext, clock)
                } catch (e: BeaconExportException) {
                    undecryptable[name] = e.message ?: "did not interpret"
                }
            }
            return DecryptedRecord(record.name, record.recordType, values, raw, undecryptable)
        }

        /** Decrypt the records worth decrypting, and count rather than hide what was skipped (`decrypt_records`). */
        fun decryptRecords(
            records: Iterable<CloudKitRecord>,
            privateKeys: List<PcsKey>,
            defaultMasterKeys: List<ByteArray> = emptyList(),
            clock: Clock = Clock.systemUTC(),
        ): DecryptedRecords {
            val out = ArrayList<DecryptedRecord>()
            val skipped = LinkedHashMap<String, Int>()
            var firstMiss: String? = null
            fun skip(reason: String) { skipped[reason] = (skipped[reason] ?: 0) + 1 }
            for (record in records) {
                if (record.recordType !in WANTED) { skip(record.recordType.ifEmpty { "<untyped>" }); continue }
                try {
                    out += decryptRecord(record, privateKeys, defaultMasterKeys, clock)
                } catch (e: MissingKeyException) {
                    skip("no key held")
                    if (firstMiss == null) firstMiss = e.message
                } catch (e: PcsException) {
                    skip("would not decrypt")
                } catch (e: DerException) {
                    skip("would not decrypt")
                }
            }
            return DecryptedRecords(out, skipped, firstMiss)
        }

        /** Join beacons with their naming (`associatedBeacon`) and alignment (`beaconIdentifier`) records; last one wins. */
        fun groupRecords(records: Iterable<DecryptedRecord>): List<RecordGroup> {
            val list = records.toList()
            val naming = HashMap<String, DecryptedRecord>()
            val alignment = HashMap<String, DecryptedRecord>()
            for (r in list) {
                if (r.recordType == RecordType.BEACON_NAMING) (r.values["associatedBeacon"] as? String)?.let { naming[it] = r }
                if (r.recordType == RecordType.KEY_ALIGNMENT) (r.values["beaconIdentifier"] as? String)?.let { alignment[it] = r }
            }
            return list.filter { it.recordType == RecordType.MASTER_BEACON }.map { RecordGroup(it, naming[it.name], alignment[it.name]) }
        }

        /** The one test: a beacon with a readable `privateKey` can be located; one without is a device, not a tag. */
        fun canBeLocated(beacon: DecryptedRecord): Boolean = beacon.values["privateKey"] is ByteArray

        /** One decrypted MasterBeaconRecord (plus companions) as an accessory (`accessory_from_record`). */
        fun accessoryFromRecord(beacon: DecryptedRecord, naming: DecryptedRecord? = null, alignment: DecryptedRecord? = null): DecryptedAccessory {
            val values = beacon.values
            val privateKey = values["privateKey"] as? ByteArray ?: throw BeaconExportException("Record ${beacon.name} has no readable privateKey")
            val skn = values["sharedSecret"] as? ByteArray ?: throw BeaconExportException("Record ${beacon.name} has no readable sharedSecret")
            val first = values["sharedSecret2"]
            val sks = (if (pyTruthy(first)) first else values["secureLocationsSharedSecret"]) as? ByteArray
                ?: throw BeaconExportException("Record ${beacon.name} has neither sharedSecret2 nor secureLocationsSharedSecret")
            val pairedAt = values["pairingDate"] as? Instant ?: throw BeaconExportException("Record ${beacon.name} has no readable pairingDate")
            val serial = (values["stableIdentifier"] as? String)?.let { extractSerial(it) }
            var alignmentDate: Instant? = null
            var alignmentIndex: Long? = null
            if (alignment != null) {
                val observed = alignment.values["lastIndexObservationDate"]
                val index = alignment.values["lastIndexObserved"]
                if (observed is Instant && index is Long) { alignmentDate = observed; alignmentIndex = index }
            }
            return DecryptedAccessory(
                masterKey = privateKey.copyOfRange(maxOf(0, privateKey.size - MASTER_KEY_TAIL), privateKey.size),
                skn = skn.copyOf(),
                sks = sks.copyOf(),
                pairedAt = pairedAt,
                name = naming?.values?.get("name") as? String,
                model = values["model"] as? String,
                identifier = beacon.name,
                groupIdentifier = values["groupIdentifier"] as? String,
                serialNumber = serial,
                alignmentDate = alignmentDate,
                alignmentIndex = alignmentIndex,
            )
        }

        /** Locatable beacons as accessories; one that cannot be assembled is skipped, not fatal (`accessories_from_records`). */
        fun accessoriesFromRecords(records: Iterable<DecryptedRecord>): List<DecryptedAccessory> =
            groupRecords(records).filter { canBeLocated(it.beacon) }.mapNotNull { group ->
                try {
                    accessoryFromRecord(group.beacon, group.naming, group.alignment)
                } catch (e: BeaconExportException) {
                    null
                }
            }

        /**
         * The hardware serial in a `stableIdentifier` (`accessory._extract_serial_from_stable_id`, for CloudKit's single string):
         * the tail after the last `~#`, or for AirPods-style `¶model§hwid§<hex serial>§pos` tails the hex-decoded third section.
         */
        fun extractSerial(stable: String): String? {
            if (stable.isEmpty()) return null
            val tail = stable.split("~#").last()
            if (tail.startsWith("¶")) {
                val sections = tail.split("§")
                if (sections.size < 3) return null
                val bytes = pyFromHex(sections[2]) ?: return null
                if (bytes.any { it < 0 }) return null
                return String(bytes, Charsets.US_ASCII)
            }
            return if (tail != stable) tail else null
        }

        /** Python's `bytes.fromhex`: hex pairs, ASCII whitespace allowed between (never inside) pairs. */
        private fun pyFromHex(s: String): ByteArray? {
            val out = java.io.ByteArrayOutputStream()
            var i = 0
            while (i < s.length) {
                if (s[i] in " \t\n\r\u000b\u000c") { i++; continue }
                if (i + 1 >= s.length) return null
                val hi = Character.digit(s[i], 16)
                val lo = Character.digit(s[i + 1], 16)
                if (hi < 0 || lo < 0 || s[i].code > 127 || s[i + 1].code > 127) return null
                out.write(hi * 16 + lo)
                i += 2
            }
            return out.toByteArray()
        }

        private fun pyTruthy(v: Any?): Boolean = when (v) {
            null -> false
            is ByteArray -> v.isNotEmpty()
            is String -> v.isNotEmpty()
            is Long -> v != 0L
            is Double -> v != 0.0
            else -> true
        }
    }
}
