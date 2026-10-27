package com.sacca.openfinder.apple.cloudkit

import java.time.Instant

/**
 * One accessory read out of the owner's BeaconStore: exactly the arguments `beacons.accessory_from_record` passes to
 * `FindMyAccessory(...)`. The reports piece's `AccessoryKeys` is built from this by integration (this package does not
 * depend on it).
 *
 * Python's `FindMyAccessory` fills two defaults itself, which are left to the adapter here: a null [alignmentDate] means
 * "start from [pairedAt]" and a null [alignmentIndex] means 0.
 *
 * [masterKey], [skn] and [sks] are secrets: [toString] is redacted, and [wipe] zeroes them once they have been handed on.
 */
class DecryptedAccessory(
    /** The last 28 bytes of the record's `privateKey` (the P-224 master scalar). */
    val masterKey: ByteArray,
    /** `sharedSecret`: the primary key chain's initial SK. */
    val skn: ByteArray,
    /** `sharedSecret2`, or an iDevice's `secureLocationsSharedSecret`: the secondary chain's initial SK. */
    val sks: ByteArray,
    val pairedAt: Instant,
    /** From the joined `BeaconNamingRecord`, when there is one. */
    val name: String?,
    val model: String?,
    /** The MasterBeaconRecord's own record name. */
    val identifier: String,
    val groupIdentifier: String?,
    /** Parsed out of `stableIdentifier` (`_extract_serial_from_stable_id`). */
    val serialNumber: String?,
    /** From the joined `KeyAlignmentRecord` (`lastIndexObservationDate`), only when both of its values are readable. */
    val alignmentDate: Instant?,
    /** `lastIndexObserved`, paired with [alignmentDate]. */
    val alignmentIndex: Long?,
) {
    fun wipe() {
        masterKey.fill(0)
        skn.fill(0)
        sks.fill(0)
    }

    override fun toString() =
        "DecryptedAccessory(identifier=$identifier, name=$name, model=$model, serial=$serialNumber, pairedAt=$pairedAt, " +
            "alignment=$alignmentIndex@$alignmentDate, keys=<redacted>)"
}
