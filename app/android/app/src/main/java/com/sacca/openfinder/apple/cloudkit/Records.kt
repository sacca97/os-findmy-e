package com.sacca.openfinder.apple.cloudkit

import com.sacca.openfinder.apple.proto.cloudkit.Record
import com.sacca.openfinder.apple.proto.cloudkit.RecordChange

/**
 * Reading values out of CloudKit records (port of `findmy/cloudkit/records.py`: `iter_wire_fields`, `RecordField`,
 * `CloudKitRecord.from_proto`, `records_from_changes`). Decryption is [Pcs]; this stops where a key is needed.
 *
 * Deliberately not ported: `describe_wire`, `reference_name`, `named_fields`, `plain_value` (diagnostics and readers for
 * zones other than BeaconStore, which the read path never reaches).
 */
object WireFields {
    /** One top-level protobuf field: its number, wire type and (for length-delimited fields only) its payload. */
    class WireField(val number: Long, val wireType: Int, val payload: ByteArray)

    /** Walk a payload's top-level fields without a schema; stops (rather than throwing) when it runs off the end. */
    fun iterate(data: ByteArray): List<WireField> {
        val out = ArrayList<WireField>()
        var offset = 0
        fun varint(): Long? {
            var value = 0L
            var shift = 0
            while (true) {
                if (offset >= data.size) return null
                val b = data[offset].toInt() and 0xff
                offset++
                if (shift < 64) value = value or ((b and 0x7f).toLong() shl shift)
                if (b and 0x80 == 0) return value
                shift += 7
            }
        }
        while (offset < data.size) {
            val tag = varint() ?: return out
            val number = tag ushr 3
            when (val wire = (tag and 7).toInt()) {
                2 -> {
                    val length = varint() ?: return out
                    if (length < 0 || length > data.size - offset) return out
                    val payload = data.copyOfRange(offset, offset + length.toInt())
                    offset += length.toInt()
                    out += WireField(number, wire, payload)
                }
                0 -> {
                    while (offset < data.size && data[offset].toInt() and 0x80 != 0) offset++
                    offset++
                    out += WireField(number, wire, ByteArray(0))
                }
                5 -> { offset += 4; out += WireField(number, wire, ByteArray(0)) }
                1 -> { offset += 8; out += WireField(number, wire, ByteArray(0)) }
                else -> return out
            }
        }
        return out
    }
}

/** One named field of a record, before decryption. [valueType] describes the PLAINTEXT; branch on [isEncrypted]. */
class RecordField(
    val name: String,
    val valueType: Int,
    val isEncrypted: Boolean,
    /** Ciphertext if encrypted, otherwise the field's `bytes_value` if it had one. */
    val raw: ByteArray?,
    val value: Record.Value,
)

/** A record as fetched, fields indexed by name (`CloudKitRecord`). [zoneName] is authenticated with every field. */
class CloudKitRecord(
    val name: String,
    val zoneName: String,
    val recordType: String,
    val fields: Map<String, RecordField>,
    /** The DER protection structure, or null when the record carries none (then [pcsKey] picks a zone default). */
    val protectionInfo: ByteArray?,
    val etag: String,
    val protectionInfoTag: String = "",
    val pcsKey: ByteArray = ByteArray(0),
    val source: Record? = null,
) {
    internal fun withRecordType(type: String) =
        CloudKitRecord(name, zoneName, type, fields, protectionInfo, etag, protectionInfoTag, pcsKey, source)

    override fun toString() = "CloudKitRecord($name, $recordType, ${fields.size} field(s))"

    companion object {
        fun fromProto(record: Record, zoneName: String): CloudKitRecord {
            val fields = LinkedHashMap<String, RecordField>()
            for (field in record.recordFieldList) {
                val name = field.identifier.name
                val value = field.value
                val raw = if (value.hasBytesValue()) value.bytesValue.toByteArray() else null
                if (name.isEmpty()) continue   // Python logs and skips a nameless field
                fields[name] = RecordField(name, value.type, value.isEncrypted, raw, value)
            }
            val protection = if (record.hasProtectionInfo() && !record.protectionInfo.protectionInfo.isEmpty) {
                record.protectionInfo.protectionInfo.toByteArray()
            } else {
                null
            }
            return CloudKitRecord(
                name = record.recordIdentifier.value.name,
                zoneName = zoneName.ifEmpty { record.recordIdentifier.zoneIdentifier.value.name },
                recordType = record.type.name,
                fields = fields,
                protectionInfo = protection,
                etag = record.etag,
                protectionInfoTag = record.protectionInfo.protectionInfoTag,
                pcsKey = record.pcsKey.toByteArray(),
                source = record,
            )
        }

        /** Changes to records, dropping changes that carry no record (deletions); the change's type fills a missing one. */
        fun fromChanges(changes: Iterable<RecordChange>, zoneName: String = ""): List<CloudKitRecord> {
            val out = ArrayList<CloudKitRecord>()
            for (change in changes) {
                if (!change.hasRecord()) continue
                var record = fromProto(change.record, zoneName)
                if (record.recordType.isEmpty() && change.hasRecordType()) record = record.withRecordType(change.recordType.name)
                out += record
            }
            return out
        }
    }
}
