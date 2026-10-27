package com.sacca.openfinder.apple.cloudkit

import com.sacca.openfinder.apple.cloudkit.CkFixtures.hex
import com.sacca.openfinder.apple.cloudkit.CkFixtures.keyJson
import com.sacca.openfinder.apple.proto.cloudkit.RecordChange
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Record shapes (`findmy.cloudkit.records`) and the private-key CHOICE reader (`findmy.keychain.servicekey`), against
 * fixtures/cloudkit/{records,servicekeys}.json.
 */
class RecordsOracleTest {
    private val records = CkFixtures.json("records.json")
    private val serviceKeys = CkFixtures.json("servicekeys.json")

    private fun assertRecord(e: JSONObject, a: CloudKitRecord) {
        assertEquals(e.getString("name"), a.name)
        assertEquals(a.name, e.getString("zone_name"), a.zoneName)
        assertEquals(a.name, e.getString("record_type"), a.recordType)
        assertEquals(a.name, e.getString("etag"), a.etag)
        assertEquals(a.name, e.optStringOrNull("protection_info"), a.protectionInfo?.let { hex(it) })
        assertEquals(a.name, e.getString("protection_info_tag"), a.protectionInfoTag)
        assertEquals(a.name, e.getString("pcs_key"), hex(a.pcsKey))
        val fields = e.getJSONArray("fields").objects()
        assertEquals(a.name, fields.map { it.getString("name") }, a.fields.keys.toList())
        for ((ef, af) in fields.zip(a.fields.values)) {
            assertEquals(af.name, ef.getInt("value_type"), af.valueType)
            assertEquals(af.name, ef.getBoolean("is_encrypted"), af.isEncrypted)
            assertEquals(af.name, ef.optStringOrNull("raw"), af.raw?.let { hex(it) })
        }
    }

    @Test fun changesBecomeRecordsAsInPython() {
        val changes = records.getJSONArray("changes").strings().map { RecordChange.parseFrom(hex(it)) }
        val got = CloudKitRecord.fromChanges(changes, CloudKitConstants.BEACON_STORE_ZONE)
        val want = records.getJSONArray("records").objects()
        assertEquals(want.size, got.size)
        want.zip(got).forEach { (e, a) -> assertRecord(e, a) }
    }

    @Test fun aRecordWithNoZoneGivenTakesTheOneInItsIdentifier() {
        val changes = records.getJSONArray("changes").strings().map { RecordChange.parseFrom(hex(it)) }
        val typedOnChange = changes.filter { it.record.recordIdentifier.value.name == "TYPED-ON-CHANGE" }
        val got = CloudKitRecord.fromChanges(typedOnChange, "")
        val want = records.getJSONArray("no_zone_records").objects()
        assertEquals(want.size, got.size)
        want.zip(got).forEach { (e, a) -> assertRecord(e, a) }
    }

    @Test fun wireFieldsWalkAsInPython() {
        for (c in records.getJSONArray("wire_fields").objects()) {
            val got = WireFields.iterate(hex(c.getString("data"))).map { listOf(it.number.toString(), it.wireType.toString(), hex(it.payload)) }
            val want = (0 until c.getJSONArray("fields").length()).map { i ->
                val f = c.getJSONArray("fields").getJSONArray(i)
                listOf(f.get(0).toString(), f.get(1).toString(), f.getString(2))
            }
            assertEquals(c.getString("data"), want, got)
        }
    }

    @Test fun privateKeyStructuresReadAsInPython() {
        for (name in serviceKeys.keys()) {
            val c = serviceKeys.getJSONObject(name)
            var keys: List<PcsKey>? = null
            val error = errorOf { keys = ServiceKeyReader.keysFromDer(hex(c.getString("data"))) }
            assertEquals(name, c.optStringOrNull("error"), error)
            if (error == null) assertEquals(name, c.getJSONArray("keys").objects().map { keyJson(it) }, keys!!.map { keyJson(it) })
        }
    }
}
