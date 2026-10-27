package com.sacca.openfinder.apple.cloudkit

import com.google.protobuf.ByteString
import com.sacca.openfinder.apple.cloudkit.CkFixtures.hex
import com.sacca.openfinder.apple.cloudkit.CkFixtures.keyJson
import com.sacca.openfinder.apple.cloudkit.CkFixtures.keys
import com.sacca.openfinder.apple.proto.cloudkit.EncryptedValue
import com.sacca.openfinder.apple.proto.cloudkit.Identifier
import com.sacca.openfinder.apple.proto.cloudkit.ProtectionInfo
import com.sacca.openfinder.apple.proto.cloudkit.RecordChange
import com.sacca.openfinder.apple.proto.cloudkit.RecordZoneIdentifier
import com.sacca.openfinder.apple.proto.cloudkit.Zone
import com.sacca.openfinder.apple.proto.cloudkit.ZoneSummary
import com.sacca.openfinder.domain.OpenFinderError
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.asFlow
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

/**
 * Stage 6 against `findmy.cloudkit.beacons`: a whole synthetic BeaconStore zone (zone protection -> zone keys -> record
 * protection -> fields), decrypted, grouped and assembled by the real Python (fixtures/cloudkit/beacons.json). The zone holds
 * every shape the read path branches on: named and unnamed beacons, alignment present/unreadable/absent, a device with no
 * private key, beacons that cannot be assembled, unwanted and untyped record types, a record for someone else, a record whose
 * key id is wrong, the zone-default branch (pcsKey) and a duplicate naming record.
 */
class BeaconStoreOracleTest {
    private val f = CkFixtures.json("beacons.json")
    /** The day the fixtures were generated; every date in them is years away from it. */
    private val clock = Clock.fixed(Instant.parse("2026-10-18T00:00:00Z"), ZoneOffset.UTC)
    private val changes = f.getJSONArray("changes").strings().map { RecordChange.parseFrom(hex(it)) }
    private val zoneKeys = keys(f.getJSONArray("zone_keys"))
    private val defaults = f.getJSONArray("default_master_keys").strings().map { hex(it) }

    private fun decrypted() = BeaconStore.decryptRecords(CloudKitRecord.fromChanges(changes, CloudKitConstants.BEACON_STORE_ZONE), zoneKeys, defaults, clock)

    private fun valueJson(v: Any?): String = when (v) {
        null -> """{"none":true}"""
        is ByteArray -> """{"bytes":"${hex(v)}"}"""
        is String -> JSONObject().put("str", v).toString()
        is Long -> """{"int":$v}"""
        is Double -> JSONObject().put("double", v).toString()
        is Instant -> """{"date_micros":${v.epochSecond * 1_000_000 + v.nano / 1000}}"""
        is EncryptedValue -> """{"wrapper":"${hex(v.toByteArray())}"}"""
        else -> error("unexpected value type ${v.javaClass}")
    }

    private fun canonical(o: JSONObject): String = when {
        o.has("double") -> JSONObject().put("double", o.getDouble("double")).toString()
        o.has("int") -> """{"int":${o.getLong("int")}}"""
        o.has("date_micros") -> """{"date_micros":${o.getLong("date_micros")}}"""
        else -> o.toString()
    }

    @Test fun zoneDecryptsAsInPython() {
        val got = decrypted()
        val want = f.getJSONArray("decrypted").objects()
        assertEquals(want.map { it.getString("name") }, got.map { it.name })
        for ((e, a) in want.zip(got)) {
            assertEquals(a.name, e.getString("record_type"), a.recordType)
            val ev = e.getJSONObject("values")
            assertEquals(a.name, ev.keys().asSequence().toSet(), a.values.keys)
            for (k in a.values.keys) assertEquals("${a.name}.$k", canonical(ev.getJSONObject(k)), valueJson(a.values[k]))
            val raw = e.getJSONObject("raw_values")
            assertEquals(a.name, raw.keys().asSequence().toSet(), a.rawValues.keys)
            for (k in a.rawValues.keys) assertEquals("${a.name}.$k", raw.getString(k), hex(a.rawValues.getValue(k)))
            assertEquals(a.name, e.getJSONArray("undecryptable").strings(), a.undecryptable.keys.sorted())
        }
    }

    @Test fun skippedRecordsAreCountedAsInPythonExceptTheUntypedMiscount() {
        val got = decrypted()
        val want = f.getJSONObject("skipped")
        val expected = want.keys().asSequence().associateWith { want.getInt(it) }.toMutableMap()
        // Python's counter for untyped records reads the wrong key and never passes 1; there are two in this zone.
        assertEquals(1, expected["<untyped>"])
        expected["<untyped>"] = 2
        assertEquals(expected, got.skipped)
        assertEquals(f.getBoolean("first_miss_present"), got.firstMiss != null)
        assertTrue(got.firstMiss!!.contains("None of the"))
    }

    @Test fun aRecordWhoseProtectionIsNotDerIsCountedNotFatal() {
        val broken = f.getJSONObject("broken_record")
        assertEquals("DerError", broken.getString("python_error"))   // the Python aborts the whole decrypt_records call here
        val records = CloudKitRecord.fromChanges(listOf(RecordChange.parseFrom(hex(broken.getString("change")))), CloudKitConstants.BEACON_STORE_ZONE)
        val got = BeaconStore.decryptRecords(records, zoneKeys, emptyList(), clock)
        assertEquals(0, got.size)
        assertEquals(mapOf("would not decrypt" to 1), got.skipped)
    }

    @Test fun groupsMatch() {
        val groups = BeaconStore.groupRecords(decrypted())
        val want = f.getJSONArray("groups").objects()
        assertEquals(want.map { it.getString("beacon") }, groups.map { it.beacon.name })
        for ((e, g) in want.zip(groups)) {
            assertEquals(g.beacon.name, e.optStringOrNull("naming"), g.naming?.name)
            assertEquals(g.beacon.name, e.optStringOrNull("alignment"), g.alignment?.name)
            assertEquals(g.beacon.name, e.getBoolean("can_be_located"), BeaconStore.canBeLocated(g.beacon))
        }
    }

    private fun micros(i: Instant) = i.epochSecond * 1_000_000 + i.nano / 1000

    private fun assertAccessories(got: List<DecryptedAccessory>) {
        val want = f.getJSONArray("accessories").objects()
        assertEquals(want.map { it.getString("identifier") }, got.map { it.identifier })
        for ((e, a) in want.zip(got)) {
            assertEquals(e.getString("master_key"), hex(a.masterKey))
            assertEquals(28, a.masterKey.size)
            assertEquals(e.getString("skn"), hex(a.skn))
            assertEquals(e.getString("sks"), hex(a.sks))
            assertEquals(e.getLong("paired_at"), micros(a.pairedAt))
            assertEquals(a.identifier, e.optStringOrNull("name"), a.name)
            assertEquals(a.identifier, e.optStringOrNull("model"), a.model)
            assertEquals(a.identifier, e.optStringOrNull("group_identifier"), a.groupIdentifier)
            assertEquals(a.identifier, e.optStringOrNull("serial_number"), a.serialNumber)
            // FindMyAccessory fills these defaults itself (pairing date, index 0); DecryptedAccessory leaves them null.
            assertEquals(a.identifier, e.getLong("alignment_date_given"), micros(a.alignmentDate ?: a.pairedAt))
            assertEquals(a.identifier, e.getLong("alignment_index_given"), a.alignmentIndex ?: 0L)
            assertFalse(a.toString().contains(hex(a.masterKey)))
        }
        // BEACON-1 has a readable alignment record; BEACON-2's is unreadable; BEACON-3 has none.
        assertEquals(19200L, got[0].alignmentIndex)
        assertNull(got[1].alignmentIndex)
        assertNull(got[2].alignmentDate)
    }

    @Test fun accessoriesMatch() = assertAccessories(BeaconStore.accessoriesFromRecords(decrypted()))

    @Test fun serialsAreExtractedAsInPython() {
        val serials = f.getJSONObject("serials")
        for (s in serials.keys()) assertEquals(s, serials.optStringOrNull(s), BeaconStore.extractSerial(s))
    }

    @Test fun datesUseTheEpochPythonChooses() {
        for (c in f.getJSONArray("dates").objects()) {
            val seconds = c.getString("seconds").let { if (it == "nan") Double.NaN else it.toDouble() }
            var got: Instant? = null
            val error = errorOf { got = BeaconStore.asInstant(seconds, clock) }
            if (c.has("error")) {
                assertEquals(c.getString("seconds"), c.getString("error"), error)
            } else {
                assertNull(c.getString("seconds"), error)
                assertEquals(c.getString("seconds"), c.getJSONObject("result").getLong("date_micros"), micros(got!!))
            }
        }
    }

    // ---------------------------------------------------------------------------------------------- the store itself

    /** A CloudKit that answers for one zone (as the fork's tests/fake_account.py `FakeCloudKit`), with the oracle's bytes. */
    private class FakeCloudKit(val zones: List<ZoneSummary>, val changes: List<RecordChange>) : CloudKitApi {
        var zoneCalls = 0
        val asked = mutableListOf<Pair<String, ByteArray?>>()
        override suspend fun openContainer(refresh: Boolean) = error("not used")
        override suspend fun zoneRetrieve(): List<ZoneSummary> { zoneCalls++; return zones }
        override suspend fun recordSync(zoneName: String, continuationToken: ByteArray?, maxChanges: Int?) = error("not used")
        override fun iterRecords(zoneName: String, continuationToken: ByteArray?, maxPages: Int): Flow<RecordChange> {
            asked += zoneName to continuationToken
            return changes.asFlow()
        }
        override suspend fun functionInvoke(service: String, name: String, parameters: ByteArray) = error("not used")
        override fun close() {}
    }

    private fun zone(name: String, protection: ByteArray?, recordProtection: ByteArray?): ZoneSummary {
        val z = Zone.newBuilder().setZoneIdentifier(RecordZoneIdentifier.newBuilder().setValue(Identifier.newBuilder().setName(name)))
        protection?.let { z.setProtectionInfo(ProtectionInfo.newBuilder().setProtectionInfo(ByteString.copyFrom(it)).setProtectionInfoTag("zone-tag")) }
        recordProtection?.let { z.setRecordProtectionInfo(ProtectionInfo.newBuilder().setProtectionInfo(ByteString.copyFrom(it))) }
        return ZoneSummary.newBuilder().setTargetZone(z).build()
    }

    private val zoneJson = f.getJSONObject("zone")
    private val serviceKeys = keys(zoneJson.getJSONArray("service_keys")).map { CkFixtures.jca(it) }

    private fun store(vararg zones: ZoneSummary) = BeaconStore(FakeCloudKit(zones.toList(), changes), clock)

    private val realZones = arrayOf(
        zone("_defaultZone", null, null),
        zone(CloudKitConstants.BEACON_STORE_ZONE, hex(zoneJson.getString("zone_protection")), hex(zoneJson.getString("record_protection"))),
    )

    @Test fun theStoreFollowsReadAccessoriesStepByStep() = ckTest {
        val store = store(*realZones)
        val keys = store.zoneKeys(serviceKeys)
        assertEquals(zoneKeys.map { keyJson(it) }, keys.map { keyJson(it) })
        assertEquals(defaults.map { hex(it) }, store.zoneRecordDefaults(keys).map { hex(it) })
        val records = store.fetchRecords()
        assertEquals(f.getJSONArray("changes").length() - 1, records.size)   // the deletion carries no record
        val decrypted = BeaconStore.decryptRecords(records, keys, store.zoneRecordDefaults(keys), clock)
        assertAccessories(BeaconStore.accessoriesFromRecords(decrypted))
    }

    @Test fun fetchAccessoriesIsTheWholePathInOneCall() = ckTest {
        val fake = FakeCloudKit(realZones.toList(), changes)
        assertAccessories(BeaconStore(fake, clock).fetchAccessories(serviceKeys, continuationToken = byteArrayOf(7)))
        assertEquals(CloudKitConstants.BEACON_STORE_ZONE, fake.asked.single().first)
        assertEquals("07", hex(fake.asked.single().second!!))
        assertEquals(2, fake.zoneCalls)   // as Python: once for the zone keys, once for the record defaults
    }

    @Test fun aZoneWithoutProtectionIsABackendError() = ckTest {
        val error = expectError(OpenFinderError.Backend::class.java) { store(zone("_defaultZone", null, null), zone("BeaconStore", null, null)).zoneKeys(serviceKeys) }
        assertTrue(error.message.contains("_defaultZone, BeaconStore"))
        expectError(OpenFinderError.Backend::class.java) { store().zoneKeys(serviceKeys) }
    }

    @Test fun keysThatDoNotOpenTheZoneAreReportedAsSuch() = ckTest {
        val stranger = CkFixtures.jca(PcsKey(PcsCurve.P256, java.math.BigInteger.valueOf(424242)))
        val error = expectError(OpenFinderError.Backend::class.java) { store(*realZones).zoneKeys(listOf(stranger)) }
        assertTrue(error.message.contains("do not open the BeaconStore zone"))
    }

    @Test fun anUnreadableRecordProtectionMeansNoDefaults() = ckTest {
        val store = store(zone(CloudKitConstants.BEACON_STORE_ZONE, hex(zoneJson.getString("zone_protection")), byteArrayOf(0x61, 0x05, 0x30)))
        assertEquals(emptyList<ByteArray>(), store.zoneRecordDefaults(zoneKeys))
        val none = store(zone(CloudKitConstants.BEACON_STORE_ZONE, hex(zoneJson.getString("zone_protection")), null))
        assertEquals(emptyList<ByteArray>(), none.zoneRecordDefaults(zoneKeys))
    }

    @Test fun safeLocationIsNeverDecrypted() {
        val safe = CloudKitRecord.fromChanges(changes, CloudKitConstants.BEACON_STORE_ZONE).first { it.recordType == RecordType.SAFE_LOCATION }
        assertEquals("BeaconExportError", errorOf { BeaconStore.decryptRecord(safe, zoneKeys, defaults, clock) })
    }
}
