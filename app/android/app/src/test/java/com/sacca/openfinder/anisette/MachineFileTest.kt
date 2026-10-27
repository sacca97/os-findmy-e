package com.sacca.openfinder.anisette

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.Base64

class MachineFileTest {
    private val store = byteArrayOf(1, 2, 3, 4, 5)
    private fun json(
        version: Int = 1,
        host: String = "00112233445566778899aabbccddeeff",
        extra: String = "",
        b64: String = Base64.getEncoder().encodeToString(store),
    ) = """{"version":$version,"host_uuid":"$host","identity":{"device_id":"D","local_user_uuid":"U","client_info":"C","serial":"S","routing":42$extra},"store_export_b64":"$b64"}"""

    @Test fun parsesAValidFile() {
        val m = MachineFile.parse(json())
        assertEquals(16, m.hostUuid.size)
        assertEquals(0x00.toByte(), m.hostUuid[0]); assertEquals(0xff.toByte(), m.hostUuid[15])
        assertEquals("D", m.identity.deviceId); assertEquals("S", m.identity.serial); assertEquals(42L, m.identity.routing)
        assertArrayEquals(store, m.storeExport)
    }

    @Test fun roundTripsThroughJson() {
        val m = MachineFile.parse(json())
        val again = MachineFile.parse(m.toJson())
        assertArrayEquals(m.hostUuid, again.hostUuid); assertArrayEquals(m.storeExport, again.storeExport)
        assertEquals(m.identity, again.identity)
    }

    @Test fun optionalIdentityFieldsMayBeAbsent() {
        val m = MachineFile.parse("""{"version":1,"host_uuid":"00112233445566778899aabbccddeeff","identity":{"device_id":"D","local_user_uuid":"U","client_info":"C"},"store_export_b64":""}""")
        assertNull(m.identity.serial); assertNull(m.identity.routing); assertEquals(0, m.storeExport.size)
    }

    @Test fun withStoreReplacesOnlyTheStore() {
        val m = MachineFile.parse(json()).withStore(byteArrayOf(9))
        assertArrayEquals(byteArrayOf(9), m.storeExport); assertEquals("D", m.identity.deviceId)
    }

    @Test fun rejectsBadInputWithSafeMessages() {
        listOf(
            "not json", "{}", json(version = 2), json(host = "abcd"), json(host = "zz112233445566778899aabbccddeeff"), json(b64 = "!!!"),
        ).forEach { bad ->
            val e = assertThrows(IllegalArgumentException::class.java) { MachineFile.parse(bad) }
            // The message must never echo file contents (they are credentials).
            assertFalse(e.message!!.contains("00112233445566778899"))
            assertFalse(e.message!!.contains("device_id"))
        }
    }

    @Test fun toStringRedactsEverything() {
        val s = MachineFile.parse(json()).toString()
        assertEquals("MachineFile(<redacted>)", s)
    }
}
