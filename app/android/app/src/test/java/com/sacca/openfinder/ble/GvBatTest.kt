package com.sacca.openfinder.ble

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class GvBatTest {
    @Test
    fun `audit sample 3d20 gives the two candidate voltages`() {
        val (be, le) = GvBat.candidates(byteArrayOf(0x3d.toByte(), 0x20.toByte()))!!
        assertEquals(3.912, be, 0.001)   // big-endian / 4
        assertEquals(4.127, le, 0.001)   // little-endian / 2
    }

    @Test
    fun `reversed byte order gives the other candidate reading, not the same one`() {
        // 0x203d: be = 8253 → 2.06 V (implausible, expected); le = 15648 → 7.82 V (implausible too) —
        // the asymmetry is the point: only one ordering of the real sample yields a plausible voltage.
        val (be, le) = GvBat.candidates(byteArrayOf(0x20.toByte(), 0x3d.toByte()))!!
        assertEquals(2.06325, be, 0.001)
        assertEquals(7.824, le, 0.001)
    }

    @Test
    fun `too short a sample is rejected`() {
        assertNull(GvBat.candidates(byteArrayOf(0x3d.toByte())))
        assertNull(GvBat.candidates(ByteArray(0)))
    }
}
