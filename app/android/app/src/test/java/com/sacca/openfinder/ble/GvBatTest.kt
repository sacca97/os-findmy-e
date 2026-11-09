package com.sacca.openfinder.ble

import org.junit.Assert.*
import org.junit.Test

class GvBatTest {
    @Test fun vendorStatusCodesSelectFourBatteryIcons() {
        assertEquals(4, GvBat.fromHex("3d20")!!.bars)
        assertEquals(3, GvBat.fromHex("3D60")!!.bars)
        assertEquals(2, GvBat.fromHex("3da0")!!.bars)
        assertEquals(1, GvBat.fromHex("3de0")!!.bars)
    }

    @Test fun unexpectedStatusIsUnknownInsteadOfLowOrFull() {
        assertNull(GvBat.fromHex("3d00")!!.bars)
    }

    @Test fun nonBatteryFramesAndMalformedInputAreRejected() {
        for (raw in listOf("", "3d", "203d", "3d2060", "zzzz", "  20")) assertNull(GvBat.fromHex(raw))
        assertNull(GvBat.decode(byteArrayOf(0x3d)))
        assertNull(GvBat.decode(byteArrayOf(0x55, 0x20)))
    }
}
