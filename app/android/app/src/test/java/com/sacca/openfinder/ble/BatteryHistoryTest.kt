package com.sacca.openfinder.ble

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class BatteryHistoryTest {
    @get:Rule val temp = TemporaryFolder()
    private val now = 1_000_000_000_000L
    private fun sample(hash: String = "a", at: Long = now) = BatteryStore.Sample(hash, "3d20", at)

    @Test fun legacySampleSurvivesAppendAndRestart() {
        val file = File(temp.root, "battery.json")
        file.writeText("""[{"hash":"a","raw":"3d20","at":${now - 1000}}]""")
        BatteryHistory(file).append(sample(), now)
        assertEquals(listOf(sample(at = now - 1000), sample()), BatteryHistory(file).read(now))
        assertEquals(listOf(file), temp.root.listFiles()!!.toList())
    }

    @Test fun duplicateSamplesDoNotGrowAndDifferentTagsRemainSeparate() {
        val store = BatteryHistory(File(temp.root, "battery.json"))
        store.append(sample(), now)
        store.append(sample(), now)
        store.append(sample("b"), now)
        assertEquals(setOf("a", "b"), store.read(now).map { it.hashB64 }.toSet())
        assertEquals(2, store.read(now).size)
    }

    @Test fun badFramesAndFutureSamplesAreRejectedWithoutChangingHistory() {
        val file = File(temp.root, "battery.json")
        val store = BatteryHistory(file)
        store.append(sample(), now)
        val original = file.readText()
        assertTrue(runCatching { store.append(sample().copy(rawHex = "5540"), now) }.isFailure)
        assertTrue(runCatching { store.append(sample(at = now + 3600_000), now) }.isFailure)
        assertEquals(original, file.readText())
    }

    @Test fun corruptedHistoryCannotBeSilentlyOverwritten() {
        val file = File(temp.root, "battery.json").apply { writeText("broken") }
        assertTrue(runCatching { BatteryHistory(file).append(sample(), now) }.isFailure)
        assertEquals("broken", file.readText())
    }
}
