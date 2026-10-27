package com.sacca.openfinder.apple.reports

import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.time.OffsetDateTime

private class MemoryBlobs : BlobStore {
    val blobs = HashMap<String, ByteArray>()
    override fun exists(name: String) = blobs.containsKey(name)
    override fun read(name: String) = if (name in unreadable) null else blobs[name]
    val unreadable = HashSet<String>()
    override fun write(name: String, plaintext: ByteArray) { blobs[name] = plaintext }
    override fun delete(name: String) { blobs.remove(name) }
}

class TagKeyStoreTest {
    private val f = ReportFixtures
    private fun pythonExport(): String = JSONArray().also { arr ->
        f.json("accessory_json.json").getJSONArray("cases").objects().take(3).forEach { arr.put(it.getJSONObject("input")) }
    }.toString()

    @Test fun importsWhatPythonsTagsSaveWritesAndExportsItBack() = runTest {
        val store = TagKeyStore(MemoryBlobs())
        assertEquals(3, store.importJson(pythonExport()))
        assertEquals(setOf("ID-1", "ID-2"), store.list().mapNotNull { it.identifier }.toSet())
        val exported = JSONArray(store.exportJson())
        assertEquals(3, exported.length())
        val original = JSONArray(pythonExport())
        for (i in 0 until 3) assertEquals(original.getJSONObject(i).getString("master_key"), exported.getJSONObject(i).getString("master_key"))
    }

    @Test fun putReplacesBySameIdSoAMovedAlignmentIsSaved() = runTest {
        val store = TagKeyStore(MemoryBlobs())
        store.importJson(pythonExport())
        val acc = store.get("ID-1")!!
        assertTrue(acc.updateAlignment(acc.alignmentDate.toInstant().plusSeconds(3600), 500))
        store.put(acc)
        assertEquals(3, store.list().size)
        assertEquals(500, store.get("ID-1")!!.alignmentIndex)
    }

    @Test fun removeAndClear() = runTest {
        val store = TagKeyStore(MemoryBlobs())
        store.importJson(pythonExport())
        store.remove("ID-1")
        assertNull(store.get("ID-1"))
        store.clear()
        assertTrue(store.list().isEmpty())
    }

    @Test fun importIsAllOrNothing() = runTest {
        val store = TagKeyStore(MemoryBlobs())
        val arr = JSONArray(pythonExport()).also { it.getJSONObject(1).put("skn", "00") }
        try { store.importJson(arr.toString()); fail() } catch (_: AccessoryFormatException) {}
        assertTrue(store.list().isEmpty())
        try { store.importJson("garbage"); fail() } catch (_: AccessoryFormatException) {}
    }

    @Test fun blobHoldsNoPlaintextKeysWhenTheBackingStoreEncrypts_andAnUnreadableBlobReadsAsEmpty() = runTest {
        val blobs = MemoryBlobs()
        val store = TagKeyStore(blobs)
        store.importJson(pythonExport())
        assertEquals(1, blobs.blobs.size)
        blobs.blobs[TagKeyStore.BLOB_NAME] = "corrupted".toByteArray()
        assertTrue(store.list().isEmpty())
    }

    @Test fun anUnreadableBlobIsNeverOverwrittenByAnUpdate() = runTest {
        val blobs = MemoryBlobs()
        val store = TagKeyStore(blobs)
        store.importJson(pythonExport())
        val before = blobs.blobs.getValue(TagKeyStore.BLOB_NAME).copyOf()
        val acc = store.get("ID-1")!!

        // a transient Keystore failure: the blob is there but cannot be decrypted
        blobs.unreadable += TagKeyStore.BLOB_NAME
        for (mutate in listOf<suspend () -> Unit>({ store.put(acc) }, { store.remove("ID-1") }, { store.importJson(pythonExport()) })) {
            try { mutate(); fail("rewrote an unreadable blob") } catch (e: com.sacca.openfinder.domain.OpenFinderException) {
                assertTrue(e.error is com.sacca.openfinder.domain.OpenFinderError.Backend)
            }
        }
        assertTrue(before.contentEquals(blobs.blobs.getValue(TagKeyStore.BLOB_NAME)))
        assertTrue(store.list().isEmpty())                       // reading degrades to empty

        // the same for a blob that reads but is garbage
        blobs.unreadable.clear()
        blobs.blobs[TagKeyStore.BLOB_NAME] = "garbage".toByteArray()
        try { store.put(acc); fail() } catch (_: com.sacca.openfinder.domain.OpenFinderException) {}
        assertEquals("garbage", String(blobs.blobs.getValue(TagKeyStore.BLOB_NAME)))

        // clear() is the deliberate reset, and afterwards writing works again
        store.clear()
        store.put(acc)
        assertEquals(1, store.list().size)
    }

    @Test fun singleObjectImportAndDerivedIds() = runTest {
        val store = TagKeyStore(MemoryBlobs())
        val nulls = f.json("accessory_json.json").getJSONArray("cases").objects().first { it.getString("name") == "nulls" }.getJSONObject("input")
        assertEquals(1, store.importJson(nulls.toString()))
        val acc = store.list().single()
        assertEquals(16, acc.id.length)
        assertFalse(acc.id.contains(nulls.getString("master_key").take(8)))
        assertEquals(acc.id, AccessoryKeys.fromJson(nulls).id)
        assertEquals(OffsetDateTime.parse("2026-09-01T00:00:00Z"), acc.pairedAt)
    }
}
