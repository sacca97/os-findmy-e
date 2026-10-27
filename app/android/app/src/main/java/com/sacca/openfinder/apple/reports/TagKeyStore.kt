package com.sacca.openfinder.apple.reports

import com.sacca.openfinder.domain.OpenFinderError
import com.sacca.openfinder.domain.OpenFinderException
import com.sacca.openfinder.security.SecretStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/** The three operations of `SecretStore` the key store needs, so tests can run without an Android Keystore. */
interface BlobStore {
    fun exists(name: String): Boolean
    fun read(name: String): ByteArray?
    fun write(name: String, plaintext: ByteArray)
    fun delete(name: String)
}

/** [BlobStore] over the app's encrypted `SecretStore` (AES-256-GCM, key in the Android Keystore). */
class SecretStoreBlobs(private val store: SecretStore) : BlobStore {
    override fun exists(name: String) = store.exists(name)
    override fun read(name: String) = store.read(name)
    override fun write(name: String, plaintext: ByteArray) = store.write(name, plaintext)
    override fun delete(name: String) = store.delete(name)
}

/**
 * The accessories' secret keys at rest: one encrypted blob holding a JSON array of `FindMyAccessory.to_json` objects, which is
 * exactly the file `tools/machoadi/tag_keys.py --tags-save` writes, so keys exported once from the Python tools can be imported
 * ([importJson]) and the store can be exported back ([exportJson]) for Python's `FindMyAccessory.from_json`.
 *
 * Nothing leaves in the clear except through [exportJson], which the caller must treat as a secret. The blob is rewritten
 * through `SecretStore`'s temp-file-and-rename, so a crash cannot corrupt it; an unreadable blob reads as an empty store (the
 * keys then have to be re-imported or re-discovered), but [put], [putAll] and [remove] REFUSE to rewrite a blob that exists and
 * cannot be read or parsed (a transient Keystore failure must not turn the next alignment save into a wipe of every other tag):
 * they throw `OpenFinderException(Backend)` and leave the blob as it is. Only [clear] discards it on purpose. Entries are keyed by [AccessoryKeys.id]; putting an accessory with an
 * existing id replaces it (this is how a moved alignment is saved after a fetch).
 */
class TagKeyStore(private val blobs: BlobStore, private val blobName: String = BLOB_NAME) {
    private val mutex = Mutex()

    suspend fun list(): List<AccessoryKeys> = mutex.withLock { withContext(Dispatchers.IO) { load() } }

    suspend fun get(id: String): AccessoryKeys? = list().firstOrNull { it.id == id }

    /** Adds or replaces (same [AccessoryKeys.id]) one accessory. */
    suspend fun put(accessory: AccessoryKeys) = putAll(listOf(accessory))

    suspend fun putAll(accessories: List<AccessoryKeys>) = mutex.withLock {
        withContext(Dispatchers.IO) {
            val byId = LinkedHashMap<String, AccessoryKeys>()
            loadForUpdate().forEach { byId[it.id] = it }
            accessories.forEach { byId[it.id] = it }
            save(byId.values)
        }
    }

    suspend fun remove(id: String) = mutex.withLock {
        withContext(Dispatchers.IO) { save(loadForUpdate().filter { it.id != id }) }
    }

    suspend fun clear() = mutex.withLock { withContext(Dispatchers.IO) { blobs.delete(blobName) } }

    /**
     * Imports a JSON array (or a single object) as the Python tools write it and merges it in.
     * All-or-nothing: nothing is stored when any entry is malformed. Returns the number of accessories imported.
     * @throws AccessoryFormatException
     */
    suspend fun importJson(text: String): Int {
        val imported = parseAll(text)
        putAll(imported)
        return imported.size
    }

    /** The whole store as the JSON array Python's tools read. Contains the secret keys in the clear. */
    suspend fun exportJson(): String = JSONArray().also { arr -> list().forEach { arr.put(it.toJson()) } }.toString()

    private fun load(): List<AccessoryKeys> {
        val raw = blobs.read(blobName) ?: return emptyList()
        return try { parseAll(String(raw, Charsets.UTF_8)) } catch (e: AccessoryFormatException) { emptyList() }
    }

    /** Like [load], but an existing blob that cannot be read is an error: writing over it would destroy the stored keys. */
    private fun loadForUpdate(): List<AccessoryKeys> {
        if (!blobs.exists(blobName)) return emptyList()
        val raw = blobs.read(blobName) ?: throw unreadable()
        return try { parseAll(String(raw, Charsets.UTF_8)) } catch (e: AccessoryFormatException) { throw unreadable() }
    }

    private fun unreadable() = OpenFinderException(OpenFinderError.Backend("The stored tag keys cannot be read right now; nothing was changed."))

    private fun save(accessories: Collection<AccessoryKeys>) {
        val json = JSONArray().also { arr -> accessories.forEach { arr.put(it.toJson()) } }.toString()
        blobs.write(blobName, json.toByteArray(Charsets.UTF_8))
    }

    private fun parseAll(text: String): List<AccessoryKeys> {
        val trimmed = text.trim()
        return try {
            if (trimmed.startsWith("[")) {
                val arr = JSONArray(trimmed)
                (0 until arr.length()).map { AccessoryKeys.fromJson(arr.getJSONObject(it)) }
            } else {
                listOf(AccessoryKeys.fromJson(JSONObject(trimmed)))
            }
        } catch (e: AccessoryFormatException) {
            throw e
        } catch (e: Exception) {
            throw AccessoryFormatException("invalid accessory JSON (${e.javaClass.simpleName})")
        }
    }

    companion object { const val BLOB_NAME = "tag_keys.json" }
}
