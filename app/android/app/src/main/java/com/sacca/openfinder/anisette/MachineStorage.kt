package com.sacca.openfinder.anisette

import android.content.Context
import com.sacca.openfinder.security.SecretStore

/**
 * The machine file, encrypted at rest through [SecretStore] (AES-256-GCM, key in the Android Keystore, StrongBox when the
 * device has it). The file name and key alias are the ones used since the first version, so an installed machine keeps working.
 * If the key is lost the machine reads as "none", never as garbage.
 */
class MachineStorage(context: Context, alias: String = "openfinder_machine_key") {
    private val secrets = SecretStore(context, alias)

    fun hasMachine(): Boolean = secrets.exists(FILE)

    fun load(): MachineFile? {
        val raw = secrets.read(FILE) ?: return null
        return try { MachineFile.parse(String(raw, Charsets.UTF_8)) } catch (e: Exception) { null }
    }

    fun save(machine: MachineFile) = secrets.write(FILE, machine.toJson().toByteArray(Charsets.UTF_8))

    fun delete() = secrets.delete(FILE)

    private companion object { const val FILE = "machine.enc" }
}
