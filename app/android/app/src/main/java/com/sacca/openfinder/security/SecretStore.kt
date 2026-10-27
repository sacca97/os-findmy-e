package com.sacca.openfinder.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Named secret blobs encrypted at rest: AES-256-GCM with a key that lives in the Android Keystore and never leaves it.
 * StrongBox (the dedicated secure chip) is used when the device has one, the TEE-backed Keystore otherwise. No biometric or
 * screen-lock requirement: the secrets must stay usable by the app at any time. Each blob is a file `iv(12) || ciphertext`
 * in app-private storage (never backed up: the manifest sets `allowBackup=false`).
 *
 * What this protects: the secrets at rest, from other apps, from backups and from a copied filesystem. What it does not:
 * a running, compromised process still sees the plaintext while it uses it. Callers keep plaintext as short-lived as they can
 * and never log it. A blob that cannot be decrypted (key lost, corrupted file) reads as absent, never as garbage.
 */
class SecretStore(
    private val context: Context,
    private val keyAlias: String,
    private val strongBoxPreferred: Boolean = true,
) {
    private val dir by lazy { context.filesDir }                 // touches the disk: first use is on a background thread
    private val lock = Any()

    fun exists(name: String): Boolean = synchronized(lock) { File(dir, name).exists() }

    /** The plaintext, or null when absent or unreadable. */
    fun read(name: String): ByteArray? = synchronized(lock) {
        val file = File(dir, name)
        if (!file.exists()) return null
        try {
            val raw = file.readBytes()
            if (raw.size <= IV_BYTES) return null
            val cipher = Cipher.getInstance(TRANSFORM).apply {
                init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, raw, 0, IV_BYTES))
            }
            cipher.doFinal(raw, IV_BYTES, raw.size - IV_BYTES)
        } catch (e: Exception) {
            null
        }
    }

    fun write(name: String, plaintext: ByteArray) = synchronized(lock) {
        val cipher = Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, key()) }
        val data = cipher.doFinal(plaintext)
        // Temp file + rename: a crash cannot leave a half-written (undecryptable) secret behind.
        val target = File(dir, name)
        val tmp = File(dir, "$name.tmp")
        tmp.writeBytes(cipher.iv + data)
        check(tmp.renameTo(target)) { "could not store $name" }
    }

    fun delete(name: String) = synchronized(lock) { File(dir, name).delete(); Unit }

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(keyAlias, null) as? SecretKey)?.let { return it }
        if (strongBoxPreferred) {
            try { return generate(strongBox = true) } catch (_: StrongBoxUnavailableException) { /* no secure chip: fall back */ }
        }
        return generate(strongBox = false)
    }

    private fun generate(strongBox: Boolean): SecretKey {
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setIsStrongBoxBacked(strongBox)
                .build(),
        )
        return gen.generateKey()
    }

    private companion object {
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
        const val TAG_BITS = 128
    }
}
