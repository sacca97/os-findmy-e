package com.sacca.openfinder.lib

import java.io.Closeable

/**
 * A failure from the Rust OpenFinder core (`sacca-openfinderlib`). The message is safe to show: it never carries a
 * password, token, key or Anisette header.
 */
class OpenFinderLibException(message: String) : Exception(message)

/**
 * Thin wrapper over `libsacca_openfinderlib.so` (`openfinder_open_machine` / `openfinder_call` / `openfinder_close`).
 *
 * The library owns the CoreADI machine: [openMachine] takes the machine file and the CoreADI image, and
 * every operation is one JSON [call]. State never lives here — each response says whether the host must
 * persist a new state blob / machine store (see `native/apple-core/src/session.rs`).
 *
 * One instance is one session. [call] blocks (it may do network I/O and CoreADI sessions), so call it
 * from a background dispatcher, never the main thread.
 *
 * ```kotlin
 * val lib = OpenFinderLib.openMachine(machineFileJson, coreAdiImageBytes)
 * lib.use {
 *     val response = JSONObject(it.call("""{"cmd":"login","username":"...","password_b64":"..."}"""))
 * }
 * ```
 */
class OpenFinderLib private constructor(private var handle: Long) : Closeable {
    /** Runs one command and returns its JSON response (`{"ok":true,...}` or `{"ok":false,"error":{...}}`). */
    fun call(requestJson: String): String {
        val current = handle
        check(current != 0L) { "the OpenFinder session is closed" }
        return nativeCall(current, requestJson)
    }

    override fun close() {
        val current = handle
        if (current != 0L) {
            handle = 0L
            nativeClose(current)
        }
    }

    private external fun nativeCall(handle: Long, requestJson: String): String
    private external fun nativeClose(handle: Long)

    companion object {
        init {
            System.loadLibrary("sacca_openfinderlib")
        }

        /** The library version, for diagnostics. */
        fun version(): String = nativeVersion()

        /**
         * Opens a session. [machineJson] is a `.machine.json` file (host UUID, identity, store) and
         * [image] the CoreADI file; both are credentials and neither is logged.
         */
        fun openMachine(machineJson: String, image: ByteArray): OpenFinderLib {
            val handle = nativeOpenMachine(machineJson, image)
            if (handle == 0L) throw OpenFinderLibException("could not open the OpenFinder session (bad machine file or CoreADI image)")
            return OpenFinderLib(handle)
        }

        @JvmStatic private external fun nativeVersion(): String
        @JvmStatic private external fun nativeOpenMachine(machineJson: String, image: ByteArray): Long
    }
}
