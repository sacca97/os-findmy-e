# adi-core: CoreADI under Unicorn, in Rust

A small native core for Mac-lineage Anisette (MID/OTP), meant to be wrapped for Android (JNI) or
used from any Rust/C host. It is a port of `tools/machoadi/{macho,harness,stubs,adi_run}.py`: it
loads a registered CoreADI build (by sha256), runs it under Unicorn on a synthetic macOS userland
(virtual `/Users/Shared/adi`, libc and CoreFoundation stubs) and calls the dispatcher.

Only `unicorn-engine` (x86 only) and `sha2` are used. The x86 `adi-cli` is about 1.4 MB.

    cd native/adi-core && cargo build --release
    adi-cli --dylib CoreADI --state STATE [--frozen SECS] [--repeat N]
    native/compare.sh CoreADI STATE        # byte-for-byte against the Python harness

Sessions, not a long-lived process. The library never frees its memory and the Python harness
leaked about 2 MB per OTP request (it ran out after a handful). Here `CoreAdi::begin_session()`
resets the VM to a snapshot taken right after load (writable segments, data cells, heap, stack,
scratch, descriptors, allocator counters), keeps the store, host UUID and clock, and calls
`Initialize`, like a fresh process but without retranslating code. One session is one header set
(`is_machine_provisioned`, `request_otp`, `get_routing`), one provisioning (`provisioning_start` and
`provisioning_end` share a session) or one `synchronize`.

Measured: about 20 ms per session, flat, with a 2.2 MB heap, over 300 sessions (first session
about 90 ms while Unicorn translates). Two things that matter and are easy to get wrong:
* The heap is reset by unmapping and remapping it. Zeroing it in place, or reusing freed blocks,
  makes every later OTP call about 5x slower (Unicorn retranslates about 3,400 blocks per call; the
  cause inside Unicorn was not found). Remapping the *stack* instead of zeroing it is also slower.
* Validation is stateful: `native/compare.sh` runs 60 sessions with the clock advancing, a fresh
  Python process per session against one Rust process, and compares every MID, OTP, routing value
  and the store hash.

## Interfaces

* **Rust**: `CoreAdi` (`headers`, `provisioning_begin`/`provisioning_finish`, `sync`, `update_routing`,
  `store_put`/`store_files`). Each is one session.
* **C**: `adi-core/adi_core.h` (`adi_open`, `adi_headers`, ...), buffers owned by the library.
  `adi-core/tests/smoke.c` exercises it.
* **Java/Android**: `android/dev/osfindmy/adi/CoreAdi.java` over JNI (`--features jni`). It throws
  `NotProvisionedException`, `AlreadyProvisionedException` or `AdiException`. Call it from one
  background thread; each call is a session.

## Android build

    NDK=/path/to/android-ndk-r27c native/android/build.sh [arm64-v8a] [x86_64]

Needs `rustup target add aarch64-linux-android x86_64-linux-android`, cmake and the NDK. It writes
`android/jniLibs/<abi>/libadi_core.so` (1.3 MB each, depending only on libc, libm, libdl) and a
test binary under `android/build/bin/<abi>/`. Three NDK quirks the script handles: Android has no
`libpthread` (an empty stub is linked), bindgen needs the NDK sysroot, and arm64 TCG needs
`__clear_cache` from the NDK's compiler-rt builtins (linked explicitly).

Tested on a Pixel 5 (arm64-v8a, Android 16): the 60-session pinned-clock sequence is byte-identical
to the host and the Python harness; about 60 ms per session (the x86 code is emulated on ARM),
first session about 210 ms. Not tested yet: the JNI library inside an APK, and the x86_64 ABI on
an emulator.

## What the app must do

* Ship (or let the user supply) the CoreADI file; `CoreAdi.open` identifies it by sha256.
* Keep the host UUID (16 bytes) with the store and never change it: the MID derives from it.
* Persist `exportStore()` after every `headers`, provisioning or `sync`; restore it with `importStore`.
* The Apple-side protocol (provisioning exchange, resync POST, headers) is still in the Python tools.

License note: the `unicorn-engine` crate is GPL-2.0.
