# adi-core: CoreADI under Unicorn, in Rust

A small native core for Mac-lineage Anisette (MID/OTP), meant to be wrapped for Android (JNI) or
used from any Rust/C host. It is a port of `tools/machoadi/{macho,harness,stubs,adi_run}.py`: it
loads a registered CoreADI build (by sha256), runs it under Unicorn on a synthetic macOS userland
(virtual `/Users/Shared/adi`, libc and CoreFoundation stubs) and calls the dispatcher.

Only `unicorn-engine` (x86 only) and `sha2` are used. The x86 `adi-cli` is about 1.4 MB.

    cd native/adi-core && cargo build --release
    adi-cli --dylib CoreADI --state STATE [--frozen SECS] [--repeat N]
    native/compare.sh CoreADI STATE        # byte-for-byte against the Python harness

Differences from the Python harness, on purpose:
* `free` is real. The Python bump allocator leaked about 2 MB per OTP request and ran out after a
  handful. Small blocks are reused; the library's 512 KiB work buffers are not (reusing them makes
  Unicorn retranslate its code on every call, about 5x slower), so `CoreAdi` rebuilds the VM when
  the 64 MiB heap is 75% full, carrying the store over.
* The scratch area is reset per top-level call.

Not done yet: the C ABI / JNI wrapper, the Android cross-build, provisioning and resync from Rust
(the `CoreAdi` methods exist; only OTP is checked against Python).

License note: the `unicorn-engine` crate is GPL-2.0.
