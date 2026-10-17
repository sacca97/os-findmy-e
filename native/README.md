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

Not done yet: the C ABI / JNI wrapper, the Android cross-build, provisioning and resync from Rust
(the `CoreAdi` methods exist; only OTP is checked against Python).

License note: the `unicorn-engine` crate is GPL-2.0.
