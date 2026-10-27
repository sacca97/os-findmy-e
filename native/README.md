# Rust implementation

The Rust workspace contains the ADI emulator, Apple login and Find My code, a CLI, and Android bindings. The CLI has completed a live Apple login. Live location retrieval and keychain recovery still need validation.

The ADI emulator uses Apple's macOS CoreADI 4.19 x86_64 binary, which is not included.

## Build and test

From this directory:

```sh
cargo test --workspace
cargo build --release -p findmy-cli
cargo build --release -p sacca-openfinderlib
```

Build Android libraries from the repository root with the Android NDK installed:

```sh
NDK=/path/to/android-ndk ./native/android/build.sh arm64-v8a
```

The libraries are written to `native/android/jniLibs/`. The app's local build inputs are listed in [its README](../app/README.md). For manual Apple checks, see [LIVE-VALIDATION.md](LIVE-VALIDATION.md); network commands require `--yes`.

The Rust emulator depends on `unicorn-engine` (GPL-2.0), and the workspace is licensed GPL-2.0-only.
