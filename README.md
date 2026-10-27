# os-findmy-emulation

This repository contains three projects:

- [`macOS-ADI-emulator`](macOS-ADI-emulator/README.md): Python package for the macOS 26 ADI daemon. This is the only project planned for release.
- [`native`](native/README.md): Rust implementation. The CLI has completed a live Apple login; live location retrieval and keychain recovery still need validation.
- [`app`](app/README.md): Android app built on the Rust library. Its Apple-facing flow has been verified.

Python tools: `tools/machoadi/` (including the `auth_probe.py` login driver), the shell wrappers in `tools/`, and their offline tests (`python -m unittest discover -s tools/tests`).

The Apple CoreADI binaries are not committed. Each project README explains which binary it needs and how to run it.

## License

Copyright (c) 2026 sacca. This repository is licensed under the [GNU GPL, version 2 only](LICENSE). The ADI emulators link [Unicorn](https://www.unicorn-engine.org/) (GPL-2.0; a few of its QEMU-derived files are GPL-2.0-only), so everything built from them, including the Android APK, is distributed under GPL-2.0. Some dependencies (for example `prost` and `ring`, Apache-2.0) have licences the FSF considers incompatible with GPL-2.0-only; the question is open. Third-party notices are in [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES).

Apple's CoreADI and `adid` binaries are not covered by this license and are not part of this repository; do not redistribute them or an APK that bundles them (the debug build embeds CoreADI).
