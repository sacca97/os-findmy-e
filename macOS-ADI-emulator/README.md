# macOS ADI emulator

Python package that runs Apple's ADI daemon under Unicorn. Anisette.py uses the emulator for its ADI operations. The Apple CoreADI executable is not included.

Install it in the same Python environment as Anisette.py:

```sh
python -m pip install .
export MACOS_ADI_BINARY=/path/to/CoreADI.x86_64
```

Provision a state directory once, then check it or generate Anisette headers:

```sh
macos-adi-emulator provision
macos-adi-emulator status
macos-adi-emulator headers
```

`provision` contacts Apple. `status` and `headers` use the saved state. The default state is `~/.local/state/macos-adi`; set `MACOS_ADI_STATE` or pass `--state DIR` to use another directory. Existing `~/.local/state/anisette-mac26` state and `ANISETTE_MAC26_STATE` are still recognized.
