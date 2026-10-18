# macOS ADI emulator

Python package that runs the macOS 26 ADI daemon under Unicorn. Anisette.py uses it to generate Anisette data. The Apple CoreADI executable is not included.

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

`provision` contacts Apple. `status` and `headers` use the saved state. The default state is `~/.local/state/anisette-mac26`; set `ANISETTE_MAC26_STATE` or pass `--state DIR` to use another directory.
