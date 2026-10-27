#!/usr/bin/env python3
"""Pack a provisioned machine state (the Python tools' layout) into one JSON file the app can import.

    python3 app/tools/pack_state.py STATE_DIR OUT.machine.json

STATE_DIR holds `identity.json` and `store/` (what `tools/machoadi/mac_anisette.py provision` writes).
The output is a CREDENTIAL (it is the machine Apple knows). Keep it out of git and out of logs; the app
must keep it in Keystore-backed storage. Format (version 1):

    { "version": 1,
      "host_uuid": "<32 hex>",                 -> CoreAdi.setHostUuid (16 bytes)
      "identity": { device_id, local_user_uuid, client_info, serial, routing, provisioned_at? },
      "store_export_b64": "<base64>" }         -> CoreAdi.importStore (the format exportStore() returns:
                                                  per file: u16 BE name length, name, u32 BE length, data)
"""
import base64, json, struct, sys
from pathlib import Path

def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__); return 2
    state, out = Path(sys.argv[1]), Path(sys.argv[2])
    ident = json.loads((state / "identity.json").read_text())
    blob = bytearray()
    for f in sorted((state / "store").glob("*")):
        if f.name == "adi.pb" or not f.is_file():   # the legacy whole-machine blob makes the library report "unprovisioned"
            continue
        name, data = f.name.encode(), f.read_bytes()
        blob += struct.pack(">H", len(name)) + name + struct.pack(">I", len(data)) + data
    uuid = bytes.fromhex(ident["host_uuid"])
    assert len(uuid) == 16, "host_uuid must be 16 bytes"
    keep = ("device_id", "local_user_uuid", "client_info", "serial", "routing", "provisioned_at")
    doc = {"version": 1, "host_uuid": ident["host_uuid"],
           "identity": {k: ident[k] for k in keep if k in ident},
           "store_export_b64": base64.b64encode(bytes(blob)).decode()}
    out.write_text(json.dumps(doc, indent=2) + "\n")
    out.chmod(0o600)
    print(f"wrote {out} ({out.stat().st_size} bytes, {len(blob)} bytes of store)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
