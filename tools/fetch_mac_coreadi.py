#!/usr/bin/env python3
"""Download and unpack Apple's Mac-lineage ADI library (CoreADI.framework).

Source: iTunes 12.8.3 for Mac (Apple KB DL1977), the last iTunes-for-Mac build
Apple still serves. The installer bundles CoreADI.pkg, whose CoreADI.framework
(4.19.0, i386 + x86_64) exports the same obfuscated ADI dispatcher as the
Windows (ADI.dll) and Android (libCoreADI.so) builds, but computes provisioning
and OTP/MID with a Mac device identity.

Everything lands under ext/ (gitignored). Stdlib only; requires curl and 7z.
Run from the repository root:

    python3 tools/fetch_mac_coreadi.py [--dest ext/itunes/mac]
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

DMG_URL = "https://secure-appldnld.apple.com/itunes12/041-56365-20210413-79A5AC6D-6B0A-46EC-B399-5A381183E3BE/iTunes12.8.3.dmg"
DMG_SHA256 = "dd08b9967db3e5847955fa168ce880303abf5f36de12abb2061e7ef1a25be214"

FRAMEWORK_REL = "System/Library/PrivateFrameworks/CoreADI.framework/Versions/A/CoreADI"
CPU_X86_64 = 0x01000007
CPU_I386 = 0x00000007
EXPECTED_EXPORTS = {"_cvu8io98wun", "_vdfut768ig"}
CPU_SLICE_NAMES = {CPU_X86_64: "x86_64", CPU_I386: "i386"}


def run(cmd: list[str]) -> None:
    print(f"[cmd] {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def unpack_cpio(data: bytes, out_dir: Path) -> list[Path]:
    """Extract a cpio archive ('newc' or 'odc') into out_dir.

    odc ('old ASCII', pre-SVR4, what Apple pkg Payloads use): magic(6) then
    dev, ino, mode, uid, gid, nlink, rdev (6 octal chars each), mtime(11),
    namesize(6), filesize(11) — 76-byte header, no padding. Directories carry
    no trailing slash here, so file type comes from the mode field; symlinks
    are materialized, hardlink twins without data are skipped.
    newc ('new ASCII'): magic(6) then 13 fields of 8 chars, 110-byte header,
    name and data padded to 4 bytes.
    """
    # widths after magic, mode idx, namesize idx, filesize idx, 4-byte padding
    FORMATS = {
        b"070707": ([6, 6, 6, 6, 6, 6, 6, 11, 6, 11], 2, 8, 9, False),
        b"070701": ([8] * 13, 1, 11, 6, True),
        b"070702": ([8] * 13, 1, 11, 6, True),
    }
    S_IFMT, S_IFDIR, S_IFLNK = 0o170000, 0o040000, 0o120000
    written: list[Path] = []
    seen_inodes: dict[tuple[int, ...], Path] = {}
    pos = 0
    while True:
        magic = data[pos : pos + 6]
        if magic not in FORMATS:
            msg = f"bad cpio magic at {pos:#x}"
            raise ValueError(msg)
        widths, mode_idx, namesize_idx, filesize_idx, padded = FORMATS[magic]
        pos += 6
        fields = []
        for width in widths:
            fields.append(int(data[pos : pos + width], 8))
            pos += width
        mode = fields[mode_idx]
        namesize = fields[namesize_idx]
        filesize = fields[filesize_idx]
        name = data[pos : pos + namesize - 1].decode()
        data_start = pos + namesize
        if padded:
            data_start = (data_start + 3) & ~3
        if name == "TRAILER!!!":
            break
        next_pos = data_start + filesize
        if padded:
            next_pos = (next_pos + 3) & ~3
        if name in ("", "."):
            pos = next_pos
            continue
        target = out_dir / name
        if mode & S_IFMT == S_IFDIR:
            target.mkdir(parents=True, exist_ok=True)
        elif mode & S_IFMT == S_IFLNK:
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                target.symlink_to(data[data_start : data_start + filesize].decode())
        else:
            inode_key = (fields[0], fields[1]) if magic == b"070707" else (fields[0], fields[7], fields[8])
            if filesize == 0 and inode_key in seen_inodes:
                pass  # hardlink twin; the data already lives at the first entry
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data[data_start : data_start + filesize])
                seen_inodes[inode_key] = target
                written.append(target)
        pos = next_pos
    return written


def slice_fat(fat_path: Path) -> dict[str, Path]:
    """Split a Mach-O universal binary into per-CPU slices written next to it."""
    data = fat_path.read_bytes()
    if data[:4] not in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        msg = f"{fat_path} is not a universal binary"
        raise ValueError(msg)
    _, nfat = struct.unpack(">II", data[:8])
    slices: dict[str, Path] = {}
    for i in range(nfat):
        cpu, _, off, size, _ = struct.unpack(">IIIII", data[8 + 20 * i : 28 + 20 * i])
        name = CPU_SLICE_NAMES.get(cpu)
        if name is None:
            continue
        out = fat_path.with_name(f"{fat_path.name}.{name}")
        out.write_bytes(data[off : off + size])
        slices[name] = out
    return slices


def macho_exports(path: Path) -> list[tuple[str, int]]:
    """Return (name, value) for defined external symbols of a Mach-O 64-bit slice."""
    data = path.read_bytes()
    if struct.unpack("<I", data[:4])[0] != 0xFEEDFACF:
        msg = f"{path} is not a 64-bit Mach-O"
        raise ValueError(msg)
    ncmds = struct.unpack("<I", data[16:20])[0]
    off = 32
    exports: list[tuple[str, int]] = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", data[off : off + 8])
        if cmd == 0x2:  # LC_SYMTAB
            symoff, nsyms, stroff, _ = struct.unpack("<IIII", data[off + 8 : off + 24])

            def cstr(x: int) -> str:
                end = data.index(b"\x00", stroff + x)
                return data[stroff + x : end].decode()

            for i in range(nsyms):
                strx, typ, _, _, value = struct.unpack(
                    "<IBBHQ", data[symoff + 16 * i : symoff + 16 * i + 16]
                )
                if (typ & 0x01) and (typ & 0x0E) == 0x0E:  # N_EXT | N_SECT
                    exports.append((cstr(strx), value))
        off += cmdsize
    return exports


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", default="ext/itunes/mac", help="output directory")
    args = parser.parse_args()

    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)
    dmg = dest / "iTunes12.8.3.dmg"

    if not dmg.exists():
        run(["curl", "-L", "--fail", "-o", str(dmg), DMG_URL])
    digest = sha256_file(dmg)
    print(f"{dmg}: sha256 {digest}")
    if digest != DMG_SHA256:
        msg = f"sha256 mismatch: expected {DMG_SHA256}"
        raise SystemExit(msg)

    pkg_dir = dest / "ipkg"
    if not (pkg_dir / "iTunes/Install iTunes.pkg").exists():
        run(["7z", "x", str(dmg), "iTunes/Install iTunes.pkg", f"-o{pkg_dir}", "-y"])
    coreadi_dir = dest / "coreadi-pkg"
    if not (coreadi_dir / "CoreADI.pkg/Payload").exists():
        run(
            [
                "7z", "x", str(pkg_dir / "iTunes/Install iTunes.pkg"),
                "CoreADI.pkg/*", f"-o{coreadi_dir}", "-y",
            ]
        )

    payload = coreadi_dir / "CoreADI.pkg/Payload"
    rootfs = coreadi_dir / "rootfs"
    if not (rootfs / FRAMEWORK_REL).exists():
        with tempfile.NamedTemporaryFile(suffix=".cpio", delete=False) as tmp:
            tmp.write(gzip.decompress(payload.read_bytes()))
            tmp_path = Path(tmp.name)
        print(f"[cpio] {tmp_path} -> {rootfs}")
        unpack_cpio(tmp_path.read_bytes(), rootfs)
        tmp_path.unlink()

    framework = rootfs / FRAMEWORK_REL
    slices = slice_fat(framework)
    for name, path in sorted(slices.items()):
        print(f"slice {name}: {path} ({path.stat().st_size} bytes)")

    x86_64 = slices.get("x86_64")
    if x86_64 is None:
        print("no x86_64 slice found", file=sys.stderr)
        return 1
    exports = macho_exports(x86_64)
    for name, value in exports:
        print(f"export {name} @ {value:#x}")
    if {name for name, _ in exports} != EXPECTED_EXPORTS:
        print(f"unexpected exports: {exports}", file=sys.stderr)
        return 1

    print("\ncorpus ready:")
    print(f"  framework : {framework}")
    print(f"  x86_64    : {x86_64}")
    print(f"  adid      : {rootfs / 'System/Library/PrivateFrameworks/CoreADI.framework/Versions/A/adid'}")
    print("  next      : tools/login.sh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
