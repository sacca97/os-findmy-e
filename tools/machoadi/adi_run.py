#!/usr/bin/env python3
"""Drive Apple's genuine Mac CoreADI whitebox under Unicorn (Linux).

Nothing about the ADI algorithm is reimplemented here: the Mach-O
``CoreADI.framework`` slice is mapped at its literal vmaddr and executed by
Unicorn, with a synthetic macOS userland (libc + CoreFoundation + a few ObjC
selectors) provided by ``stubs.MacStubs``.

The wire format between the caller and the dispatcher export
``_vdfut768ig(function_code, CoreADIParameters *)`` follows Dadoum/apple-crates
(`adi/src/core_adi.rs`, `adi/src/calls.rs`) -- the same framing the genuine
Windows/Android builds use:

    payload[0:4]   u32 big-endian encryption_type (1 = Clear)
    payload[4:8]   u32 big-endian marker (1)
    payload[8:]    bincode request message, fixed-int, big-endian
    CoreADIParameters { u8* payload; u32 input_size; u32 output_size; u32 flags; }

Pointers inside the message are serialised as their 8-byte big-endian numeric
value, so they must be real addresses *inside the emulated process*.

The dispatcher status is written to payload[0:4] as a big-endian i32; a negative
status means the operation failed and ``payload[0:4]`` holds the error code.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import EmulationError, Harness, MachOImage  # noqa: E402
from stubs import MacStubs  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
COREADI = Path(
    os.environ.get("COREADI_PATH")
    or ROOT
    / "ext/itunes/mac/coreadi-pkg/rootfs/System/Library/PrivateFrameworks"
    / "CoreADI.framework/Versions/A/CoreADI.x86_64"
)

# _vdfut768ig is at a different offset in every build, so the offset is looked up from the sha256
# of the file actually loaded. A build that is not listed is refused rather than run at a wrong
# entry point; COREADI_DISPATCH=0x... overrides the lookup for trying a new one.
BUILDS = {
    "2eafc3c79c7f41a8afbfbeaaf23ee5dab5ad5bda55ec8e54dbc0ddf1d20ce630": ("iTunes 12.8.3, CoreADI 4.19 (x86_64 slice)", 0x979A0),
    "6fe4b27f2d75b5f365917a92389bed75542f3ba08197f136262be3b34d19cb5c": ("macOS 15.8.1 24H32 (fat file)", 0x17BF60),
}


def identify_build(data: bytes) -> tuple[str, int]:
    """(name, dispatcher offset) for a CoreADI image; raises if the build is unknown."""
    digest = hashlib.sha256(data).hexdigest()
    override = os.environ.get("COREADI_DISPATCH")
    if override:
        return BUILDS.get(digest, ("unlisted build", 0))[0], int(override, 0)
    if digest not in BUILDS:
        raise EmulationError(f"unknown CoreADI build sha256 {digest}; set COREADI_DISPATCH to its _vdfut768ig offset")
    return BUILDS[digest]


# Function codes (Dadoum/apple-crates, `adi/src/calls.rs`).
MAGIC = {
    "Initialize": 0x12DB31C5,
    "TearDown": 0x08C0FE9E,
    "IsMachineProvisioned": 0xB0EDA7AF,
    "GetAllProvisionedAccounts": 0x72096FE6,
    "ProvisioningStart": 0x716BD86C,
    "ProvisioningEnd": 0x0B2B3196,
    "SessionDestroy": 0x55A637C0,
    "SetIDMSRouting": 0x632B8D6E,
    "GetIDMSRouting": 0x85FE63B0,
    "Synchronize": 0xA54951EC,
    "Erase": 0x7715488C,
    "RequestOTP": 0xCFE0B46A,
    "StorageDispose": 0x3E58E7F9,
    "AccountsDispose": 0x9679D4B5,
    "Gen2FACode": 0x385B2CE8,
    # Android-only (present here only to confirm they are *absent* on macOS).
    "SetAndroidID": 0xC774D292,
    "SetProvisioningPath": 0xB23C691E,
}

# Known dispatcher/operation error codes.
ERR_NOT_PROVISIONED = -45061
ERR_GENERIC = -45002


def w32(value: int) -> bytes:
    return struct.pack(">I", value & 0xFFFFFFFF)


def w64(value: int) -> bytes:
    return struct.pack(">Q", value & 0xFFFFFFFFFFFFFFFF)


def wi64(value: int) -> bytes:
    return struct.pack(">q", value)


def s32(value: int) -> int:
    return value - 0x1_0000_0000 if value >= 0x8000_0000 else value


@dataclass
class Result:
    name: str
    rc: int
    ret: int
    outputs: dict[str, object] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.rc >= 0 and self.ret >= 0

    def __str__(self) -> str:
        status = "ok " if self.ok else "ERR"
        out = " ".join(f"{k}={v}" for k, v in self.outputs.items())
        return f"{self.name:24} {status} rc={self.rc:>7} ret={self.ret:>7} {out}".rstrip()


class CoreADI:
    """A live Mac ADI dispatcher running on a synthetic macOS."""

    def __init__(self, path: Path = COREADI, *, log: bool = False) -> None:
        image = MachOImage(str(path))
        self.build, self.dispatch = identify_build(image.data)
        self.harness = Harness(image)
        self.stubs = MacStubs(self.harness, log=log)
        self.last_insns = 0

    # -- low level --------------------------------------------------------
    def _dispatch(self, name: str, message: bytes) -> tuple[int, int, int]:
        h = self.harness
        buf = bytearray(max(0x800, 8 + len(message)))
        buf[3] = 1  # encryption_type = Clear
        buf[7] = 1  # marker = 1
        buf[8 : 8 + len(message)] = message
        buf_addr = h.scratch(len(buf))
        h.mem_write(buf_addr, bytes(buf))

        params = h.scratch(0x20)
        h.mem_write(params, b"\x00" * 0x20)
        h.write_u64(params + 0x00, buf_addr)
        h.write_u32(params + 0x08, 8 + len(message))
        h.write_u32(params + 0x0C, 4)
        h.write_u32(params + 0x10, 0)

        rc = s32(h.invoke(self.dispatch, [MAGIC[name], params]))
        ret = struct.unpack(">i", h.mem_read(buf_addr, 4))[0]
        h.mem_write(buf_addr + 4, b"\x00" * 4)
        return rc, ret, buf_addr

    def _out_ptr(self, value: int = 0) -> int:
        """A fresh 8-byte cell whose address can be handed to the dispatcher."""
        addr = self.harness.scratch(8)
        self.harness.write_u64(addr, value)
        return addr

    def _out_u32(self, value: int = 0) -> int:
        addr = self.harness.scratch(8)
        self.harness.write_u32(addr, value)
        return addr

    def _read_u64(self, addr: int) -> int:
        return self.harness.read_u64(addr)

    def _read_u32(self, addr: int) -> int:
        return self.harness.read_u32(addr)

    def _slice(self, ptr_addr: int, len_addr: int) -> bytes:
        ptr = self._read_u64(ptr_addr)
        length = self._read_u32(len_addr)
        if not ptr or not length:
            return b""
        return bytes(self.harness.mem_read(ptr, length))

    # -- operations -------------------------------------------------------
    def initialize(self) -> Result:
        rc, ret, _ = self._dispatch("Initialize", b"")
        return Result("Initialize", rc, ret)

    def teardown(self) -> Result:
        rc, ret, _ = self._dispatch("TearDown", b"")
        return Result("TearDown", rc, ret)

    def is_machine_provisioned(self, ds_id: int) -> Result:
        rc, ret, _ = self._dispatch("IsMachineProvisioned", wi64(ds_id))
        return Result("IsMachineProvisioned", rc, ret, {"ds_id": ds_id})

    def get_all_provisioned_accounts(self) -> Result:
        list_ptr = self._out_ptr()
        list_len = self._out_u32()
        rc, ret, _ = self._dispatch(
            "GetAllProvisionedAccounts", w64(list_ptr) + w64(list_len)
        )
        return Result("GetAllProvisionedAccounts", rc, ret)

    def request_otp(self, ds_id: int) -> Result:
        mid_ptr, mid_len = self._out_ptr(), self._out_u32()
        otp_ptr, otp_len = self._out_ptr(), self._out_u32()
        rc, ret, _ = self._dispatch(
            "RequestOTP",
            wi64(ds_id)
            + w64(mid_ptr)
            + w64(mid_len)
            + w64(otp_ptr)
            + w64(otp_len),
        )
        mid_n, otp_n = self._read_u32(mid_len), self._read_u32(otp_len)
        mid = self._slice(mid_ptr, mid_len)
        otp = self._slice(otp_ptr, otp_len)
        # The library hands back pointers into its own storage; release them so
        # repeated calls in one process do not accumulate.
        if mid and otp:
            self.storage_dispose(self._read_u64(mid_ptr))
        return Result(
            "RequestOTP",
            rc,
            ret,
            {
                "mid_len": mid_n,
                "otp_len": otp_n,
                "mid": mid,
                "otp": otp,
            },
        )

    def provisioning_start(self, ds_id: int, spim: bytes = b"") -> Result:
        spim_buf = self.harness.scratch(max(len(spim), 16))
        if spim:
            self.harness.mem_write(spim_buf, spim)
        cpim_ptr, cpim_len = self._out_ptr(), self._out_u32()
        session = self._out_u32()
        rc, ret, _ = self._dispatch(
            "ProvisioningStart",
            wi64(ds_id)
            + w64(spim_buf)
            + w32(len(spim))
            + w64(cpim_ptr)
            + w64(cpim_len)
            + w64(session),
        )
        return Result(
            "ProvisioningStart",
            rc,
            ret,
            {
                "spim_len": len(spim),
                "cpim_len": self._read_u32(cpim_len),
                "session": self._read_u32(session),
                "cpim": self._slice(cpim_ptr, cpim_len),
                "session_id": self._read_u32(session),
            },
        )

    def provisioning_end(self, session: int, ptm: bytes, tk: bytes) -> Result:
        ptm_buf = self.harness.scratch(max(len(ptm), 16))
        if ptm:
            self.harness.mem_write(ptm_buf, ptm)
        tk_buf = self.harness.scratch(max(len(tk), 16))
        if tk:
            self.harness.mem_write(tk_buf, tk)
        rc, ret, _ = self._dispatch(
            "ProvisioningEnd",
            w32(session)
            + w64(ptm_buf)
            + w32(len(ptm))
            + w64(tk_buf)
            + w32(len(tk)),
        )
        return Result(
            "ProvisioningEnd",
            rc,
            ret,
            {"session": session, "ptm_len": len(ptm), "tk_len": len(tk)},
        )

    def synchronize(self, ds_id: int, sim: bytes) -> Result:
        sim_buf = self.harness.scratch(max(len(sim), 16))
        if sim:
            self.harness.mem_write(sim_buf, sim)
        mid_ptr, mid_len = self._out_ptr(), self._out_u32()
        srm_ptr, srm_len = self._out_ptr(), self._out_u32()
        rc, ret, _ = self._dispatch(
            "Synchronize",
            wi64(ds_id)
            + w64(sim_buf)
            + w32(len(sim))
            + w64(mid_ptr)
            + w64(mid_len)
            + w64(srm_ptr)
            + w64(srm_len),
        )
        return Result(
            "Synchronize",
            rc,
            ret,
            {
                "mid_len": self._read_u32(mid_len),
                "srm_len": self._read_u32(srm_len),
                "mid": self._slice(mid_ptr, mid_len),
                "srm": self._slice(srm_ptr, srm_len),
            },
        )

    def storage_dispose(self, ptr: int) -> Result:
        rc, ret, _ = self._dispatch("StorageDispose", w64(ptr))
        return Result("StorageDispose", rc, ret)

    def erase(self, ds_id: int) -> Result:
        rc, ret, _ = self._dispatch("Erase", wi64(ds_id))
        return Result("Erase", rc, ret)

    def set_routing(self, ds_id: int, routing: int) -> Result:
        rc, ret, _ = self._dispatch("SetIDMSRouting", wi64(ds_id) + w64(routing))
        return Result("SetIDMSRouting", rc, ret, {"routing": routing})

    def get_routing(self, ds_id: int) -> Result:
        route = self._out_ptr()
        rc, ret, _ = self._dispatch("GetIDMSRouting", wi64(ds_id) + w64(route))
        return Result("GetIDMSRouting", rc, ret, {"routing": self._read_u64(route)})

    def gen_2fa(self, ds_id: int) -> Result:
        code = self._out_u32()
        rc, ret, _ = self._dispatch("Gen2FACode", wi64(ds_id) + w64(code))
        return Result("Gen2FACode", rc, ret, {"code": self._read_u32(code)})

    # -- convenience ------------------------------------------------------
    def __enter__(self) -> CoreADI:
        return self

    def __exit__(self, *exc: object) -> None:
        try:
            self.teardown()
        except EmulationError:
            pass


def _probe(args: argparse.Namespace) -> int:
    adi = CoreADI(log=args.log)
    ds_id = args.ds_id
    steps = [
        adi.initialize,
        lambda: adi.is_machine_provisioned(ds_id),
        lambda: adi.get_all_provisioned_accounts(),
        lambda: adi.get_routing(ds_id),
        lambda: adi.request_otp(ds_id),
        lambda: adi.provisioning_start(ds_id),
        lambda: adi.gen_2fa(ds_id),
        adi.teardown,
    ]
    for step in steps:
        try:
            print(step())
        except EmulationError as exc:  # noqa: BLE001
            print(f"  FAILED: {exc}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ds-id", type=int, default=-2, help="DSID (Grand Slam uses -2)")
    ap.add_argument("--log", action="store_true", help="log the synthetic syscalls")
    return _probe(ap.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
