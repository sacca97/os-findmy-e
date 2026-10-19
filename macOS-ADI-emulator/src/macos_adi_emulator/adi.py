"""Run Apple's macOS 26 ``adid`` executable under Unicorn and call its ADI API.

The daemon is an x86_64 Mach-O executable that accepts requests over XPC. This
module supplies its macOS process environment, starts the daemon, and encodes
ADI requests. Set ``MACOS_ADI_BINARY`` to the separately obtained executable;
the Apple binary is not part of this package.
"""
from __future__ import annotations

import os
import struct
import time
from pathlib import Path

from . import harness as H
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RDI,
    UC_X86_REG_RSI,
    UC_X86_REG_RDX,
    UC_X86_REG_RCX,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
)
from .harness import EmulationError, Harness, MachOImage
from .stubs import MacStubs

DEFAULT_BINARY = Path(__file__).with_name("CoreADI.x86_64")
MAIN = 0x100030EB0  # `start`

# `xpc_type_dictionary` and friends are imports whose *address* is the value.
H._DATA_SYMBOLS |= {
    "kCFAllocatorNull", "kCFRunLoopCommonModes", "NSConcreteGlobalBlock",
    "NSConcreteStackBlock", "CFConstantStringClassReference", "dispatch_main_q",
    "os_log_default", "mach_task_self_", "xpc_type_dictionary", "xpc_type_error",
    "xpc_error_connection_invalid",
}

CLEAR = 1
PROTOCOL_MARKER = 1  # the third u32 the daemon expects (`[0,0,0,1]`)

MAGIC = {
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
    "Gen2FACode": 0x385B2CE8,
}

ERRORS = {
    -45001: "InvalidParameters", -45002: "InvalidParameters2", -45003: "InvalidTK",
    -45006: "PTMTKPairMismatch", -45012: "ThreadingError", -45016: "UnreachableADID",
    -45017: "MachMessageError", -45018: "InvalidEncryptionScheme",
    -45019: "InvalidFunctionCode", -45020: "InvalidParameterBody",
    -45025: "InvalidSession", -45026: "EmptySession",
    -45031: "InvalidEncryptedBlockHeader", -45032: "InvalidEncryptedBlockLength",
    -45033: "InvalidEncryptedBlockContent", -45034: "InvalidADICall",
    -45036: "InvalidTime", -45046: "InvalidHardwareIdentifiers", -45054: "FilesystemError",
    -45061: "NotProvisioned", -45062: "NoProvisioningToErase", -45063: "PendingSession",
    -45066: "TerminatedSession", -45075: "LibraryLoadingError", -45076: "UnsupportedCoreADI",
}

def encode_i64(v: int) -> bytes:
    return struct.pack(">q", v)


def encode_u32(v: int) -> bytes:
    return struct.pack(">I", v & 0xFFFFFFFF)


def encode_u64(v: int) -> bytes:
    return struct.pack(">Q", v & 0xFFFFFFFFFFFFFFFF)


def encode_bytes(b: bytes) -> bytes:
    """A `Vec<u8>`: u32 big-endian length followed by the bytes."""
    return encode_u32(len(b)) + bytes(b)


class _Image(MachOImage):
    """Map the executable's segments, skipping the 4 GiB `__PAGEZERO`."""

    def map_into(self, uc):
        for seg in self.macho.segments:
            if seg.name == "__PAGEZERO":
                continue
            size = (seg.vmsize + 0xFFF) // 0x1000 * 0x1000
            uc.mem_map(seg.vmaddr, size)
            if seg.filesize:
                uc.mem_write(seg.vmaddr, self.data[seg.fileoff:seg.fileoff + seg.filesize])


class _Daemon(Harness):
    """Harness that stops when the daemon's `main` reaches `CFRunLoopRun`."""

    reached_runloop = False

    def _hook_code(self, uc, address, size, user):
        sym = self._stub_by_index.get(address)
        if sym is not None and H._norm(sym) == "CFRunLoopRun":
            self.reached_runloop = True
            uc.emu_stop()
            return
        return super()._hook_code(uc, address, size, user)


def _arg(h: Harness, i: int) -> int:
    regs = (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
            UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9)
    return h.uc.reg_read(regs[i])


class AdidError(RuntimeError):
    """A non-zero ADI status returned by the daemon."""

    def __init__(self, code: int):
        self.code = code
        name = ERRORS.get(code, "Unknown")
        super().__init__(f"adid returned {code} ({name})")


class Adid:
    """A booted macOS 26 `adid` daemon that answers XPC requests."""

    def __init__(self, binary: Path | str | None = None, *, host_uuid: bytes | None = None,
                 setup_user: bool = True):
        binary = Path(binary or os.environ.get("MACOS_ADI_BINARY", DEFAULT_BINARY))
        if not binary.is_file():
            raise FileNotFoundError(
                f"macOS 26 ADI binary not found at {binary}; set MACOS_ADI_BINARY to the extracted executable"
            )
        self.harness = _Daemon(_Image(str(binary), data=binary.read_bytes()))
        self.stubs = MacStubs(self.harness)
        if host_uuid is not None:
            self.stubs.hostuuid = host_uuid
        if setup_user:
            # A machine that has passed Setup Assistant.
            self.stubs.files["/var/db/.AppleSetupUser"] = bytearray(b"")

        self._objects: dict[int, dict] = {}
        self._state: dict = {"listener_block": None, "peer_block": None, "reply": None}
        self._client = {
            "euid": 501, "pid": 1234,
            "path": "/System/Library/PrivateFrameworks/AuthKit.framework/Support/akd",
            "adi_client": "1",
        }
        self._install_stubs()
        self._boot()

    # -- XPC / libc model -------------------------------------------------
    @property
    def _h(self) -> Harness:
        return self.harness

    def _object(self, kind: str, **kw) -> int:
        addr = self._h.object(0x40)
        self._objects[addr] = dict(kind=kind, **kw)
        return addr

    @staticmethod
    def _cstr(h: Harness, addr: int) -> str:
        return h.read_cstr(addr) if addr else ""

    def _cell(self, name: str) -> int:
        h = self._h
        return h._data_addr[name if name in h._data_addr else "_" + name]

    def _install_stubs(self) -> None:
        h = self._h
        cl = self._client

        def newobj(kind, **kw):
            return self._object(kind, **kw)

        def mmap(hh: Harness) -> int:
            length = (_arg(hh, 1) + 0xFFF) & ~0xFFF
            addr = hh.heap_alloc(length, alignment=0x1000)
            # Anonymous mappings must be zero-filled, including reused memory.
            hh.mem_write(addr, bytes(length))
            return addr

        def munmap(hh: Harness) -> int:
            hh.heap_free(_arg(hh, 0))
            return 0

        def sysctlbyname(hh: Harness) -> int:
            # The daemon checks kern.hv_vmm_present and bails in a VM; answer 0.
            oldp, oldlenp = _arg(hh, 1), _arg(hh, 2)
            if oldp and oldlenp:
                n = hh.read_u64(oldlenp)
                hh.mem_write(oldp, b"\0" * min(n, 8))
            return 0

        def set_handler(hh: Harness) -> int:
            conn, blk = _arg(hh, 0), _arg(hh, 1)
            kind = self._objects.get(conn, {}).get("kind")
            copy = hh.object(0x30)
            hh.mem_write(copy, hh.mem_read(blk, 0x30))
            self._state["listener_block" if kind == "listener" else "peer_block"] = copy
            return 0

        def xpc_get_type(hh: Harness) -> int:
            kind = self._objects.get(_arg(hh, 0), {}).get("kind")
            name = "_xpc_type_dictionary" if kind in ("dict", "reply") else "_xpc_type_error"
            return self._cell(name)

        def get_data(hh: Harness) -> int:
            msg, key, lenp = _arg(hh, 0), _arg(hh, 1), _arg(hh, 2)
            data = self._objects[msg]["data"].get(self._cstr(hh, key))
            if data is None:
                return 0
            p = hh.scratch(len(data) + 8)
            hh.mem_write(p, data)
            if lenp:
                hh.write_u64(lenp, len(data))
            return p

        def set_data(hh: Harness) -> int:
            reply, key, p, n = _arg(hh, 0), _arg(hh, 1), _arg(hh, 2), _arg(hh, 3)
            self._objects[reply]["data"][self._cstr(hh, key)] = hh.mem_read(p, n)
            return 0

        def send_reply(hh: Harness) -> int:
            self._state["reply"] = dict(self._objects[_arg(hh, 0)]["data"])
            return 0

        def entitlement(hh: Harness) -> int:
            name = self._objects.get(_arg(hh, 1), {}).get("s", "?")
            if name in ("adi-client", "com.apple.private.adid"):
                return newobj("cfstr", s=cl["adi_client"])
            return hh.read_u64(hh._data_addr["_kCFBooleanTrue"])

        def audit_token(hh: Harness) -> int:
            buf = _arg(hh, 1)
            if buf:
                hh.mem_write(buf, struct.pack("<8I", cl["euid"], cl["euid"], 0, cl["euid"],
                                              0, cl["pid"], 0, 0))
            return 0

        def au32(hh: Harness) -> int:
            for i, v in enumerate((cl["euid"], cl["euid"], 0, cl["euid"], 0, cl["pid"])):
                p = _arg(hh, i)
                if p:
                    hh.write_u32(p, v)
            return 0

        def cfstr_create(hh: Harness) -> int:
            return newobj("cfstr", s=self._cstr(hh, _arg(hh, 1)))

        def cf_get_typeid(hh: Harness) -> int:
            return {"cfstr": 7, "cfnum": 22, "cfdict": 18}.get(
                self._objects.get(_arg(hh, 0), {}).get("kind"), 99)

        def cf_getcstring(hh: Harness) -> int:
            o, buf, size = _arg(hh, 0), _arg(hh, 1), _arg(hh, 2)
            sv = self._objects[o]["s"].encode() + b"\0"
            hh.mem_write(buf, sv[:size])
            return 1

        def strtoul(hh: Harness) -> int:
            p, endp, base = _arg(hh, 0), _arg(hh, 1), _arg(hh, 2)
            digits = ""
            for ch in self._cstr(hh, p):
                if ch.isalnum():
                    digits += ch
                else:
                    break
            try:
                value = int(digits, base or 10)
            except ValueError:
                value, digits = 0, ""
            if endp:
                hh.write_u64(endp, p + len(digits))
            return value

        def pidpath(hh: Harness) -> int:
            buf = _arg(hh, 1)
            path = cl["path"].encode()
            hh.mem_write(buf, path + b"\0")
            return len(path)

        handlers = {
            "os_transaction_create": lambda hh: hh.object(0x20),
            "os_release": lambda hh: 0,
            "pthread_set_qos_class_self_np": lambda hh: 0,
            "sysconf": lambda hh: 4096,
            "mmap": mmap,
            "munmap": munmap,
            "ptrace": lambda hh: 0,
            "sched_yield": lambda hh: 0,
            "getpid": lambda hh: 4242,
            "getuid": lambda hh: 501,
            "umask": lambda hh: 0o022,
            "os_log_type_enabled": lambda hh: 0,
            "os_log_impl": lambda hh: 0,
            "sysctlbyname": sysctlbyname,
            "xpc_connection_create_mach_service": lambda hh: newobj("listener"),
            "xpc_connection_set_event_handler": set_handler,
            "xpc_connection_set_target_queue": lambda hh: 0,
            "xpc_connection_activate": lambda hh: 0,
            "xpc_connection_resume": lambda hh: 0,
            "xpc_connection_cancel": lambda hh: 0,
            "xpc_get_type": xpc_get_type,
            "xpc_dictionary_get_data": get_data,
            "xpc_dictionary_set_data": set_data,
            "xpc_dictionary_create_reply": lambda hh: newobj("reply", data={}),
            "xpc_dictionary_send_reply": send_reply,
            "xpc_dictionary_get_audit_token": audit_token,
            "xpc_dictionary_get_value": lambda hh: 0,
            "xpc_dictionary_get_uint64": lambda hh: 0,
            "xpc_dictionary_get_string": lambda hh: 0,
            "audit_token_to_au32": au32,
            "audit_token_to_euid": lambda hh: cl["euid"],
            "CFStringCreateWithCStringNoCopy": cfstr_create,
            "CFNumberGetTypeID": lambda hh: 22,
            "CFStringGetTypeID": lambda hh: 7,
            "CFDictionaryGetTypeID": lambda hh: 18,
            "CFGetTypeID": cf_get_typeid,
            "CFStringGetCString": cf_getcstring,
            "strtoul": strtoul,
            "proc_pidpath": pidpath,
            "SecTaskCreateWithAuditToken": lambda hh: hh.object(0x20),
            "SecTaskCopyValueForEntitlement": entitlement,
            "xpc_transaction_begin": lambda hh: 0,
            "xpc_transaction_end": lambda hh: 0,
            "xpc_release": lambda hh: 0,
            "CFRunLoopGetMain": lambda hh: hh.object(0x20),
            "CFRunLoopGetCurrent": lambda hh: hh.object(0x20),
            "CFFileDescriptorCreate": lambda hh: hh.object(0x20),
            "CFFileDescriptorCreateRunLoopSource": lambda hh: hh.object(0x20),
            "kqueue": lambda hh: 0x34,
            "kevent": lambda hh: 0,
            "signal": lambda hh: 0,
            "CFRunLoopAddSource": lambda hh: 0,
            "CFFileDescriptorEnableCallBacks": lambda hh: 0,
            "gettimeofday": self._stub_gettimeofday,
        }
        for name, fn in handlers.items():
            h.register(name, fn)

    def _stub_gettimeofday(self, hh: Harness) -> int:
        tv = _arg(hh, 0)
        now = time.time()
        sec = int(now)
        usec = int((now - sec) * 1_000_000)
        if tv:
            hh.write_u64(tv, sec)
            hh.write_u64(tv + 8, usec)
        return 0

    def _boot(self) -> None:
        h = self._h
        argv0 = h.scratch(16)
        h.mem_write(argv0, b"/usr/libexec/adid\0")
        argv = h.scratch(16)
        h.write_u64(argv, argv0)
        h.write_u64(argv + 8, 0)

        h.invoke(MAIN, [1, argv])
        if not h.reached_runloop:
            raise EmulationError("adid did not reach CFRunLoopRun")

        peer = h.object(0x40)
        self._objects[peer] = dict(kind="peer")
        self._invoke_block(self._state["listener_block"], peer)

    def _invoke_block(self, block: int, *args) -> int:
        fn = self._h.read_u64(block + 16)
        return self._h.invoke(fn, [block, *args])

    # -- protocol ---------------------------------------------------------
    def call(self, name: str, *args: bytes) -> tuple[int, bytes]:
        """Send one request; return (adi_status, reply_payload)."""
        header = encode_u32(CLEAR) + encode_u32(MAGIC[name]) + encode_u32(PROTOCOL_MARKER)
        payload = header + b"".join(args)

        # XPC/CF wrapper objects and input buffers belong to this synchronous
        # request. Keep the boot objects and daemon heap (including sessions).
        h = self._h
        scratch, objects, url = h._scratch_cur, h._obj_cur, self.stubs._next_url
        saved_objects, saved_urls = self._objects.copy(), self.stubs.urls.copy()
        try:
            self._state["reply"] = None
            message = h.object(0x40)
            self._objects[message] = dict(kind="dict", data={"data": payload})
            self._invoke_block(self._state["peer_block"], message)
            reply = self._state["reply"]
            if not reply or "data" not in reply:
                raise AdidError(-45017)  # no reply == the daemon rejected the message
            data = reply["data"]
            status = struct.unpack(">i", data[:4])[0]
            return status, data[4:]
        finally:
            h._scratch_cur, h._obj_cur, self.stubs._next_url = scratch, objects, url
            self._objects, self.stubs.urls = saved_objects, saved_urls
            self._state["reply"] = None

    def must(self, name: str, *args: bytes) -> bytes:
        status, payload = self.call(name, *args)
        if status != 0:
            raise AdidError(status)
        return payload

    # -- ADIProxy surface -------------------------------------------------
    def is_machine_provisioned(self, ds_id: int) -> bool:
        status, _ = self.call("IsMachineProvisioned", encode_i64(ds_id))
        if status == 0:
            return True
        if status == -45061:  # NotProvisioned
            return False
        raise AdidError(status)

    def get_all_provisioned_accounts(self) -> list[dict]:
        payload = self.must("GetAllProvisionedAccounts")
        if len(payload) < 4:
            # An empty (or absent) vector: the daemon sends a bare success.
            return []
        (count,) = struct.unpack(">I", payload[:4])
        accounts = []
        off = 4
        for _ in range(count):
            (ds_id,) = struct.unpack(">q", payload[off:off + 8])
            (mid_len,) = struct.unpack(">I", payload[off + 8:off + 12])
            (otp_len,) = struct.unpack(">I", payload[off + 12:off + 16])
            off += 16
            mid = payload[off:off + mid_len]
            off += mid_len
            otp = payload[off:off + otp_len]
            off += otp_len
            accounts.append({"ds_id": ds_id, "mid": mid, "otp": otp})
        return accounts

    def start_provisioning(self, ds_id: int, spim: bytes) -> tuple[bytes, int]:
        payload = self.must("ProvisioningStart", encode_i64(ds_id), encode_bytes(spim))
        (cpim_len,) = struct.unpack(">I", payload[:4])
        cpim = payload[4:4 + cpim_len]
        # The daemon appends the session id (and possibly more) after the CPIM.
        rest = payload[4 + cpim_len:]
        session = struct.unpack(">I", rest[:4])[0] if len(rest) >= 4 else 0
        return cpim, session

    def end_provisioning(self, session: int, ptm: bytes, tk: bytes) -> None:
        self.must("ProvisioningEnd", encode_u32(session), encode_bytes(ptm), encode_bytes(tk))

    def destroy_provisioning_session(self, session: int) -> None:
        self.must("SessionDestroy", encode_u32(session))

    def set_idms_routing(self, ds_id: int, routing: int) -> None:
        self.must("SetIDMSRouting", encode_i64(ds_id), encode_u64(routing))

    def get_idms_routing(self, ds_id: int) -> int:
        payload = self.must("GetIDMSRouting", encode_i64(ds_id))
        return struct.unpack(">Q", payload[:8])[0]

    def synchronize(self, ds_id: int, sim: bytes) -> tuple[bytes, bytes]:
        payload = self.must("Synchronize", encode_i64(ds_id), encode_bytes(sim))
        (mid_len,) = struct.unpack(">I", payload[:4])
        mid = payload[4:4 + mid_len]
        off = 4 + mid_len
        (srm_len,) = struct.unpack(">I", payload[off:off + 4])
        srm = payload[off + 4:off + 4 + srm_len]
        return mid, srm

    def erase(self, ds_id: int) -> None:
        self.must("Erase", encode_i64(ds_id))

    def request_otp(self, ds_id: int) -> tuple[bytes, bytes]:
        payload = self.must("RequestOTP", encode_i64(ds_id))
        (mid_len,) = struct.unpack(">I", payload[:4])
        mid = payload[4:4 + mid_len]
        off = 4 + mid_len
        (otp_len,) = struct.unpack(">I", payload[off:off + 4])
        otp = payload[off + 4:off + 4 + otp_len]
        return mid, otp

    def generate_2fa_code(self, ds_id: int) -> int:
        payload = self.must("Gen2FACode", encode_i64(ds_id))
        return struct.unpack(">I", payload[:4])[0]
