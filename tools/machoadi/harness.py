"""Unicorn-backed x86_64 Mach-O runtime for the Mac CoreADI whitebox.

The goal is *observability*, not reimplementation: run Apple's own (old, Intel,
pre-chained-fixups) CoreADI binary under emulation so the ADI dispatcher can be
tracing-instrumented, then use the traces to write a clean-room surrogate.

Loading strategy
----------------
The dylib's preferred base is 0, so we map every segment at its literal
``vmaddr`` and skip rebasing entirely (slide == 0). Import slots (dyld binds)
are redirected to a synthetic stub page: each imported symbol gets a unique
address holding ``ret``; a code hook fires on the way in, runs a Python handler,
and the ``ret`` returns to the caller (correct for both ``call`` and tail-call
``jmp`` positions).

Data imports (``kCF*`` constants, ``___stack_chk_guard``, ...) instead point at
a per-symbol 8-byte cell so normal dereferences see a plausible object.
"""

from __future__ import annotations

import logging
import struct
from collections.abc import Callable
from typing import Any

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_MEM_FETCH_UNMAPPED,
    UC_MEM_READ_UNMAPPED,
    UC_MEM_WRITE_UNMAPPED,
    UC_MODE_64,
    Uc,
)
from unicorn.x86_const import (
    UC_X86_REG_EFLAGS,
    UC_X86_REG_R10,
    UC_X86_REG_R11,
    UC_X86_REG_R12,
    UC_X86_REG_R13,
    UC_X86_REG_R14,
    UC_X86_REG_R15,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RAX,
    UC_X86_REG_RBP,
    UC_X86_REG_RBX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDI,
    UC_X86_REG_RDX,
    UC_X86_REG_RIP,
    UC_X86_REG_RSI,
    UC_X86_REG_RSP,
)

from macho import MachO

logger = logging.getLogger(__name__)

PAGE = 0x1000

# --- emulator address layout (kept well clear of the 0-based image) --------
RETURN_ADDRESS = 0x40000000
HEAP_ADDRESS = 0x40010000
HEAP_SIZE = 0x01000000
STACK_ADDRESS = 0x50000000
STACK_SIZE = 0x00200000
STUB_ADDRESS = 0x60000000
STUB_SIZE = 0x00020000
DATA_ADDRESS = 0x60020000
DATA_SIZE = 0x00020000
SCRATCH_ADDRESS = 0x60040000
SCRATCH_SIZE = 0x00040000
OBJECT_ADDRESS = 0x60080000
OBJECT_SIZE = 0x00040000

_STUB_SLOT = 0x10  # bytes between adjacent stubs
_RET = b"\xc3"

# Imports that denote a *variable* rather than a function entry point.
# Keys are normalised (leading Mach-O underscores stripped).
_DATA_SYMBOLS = {
    "stack_chk_guard",
    "kCFAllocatorDefault",
    "kCFBooleanFalse",
    "kCFBooleanTrue",
    "kCFErrorDomainOSStatus",
    "kCFURLFileSecurityKey",
    "kCFURLIsDirectoryKey",
    "kCFURLIsHiddenKey",
    "kCFURLTypeIdentifierKey",
    "kUTTypePlainText",
}


def _norm(symbol: str) -> str:
    """Strip Mach-O's leading underscores for handler/table lookup."""
    return symbol.lstrip("_")


def _is_data_symbol(symbol: str) -> bool:
    return _norm(symbol) in _DATA_SYMBOLS

_ARG_REGS = (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9)


class EmulationError(RuntimeError):
    pass


class UnmappedAccess(EmulationError):
    pass


class MachOImage:
    def __init__(self, path: str, data: bytes | None = None) -> None:
        self.path = path
        self.data = data if data is not None else open(path, "rb").read()
        self.macho = MachO(self.data, path)

    def map_into(self, uc: Uc) -> None:
        for seg in self.macho.segments:
            start = seg.vmaddr
            size = (seg.vmsize + PAGE - 1) // PAGE * PAGE
            if size == 0:
                continue
            uc.mem_map(start, size)
            if seg.filesize:
                blob = self.data[seg.fileoff : seg.fileoff + seg.filesize]
                uc.mem_write(start, blob.ljust(min(seg.vmsize, seg.filesize), b"\x00"))


class Harness:
    def __init__(self, image: MachOImage, *, log_stubs: bool = False, apply_binds: bool = True) -> None:
        self.image = image
        self.log_stubs = log_stubs
        self.fault: dict[str, int | str] | None = None
        self._fault_count = 0
        self._permissive = False
        self._max_faults = 64
        self._faults = 0
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)

        self._handlers: dict[str, Callable[[Harness], int | None]] = {}
        self._stub_addr: dict[str, int] = {}
        self._stub_by_index: dict[int, str] = {}
        self._data_addr: dict[str, int] = {}
        self._resolved: dict[int, str] = {}  # bind location -> symbol
        self._heap_cur = HEAP_ADDRESS
        self._scratch_cur = SCRATCH_ADDRESS
        self._obj_cur = OBJECT_ADDRESS
        self._calls: list[str] = []
        self._permissive_pages: set[int] = set()

        self._map_all()
        self._setup_stubs()
        self._install_default_handlers()
        if apply_binds:
            self._apply_binds()
        self._install_hooks()

    # -- setup ------------------------------------------------------------
    def _map_all(self) -> None:
        uc = self.uc
        uc.mem_map(RETURN_ADDRESS, PAGE)
        uc.mem_map(HEAP_ADDRESS, HEAP_SIZE)
        uc.mem_map(STACK_ADDRESS, STACK_SIZE)
        uc.mem_map(STUB_ADDRESS, STUB_SIZE)
        uc.mem_map(DATA_ADDRESS, DATA_SIZE)
        uc.mem_map(SCRATCH_ADDRESS, SCRATCH_SIZE)
        uc.mem_map(OBJECT_ADDRESS, OBJECT_SIZE)
        self.image.map_into(uc)

    def _setup_stubs(self) -> None:
        self.uc.mem_write(STUB_ADDRESS, _RET * STUB_SIZE)
        for i, sym in enumerate(self.image.macho.bind_symbols()):
            if _is_data_symbol(sym):
                cell = DATA_ADDRESS + i * _STUB_SLOT
                self._data_addr[sym] = cell
                self.uc.mem_write(cell, struct.pack("<Q", OBJECT_ADDRESS + i * _STUB_SLOT))
            else:
                addr = STUB_ADDRESS + i * _STUB_SLOT
                self._stub_addr[sym] = addr
                self._stub_by_index[addr] = sym

    def _apply_binds(self) -> None:
        for bind in self.image.macho.all_binds():
            sym = bind.symbol
            if sym in self._data_addr:
                target = self._data_addr[sym]
            elif sym in self._stub_addr:
                target = self._stub_addr[sym]
            else:
                # Not in the exported bind list (defensive): allocate a fresh stub.
                target = STUB_ADDRESS + (len(self._stub_addr) + 0x800) * _STUB_SLOT
                self._stub_addr[sym] = target
                self._stub_by_index[target] = sym
            # dyld semantics: the loader stores ``symbol + addend`` and the
            # whitebox later recovers the symbol with ``slot - addend``.  We
            # must reproduce that masking, otherwise the VM dereferences
            # ``stub - addend`` and runs off into unmapped memory.
            value = (target + bind.addend) & 0xFFFFFFFFFFFFFFFF
            self.uc.mem_write(bind.address, struct.pack("<Q", value))
            self._resolved[bind.address] = sym

    def _install_hooks(self) -> None:
        uc = self.uc
        uc.hook_add(UC_HOOK_CODE, self._hook_code, None, STUB_ADDRESS, STUB_ADDRESS + STUB_SIZE - 1)
        uc.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
            self._hook_invalid,
        )

    def _install_default_handlers(self) -> None:
        self.register("___stack_chk_fail", lambda h: self._abort("stack check failed"))
        for name in ("pthread_rwlock_init", "pthread_rwlock_rdlock", "pthread_rwlock_wrlock",
                     "pthread_rwlock_unlock", "pthread_rwlock_destroy"):
            self.register(name, lambda h: 0)
        self.register("getuid", lambda h: 501)  # _fpsd-ish uid; deterministic
        self.register("umask", lambda h: 0o022)
        self.register("arc4random", lambda h: 0x12345678)
        self.register("gethostuuid", self._gethostuuid)
        self.register("gettimeofday", self._gettimeofday)
        self.register("___error", self._errno_ptr)
        self.register("objc_msgSend", self._objc_msgSend)
        self.register("NSVersionOfRunTimeLibrary", lambda h: 0)
        self.register("CFErrorGetCode", lambda h: -1)
        self.register("CFErrorGetDomain", lambda h: 0)
        self.register("CFRelease", lambda h: 0)
        self.register("CSBackupIsItemExcluded", lambda h: 0)
        self.register("CSBackupSetItemExcluded", lambda h: 0)
        self.register("CFFileSecuritySetMode", lambda h: 1)
        self.register("malloc", self._malloc)
        self.register("free", self._free)

    # -- public API -------------------------------------------------------
    def register(self, symbol: str, handler: Callable[[Harness], int | None]) -> None:
        self._handlers[_norm(symbol)] = handler

    def mem_read(self, addr: int, size: int) -> bytes:
        return bytes(self.uc.mem_read(addr, size))

    def mem_write(self, addr: int, data: bytes) -> None:
        self.uc.mem_write(addr, data)

    def read_u64(self, addr: int) -> int:
        return struct.unpack("<Q", self.mem_read(addr, 8))[0]

    def read_u32(self, addr: int) -> int:
        return struct.unpack("<I", self.mem_read(addr, 4))[0]

    def write_u64(self, addr: int, value: int) -> None:
        self.mem_write(addr, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))

    def write_u32(self, addr: int, value: int) -> None:
        self.mem_write(addr, struct.pack("<I", value & 0xFFFFFFFF))

    def read_cstr(self, addr: int, max_len: int = 0x1000) -> str:
        out = bytearray()
        while len(out) < max_len:
            b = self.mem_read(addr + len(out), 1)
            if b == b"\x00":
                break
            out += b
        return out.decode("utf-8", "replace")

    def scratch(self, size: int) -> int:
        size = (size + 0xF) & ~0xF
        addr = self._scratch_cur
        self._scratch_cur += size
        return addr

    def object(self, size: int) -> int:
        size = (size + 0xF) & ~0xF
        addr = self._obj_cur
        self._obj_cur += size
        return addr

    def invoke(self, address: int, args: list[int], *, permissive: bool = False, max_faults: int = 64) -> int:
        uc = self.uc
        for reg, value in zip(_ARG_REGS, args):
            uc.reg_write(reg, value)
        rsp = STACK_ADDRESS + STACK_SIZE - 0x1000
        self.write_u64(rsp, RETURN_ADDRESS)
        uc.reg_write(UC_X86_REG_RSP, rsp)
        uc.reg_write(UC_X86_REG_RBP, 0)

        self._permissive = permissive
        self._max_faults = max_faults
        self._faults = 0
        try:
            uc.emu_start(address, RETURN_ADDRESS, timeout=0, count=0)
        except Exception as exc:  # noqa: BLE001
            fault = self.fault
            self.fault = None
            raise EmulationError(
                f"emulation failed at rip={uc.reg_read(UC_X86_REG_RIP):#x}: {exc}"
            ) from exc
        finally:
            self._permissive = False
        return uc.reg_read(UC_X86_REG_RAX)

    def _map_page(self, page: int) -> None:
        if page in self._permissive_pages:
            return
        self._permissive_pages.add(page)
        try:
            self.uc.mem_map(page, PAGE)
        except Exception:  # noqa: BLE001
            return

    def stack_trace(self) -> list[int]:
        return list(self._calls)

    # -- hooks ------------------------------------------------------------
    def _hook_code(self, uc: Uc, address: int, size: int, _user: Any) -> None:
        sym = self._stub_by_index.get(address)
        if sym is None:
            return
        self._calls.append(sym)
        handler = self._handlers.get(_norm(sym))
        if handler is None:
            if self.log_stubs:
                logger.info("stub %s (unhandled) -> 0", sym)
            return
        result = handler(self)
        if result is not None:
            uc.reg_write(UC_X86_REG_RAX, result & 0xFFFFFFFFFFFFFFFF)

    def _hook_invalid(self, uc: Uc, access: int, address: int, size: int, value: int, _user: Any) -> bool:
        self._fault_count += 1
        kind = {
            UC_MEM_READ_UNMAPPED: "read-unmapped",
            UC_MEM_WRITE_UNMAPPED: "write-unmapped",
            UC_MEM_FETCH_UNMAPPED: "fetch-unmapped",
        }.get(access, f"access-{access}")
        if self._permissive and kind.endswith("unmapped"):
            # The VM deliberately reads memory near the dyld-bound imports
            # (`*(symbol + addend - D)`), which only exists on a real macOS
            # shared cache. Materialise the page and let the access retry.
            self._faults += 1
            if self._faults > self._max_faults:
                raise EmulationError(f"too many faults ({self._faults})")
            self._map_page(address & ~(PAGE - 1))
            return True
        self.fault = {
            "kind": kind,
            "address": address,
            "size": size,
            "rip": uc.reg_read(UC_X86_REG_RIP),
            "rax": uc.reg_read(UC_X86_REG_RAX),
            "rbx": uc.reg_read(UC_X86_REG_RBX),
            "rcx": uc.reg_read(UC_X86_REG_RCX),
            "rdx": uc.reg_read(UC_X86_REG_RDX),
            "rsi": uc.reg_read(UC_X86_REG_RSI),
            "rdi": uc.reg_read(UC_X86_REG_RDI),
            "r8": uc.reg_read(UC_X86_REG_R8),
            "r9": uc.reg_read(UC_X86_REG_R9),
            "rbp": uc.reg_read(UC_X86_REG_RBP),
            "rsp": uc.reg_read(UC_X86_REG_RSP),
        }
        raise UnmappedAccess(f"{kind} at {address:#x} (size {size}) rip={self.fault['rip']:#x}")

    # -- handlers ---------------------------------------------------------
    def _abort(self, message: str) -> int:
        raise EmulationError(message)

    def _malloc(self, h: Harness) -> int:
        size = h.uc.reg_read(UC_X86_REG_RDI)
        addr = h._heap_cur
        h._heap_cur = (h._heap_cur + max(size, 0x20) + 0xF) & ~0xF
        return addr

    def _free(self, h: Harness) -> int:
        return 0

    def _errno_ptr(self, h: Harness) -> int:
        if not hasattr(h, "_errno_addr"):
            h._errno_addr = h.scratch(8)
            h.write_u64(h._errno_addr, 0)
        return h._errno_addr

    def _gethostuuid(self, h: Harness) -> int:
        out = h.uc.reg_read(UC_X86_REG_RDI)
        # A stable, obviously-synthetic UUID; caller-controlled in real use.
        h.mem_write(out, bytes.fromhex("41444d414341444941444d4143414449")[:16].ljust(16, b"\x00"))
        return 0

    def _gettimeofday(self, h: Harness) -> int:
        tv = h.uc.reg_read(UC_X86_REG_RDI)
        if tv:
            h.write_u64(tv, 1700000000)
            h.write_u64(tv + 8, 0)
        return 0

    _SEL_CACHE: dict[int, str] = {}

    def _objc_msgSend(self, h: Harness) -> int:
        sel = h.uc.reg_read(UC_X86_REG_RSI)
        name = h.read_cstr(sel)
        if h.log_stubs:
            logger.info("objc_msgSend sel=%s", name)
        if name == "processInfo":
            return h.object(0x100)
        if name == "operatingSystem":
            return 0x0D  # NSMavericks? see caller intent; logged for tuning
        if name == "isOperatingSystemAtLeastVersion:":
            return 1
        return 0
