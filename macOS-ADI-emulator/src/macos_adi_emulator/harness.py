"""Unicorn runtime for the x86_64 macOS ADI executable."""

from __future__ import annotations

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
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RAX,
    UC_X86_REG_RBP,
    UC_X86_REG_RCX,
    UC_X86_REG_RDI,
    UC_X86_REG_RDX,
    UC_X86_REG_RIP,
    UC_X86_REG_RSI,
    UC_X86_REG_RSP,
)

from .macho import MachO

from .adi_layout import (
    DATA_ADDRESS,
    DATA_SIZE,
    HEAP_ADDRESS,
    HEAP_SIZE,
    OBJECT_ADDRESS,
    OBJECT_SIZE,
    PAGE,
    RETURN_ADDRESS,
    SCRATCH_ADDRESS,
    SCRATCH_SIZE,
    STACK_ADDRESS,
    STACK_SIZE,
    STUB_ADDRESS,
    STUB_SIZE,
)

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
    def __init__(self, image: MachOImage) -> None:
        self.image = image
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        # Unicorn's default translation cache can grow to 1 GiB. This daemon
        # has a small working set even though its generated code changes often.
        self.uc.ctl_set_tcg_buffer_size(16 * 1024 * 1024)

        self._handlers: dict[str, Callable[[Harness], int | None]] = {}
        self._stub_addr: dict[str, int] = {}
        self._stub_by_index: dict[int, str] = {}
        self._data_addr: dict[str, int] = {}
        self._heap_cur = HEAP_ADDRESS
        self._heap_free = [(HEAP_ADDRESS, HEAP_SIZE)]
        self._heap_allocations: dict[int, int] = {}
        self._scratch_cur = SCRATCH_ADDRESS
        self._obj_cur = OBJECT_ADDRESS

        self._map_all()
        self._setup_stubs()
        self._install_default_handlers()
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
            # dyld stores the symbol address with its addend in the bind slot.
            value = (target + bind.addend) & 0xFFFFFFFFFFFFFFFF
            self.uc.mem_write(bind.address, struct.pack("<Q", value))

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
            current = addr + len(out)
            size = min(64, max_len - len(out), PAGE - current % PAGE)
            chunk = self.mem_read(current, size)
            end = chunk.find(b"\x00")
            if end >= 0:
                out += chunk[:end]
                break
            out += chunk
        return out.decode("utf-8", "replace")

    def scratch(self, size: int) -> int:
        size = (size + 0xF) & ~0xF
        addr = self._scratch_cur
        self._scratch_cur += size
        return addr

    def heap_alloc(self, size: int, alignment: int = 0x10) -> int:
        """Allocate within the mapped heap, reusing released ranges."""
        if size < 0 or alignment <= 0 or alignment & (alignment - 1):
            raise ValueError("invalid heap allocation size or alignment")
        size = (max(size, 0x20) + alignment - 1) & ~(alignment - 1)
        for i, (start, length) in enumerate(self._heap_free):
            addr = (start + alignment - 1) & ~(alignment - 1)
            end = addr + size
            if end > start + length:
                continue
            remaining = []
            if addr > start:
                remaining.append((start, addr - start))
            if end < start + length:
                remaining.append((end, start + length - end))
            self._heap_free[i:i + 1] = remaining
            self._heap_allocations[addr] = size
            self._heap_cur = max(self._heap_cur, end)
            return addr
        raise EmulationError(f"emulated heap exhausted allocating {size:#x} bytes")

    def heap_free(self, addr: int) -> None:
        if not addr:
            return
        size = self._heap_allocations.pop(addr, None)
        if size is None:
            raise EmulationError(f"invalid emulated heap release at {addr:#x}")
        ranges = sorted([*self._heap_free, (addr, size)])
        merged: list[tuple[int, int]] = []
        for start, length in ranges:
            if merged and merged[-1][0] + merged[-1][1] == start:
                prev, prev_length = merged[-1]
                merged[-1] = (prev, prev_length + length)
            else:
                merged.append((start, length))
        self._heap_free = merged

    def object(self, size: int) -> int:
        size = (size + 0xF) & ~0xF
        addr = self._obj_cur
        self._obj_cur += size
        return addr

    def invoke(self, address: int, args: list[int]) -> int:
        uc = self.uc
        for reg, value in zip(_ARG_REGS, args):
            uc.reg_write(reg, value)
        rsp = STACK_ADDRESS + STACK_SIZE - 0x1000
        self.write_u64(rsp, RETURN_ADDRESS)
        uc.reg_write(UC_X86_REG_RSP, rsp)
        uc.reg_write(UC_X86_REG_RBP, 0)

        try:
            uc.emu_start(address, RETURN_ADDRESS, timeout=0, count=0)
        except Exception as exc:  # noqa: BLE001
            raise EmulationError(
                f"emulation failed at rip={uc.reg_read(UC_X86_REG_RIP):#x}: {exc}"
            ) from exc
        return uc.reg_read(UC_X86_REG_RAX)

    # -- hooks ------------------------------------------------------------
    def _hook_code(self, uc: Uc, address: int, size: int, _user: Any) -> None:
        sym = self._stub_by_index.get(address)
        if sym is None:
            return
        handler = self._handlers.get(_norm(sym))
        if handler is None:
            return
        result = handler(self)
        if result is not None:
            uc.reg_write(UC_X86_REG_RAX, result & 0xFFFFFFFFFFFFFFFF)

    def _hook_invalid(self, uc: Uc, access: int, address: int, size: int, value: int, _user: Any) -> bool:
        kind = {
            UC_MEM_READ_UNMAPPED: "read-unmapped",
            UC_MEM_WRITE_UNMAPPED: "write-unmapped",
            UC_MEM_FETCH_UNMAPPED: "fetch-unmapped",
        }.get(access, f"access-{access}")
        rip = uc.reg_read(UC_X86_REG_RIP)
        raise UnmappedAccess(f"{kind} at {address:#x} (size {size}) rip={rip:#x}")

    # -- handlers ---------------------------------------------------------
    def _abort(self, message: str) -> int:
        raise EmulationError(message)

    def _malloc(self, h: Harness) -> int:
        size = h.uc.reg_read(UC_X86_REG_RDI)
        return h.heap_alloc(size)

    def _free(self, h: Harness) -> int:
        h.heap_free(h.uc.reg_read(UC_X86_REG_RDI))
        return 0


