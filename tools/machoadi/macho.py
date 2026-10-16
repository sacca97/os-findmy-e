"""Minimal Mach-O (64-bit) reader focused on what a Unicorn loader needs.

Only the pieces required to *map* a pre-11.0 Mach-O and resolve its external
symbols are implemented:

* segments / sections
* ``LC_SYMTAB`` (for names + symbol classification)
* classic ``LC_DYLD_INFO[_ONLY]`` rebase / bind / lazy-bind opcode streams
* the lists of linked dylibs

Chained fixups (macOS 12+), which this corpus predates, are not handled.

All offsets in the bind/rebase streams are decoded with the same state machine
dyld uses (see dyld's ``ImageLoaderMachOCompressed.cpp``).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

MH_MAGIC_64 = 0xFEEDFACF
MH_EXECUTE = 0x2
MH_DYLIB = 0x6

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_LAZY_LOAD_DYLIB = 0x20
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_CODE_SIGNATURE = 0x1D
LC_FUNCTION_STARTS = 0x26
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_DYLD_CHAINED_FIXUPS = 0x80000034

# --- bind opcodes ---------------------------------------------------------
BIND_OPCODE_MASK = 0xF0
BIND_IMMEDIATE_MASK = 0x0F
BIND_OPCODE_DONE = 0x00
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20
BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
BIND_OPCODE_SET_TYPE_IMM = 0x50
BIND_OPCODE_SET_ADDEND_SLEB = 0x60
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70
BIND_OPCODE_ADD_ADDR_ULEB = 0x80
BIND_OPCODE_DO_BIND = 0x90
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0
BIND_OPCODE_THREADED = 0xD0

BIND_SYMBOL_FLAGS_WEAK_IMPORT = 0x1
BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION = 0x8

BIND_TYPE_POINTER = 1
BIND_TYPE_TEXT_ABSOLUTE32 = 2
BIND_TYPE_TEXT_PCREL32 = 3

# --- rebase opcodes -------------------------------------------------------
REBASE_OPCODE_MASK = 0xF0
REBASE_IMMEDIATE_MASK = 0x0F
REBASE_OPCODE_DONE = 0x00
REBASE_OPCODE_SET_TYPE_IMM = 0x10
REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x20
REBASE_OPCODE_ADD_ADDR_ULEB = 0x30
REBASE_OPCODE_ADD_ADDR_IMM_SCALED = 0x40
REBASE_OPCODE_DO_REBASE_IMM_TIMES = 0x50
REBASE_OPCODE_DO_REBASE_ULEB_TIMES = 0x60
REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB = 0x70
REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80

REBASE_TYPE_POINTER = 1
REBASE_TYPE_TEXT_ABSOLUTE32 = 2
REBASE_TYPE_TEXT_PCREL32 = 3

_DYLIB_CMD_NAMES = {
    LC_LOAD_DYLIB: "load",
    LC_ID_DYLIB: "id",
    LC_LOAD_WEAK_DYLIB: "weak",
    LC_REEXPORT_DYLIB: "reexport",
    LC_LAZY_LOAD_DYLIB: "lazy",
}


def _u(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _q(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def read_uleb(data: bytes, off: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = data[off]
        off += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if byte & 0x80 == 0:
            return result, off


def read_sleb(data: bytes, off: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = data[off]
        off += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if byte & 0x80 == 0:
            if shift < 64 and byte & 0x40:
                result |= -(1 << shift)
            return result, off


def _cstr(data: bytes, off: int) -> str:
    end = data.index(b"\x00", off)
    return data[off:end].decode("utf-8", "replace")


@dataclass
class Section:
    segname: str
    sectname: str
    addr: int
    size: int
    offset: int
    align: int
    flags: int

    @property
    def qual(self) -> str:
        return f"{self.segname}.{self.sectname}"


@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    sections: list[Section] = field(default_factory=list)


@dataclass
class Bind:
    address: int
    seg_index: int
    segname: str
    ordinal: int
    symbol: str
    flags: int
    addend: int
    type: int
    lazy: bool = False
    library: str | None = None

    @property
    def weak(self) -> bool:
        return bool(self.flags & BIND_SYMBOL_FLAGS_WEAK_IMPORT)


@dataclass
class Rebase:
    address: int
    seg_index: int
    segname: str
    type: int


class MachOError(RuntimeError):
    pass


class MachO:
    def __init__(self, data: bytes, path: str = "") -> None:
        self.data = data
        self.path = path
        self.slices: list[str] = []

        magic = _u(data, 0)
        if magic == 0xCAFEBABE or magic == 0xBEBAFECA:
            raise MachOError("fat Mach-O: use the thin slice")
        if magic != MH_MAGIC_64:
            raise MachOError(f"not a 64-bit Mach-O (magic={magic:#x})")

        (
            _magic,
            self.cputype,
            self.cpusubtype,
            self.filetype,
            self.ncmds,
            self.sizeofcmds,
            self.flags,
            _reserved,
        ) = struct.unpack_from("<IIIIIIII", data, 0)

        self.segments: list[Segment] = []
        self.dylibs: list[tuple[int, str]] = []
        self.symoff = self.nsyms = self.stroff = self.strsize = 0
        self._dyld_info: dict[str, tuple[int, int]] = {}
        self._parse_load_commands()

        # Full symtab view.
        self.symbols: list[tuple[str, int, int, int, int]] = []
        self._parse_symtab()

    # -- load commands ----------------------------------------------------
    def _parse_load_commands(self) -> None:
        off = 32
        for _ in range(self.ncmds):
            cmd = _u(self.data, off)
            cmdsize = _u(self.data, off + 4)
            if cmd == LC_SEGMENT_64:
                self._parse_segment(off)
            elif cmd in _DYLIB_CMD_NAMES:
                nameoff = _u(self.data, off + 8)
                name = _cstr(self.data, off + nameoff)
                if cmd != LC_ID_DYLIB:
                    self.dylibs.append((cmd, name))
            elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
                fields = struct.unpack_from("<10I", self.data, off + 8)
                for i, key in enumerate(["rebase", "bind", "weak_bind", "lazy_bind", "export"]):
                    self._dyld_info[key] = (fields[i * 2], fields[i * 2 + 1])
            elif cmd == LC_SYMTAB:
                (
                    self.symoff,
                    self.nsyms,
                    self.stroff,
                    self.strsize,
                ) = struct.unpack_from("<IIII", self.data, off + 8)
            off += cmdsize

    def _parse_segment(self, off: int) -> None:
        name = self.data[off + 8 : off + 24].rstrip(b"\x00").decode("ascii", "replace")
        vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, _flags = struct.unpack_from(
            "<QQQQIIII", self.data, off + 24
        )
        seg = Segment(name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot)
        so = off + 72
        for _ in range(nsects):
            sectname = self.data[so : so + 16].rstrip(b"\x00").decode("ascii", "replace")
            segname = self.data[so + 16 : so + 32].rstrip(b"\x00").decode("ascii", "replace")
            addr, size = struct.unpack_from("<QQ", self.data, so + 32)
            (offset,) = struct.unpack_from("<I", self.data, so + 48)
            align, _reloff, _nreloc, flags, _r1, _r2, _r3 = struct.unpack_from(
                "<IIIIIII", self.data, so + 52
            )
            seg.sections.append(Section(segname, sectname, addr, size, offset, align, flags))
            so += 80
        self.segments.append(seg)

    def _parse_symtab(self) -> None:
        for i in range(self.nsyms):
            base = self.symoff + 16 * i
            strx, n_type, n_sect, n_desc, n_value = struct.unpack_from("<IBBHQ", self.data, base)
            name = _cstr(self.data, self.stroff + strx)
            self.symbols.append((name, n_type, n_sect, n_desc, n_value))

    # -- lookups ----------------------------------------------------------
    @property
    def undefined_symbols(self) -> list[tuple[str, int, int]]:
        """(name, n_desc, n_type) for every N_UNDF|N_EXT symbol."""
        out = []
        for name, n_type, _n_sect, n_desc, _value in self.symbols:
            if n_type & 0x0E == 0x00 and n_type & 0x01:  # N_UNDF | N_EXT
                out.append((name, n_desc, n_type))
        return out

    def segment_for(self, addr: int) -> tuple[int, Segment] | None:
        for i, seg in enumerate(self.segments):
            if seg.vmaddr <= addr < seg.vmaddr + seg.vmsize:
                return i, seg
        return None

    def section_for(self, addr: int) -> Section | None:
        hit = self.segment_for(addr)
        if hit is None:
            return None
        for sect in hit[1].sections:
            if sect.addr <= addr < sect.addr + sect.size:
                return sect
        return None

    def read_cstr_at(self, addr: int) -> str:
        seg_i = self.segment_for(addr)
        if seg_i is None:
            raise MachOError(f"address {addr:#x} not in any segment")
        _i, seg = seg_i
        file_off = seg.fileoff + (addr - seg.vmaddr)
        return _cstr(self.data, file_off)

    def dylib_name(self, ordinal: int) -> str | None:
        """ordinal is 1-based index into the load-dylib list."""
        if 1 <= ordinal <= len(self.dylibs):
            return self.dylibs[ordinal - 1][1]
        return None

    # -- dyld info --------------------------------------------------------
    def _stream(self, name: str) -> tuple[int, int]:
        return self._dyld_info.get(name, (0, 0))

    def iter_rebases(self) -> list[Rebase]:
        off, size = self._stream("rebase")
        if size == 0:
            return []
        data = self.data
        end = off + size
        out: list[Rebase] = []
        seg_index = 0
        seg_offset = 0
        rtype = REBASE_TYPE_POINTER
        while off < end:
            byte = data[off]
            opcode = byte & REBASE_OPCODE_MASK
            imm = byte & REBASE_IMMEDIATE_MASK
            off += 1
            if opcode == REBASE_OPCODE_DONE:
                break
            elif opcode == REBASE_OPCODE_SET_TYPE_IMM:
                rtype = imm
            elif opcode == REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                seg_index = imm
                seg_offset, off = read_uleb(data, off)
            elif opcode == REBASE_OPCODE_ADD_ADDR_ULEB:
                val, off = read_uleb(data, off)
                seg_offset += val
            elif opcode == REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
                seg_offset += imm * 8
            elif opcode == REBASE_OPCODE_DO_REBASE_IMM_TIMES:
                for _ in range(imm):
                    out.append(self._mk_rebase(seg_index, seg_offset, rtype))
                    seg_offset += 8
            elif opcode == REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
                count, off = read_uleb(data, off)
                for _ in range(count):
                    out.append(self._mk_rebase(seg_index, seg_offset, rtype))
                    seg_offset += 8
            elif opcode == REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
                out.append(self._mk_rebase(seg_index, seg_offset, rtype))
                val, off = read_uleb(data, off)
                seg_offset += val + 8
            elif opcode == REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
                count, off = read_uleb(data, off)
                skip, off = read_uleb(data, off)
                for _ in range(count):
                    out.append(self._mk_rebase(seg_index, seg_offset, rtype))
                    seg_offset += skip + 8
            else:
                raise MachOError(f"bad rebase opcode {opcode:#x} at {off - 1:#x}")
        return out

    def _mk_rebase(self, seg_index: int, seg_offset: int, rtype: int) -> Rebase:
        seg = self.segments[seg_index]
        return Rebase(seg.vmaddr + seg_offset, seg_index, seg.name, rtype)

    def _iter_binds(self, stream: str, lazy: bool) -> list[Bind]:
        off, size = self._stream(stream)
        if size == 0:
            return []
        data = self.data
        end = off + size

        out: list[Bind] = []
        ordinal = 0
        symbol = ""
        sym_flags = 0
        btype = BIND_TYPE_POINTER
        addend = 0
        seg_index = 0
        seg_offset = 0
        while off < end:
            byte = data[off]
            opcode = byte & BIND_OPCODE_MASK
            imm = byte & BIND_IMMEDIATE_MASK
            off += 1
            if opcode == BIND_OPCODE_DONE:
                if lazy:
                    # each lazy entry terminates with DONE; keep going
                    continue
                break
            elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                ordinal = imm
            elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                ordinal, off = read_uleb(data, off)
            elif opcode == BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                ordinal = imm if imm == 0 else (0xF0 | imm) - 0x100
            elif opcode == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                sym_flags = imm
                # The symbol name follows inline, NUL-terminated.
                end_pos = data.index(b"\x00", off)
                symbol = data[off:end_pos].decode("ascii", "replace")
                off = end_pos + 1
            elif opcode == BIND_OPCODE_SET_TYPE_IMM:
                btype = imm
            elif opcode == BIND_OPCODE_SET_ADDEND_SLEB:
                addend, off = read_sleb(data, off)
            elif opcode == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                seg_index = imm
                seg_offset, off = read_uleb(data, off)
            elif opcode == BIND_OPCODE_ADD_ADDR_ULEB:
                val, off = read_uleb(data, off)
                seg_offset = (seg_offset + val) & 0xFFFFFFFFFFFFFFFF
            elif opcode == BIND_OPCODE_DO_BIND:
                out.append(self._mk_bind(seg_index, seg_offset, ordinal, symbol, sym_flags, addend, btype, lazy))
                seg_offset += 8
            elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                out.append(self._mk_bind(seg_index, seg_offset, ordinal, symbol, sym_flags, addend, btype, lazy))
                val, off = read_uleb(data, off)
                seg_offset = (seg_offset + val + 8) & 0xFFFFFFFFFFFFFFFF
            elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                out.append(self._mk_bind(seg_index, seg_offset, ordinal, symbol, sym_flags, addend, btype, lazy))
                seg_offset += imm * 8 + 8
            elif opcode == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                count, off = read_uleb(data, off)
                skip, off = read_uleb(data, off)
                for _ in range(count):
                    out.append(self._mk_bind(seg_index, seg_offset, ordinal, symbol, sym_flags, addend, btype, lazy))
                    seg_offset += skip + 8
            elif opcode == BIND_OPCODE_THREADED:
                raise MachOError("threaded bind opcode (chained fixups) is not supported")
            else:
                raise MachOError(f"bad bind opcode {opcode:#x} at {off - 1:#x}")
        return out

    def _mk_bind(
        self,
        seg_index: int,
        seg_offset: int,
        ordinal: int,
        symbol: str,
        flags: int,
        addend: int,
        btype: int,
        lazy: bool,
    ) -> Bind:
        seg = self.segments[seg_index]
        return Bind(
            address=seg.vmaddr + seg_offset,
            seg_index=seg_index,
            segname=seg.name,
            ordinal=ordinal,
            symbol=symbol,
            flags=flags,
            addend=addend,
            type=btype,
            lazy=lazy,
            library=self.dylib_name(ordinal) if ordinal > 0 else None,
        )

    def iter_binds(self) -> list[Bind]:
        return self._iter_binds("bind", lazy=False)

    def iter_lazy_binds(self) -> list[Bind]:
        return self._iter_binds("lazy_bind", lazy=True)

    def all_binds(self) -> list[Bind]:
        return self.iter_binds() + self.iter_lazy_binds()

    def bind_symbols(self) -> list[str]:
        seen: dict[str, None] = {}
        for b in self.all_binds():
            seen.setdefault(b.symbol, None)
        return list(seen)
