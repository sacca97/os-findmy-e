"""POSIX / CoreFoundation / Foundation stubs for the Mac CoreADI whitebox.

The dylib is a normal macOS userland component: once its imports are bound it
talks to libc (open/read/write/lstat/...), CoreFoundation (CFURL resource
properties) and a little Objective-C (NSProcessInfo) to decide where its
provisioning store lives and whether the machine already has an ADI blob.

Everything here is a *surrogate* for the host operating system, not a
reimplementation of ADI: the virtual filesystem is what a real Mac would have
under ``/Users/Shared/adi``, and the errno/stat plumbing mirrors BSD.
"""

from __future__ import annotations

import errno as _errno
import os
import struct
import time
import zlib
from typing import TYPE_CHECKING

from unicorn.x86_const import (
    UC_X86_REG_RDI,
    UC_X86_REG_RSI,
    UC_X86_REG_RDX,
    UC_X86_REG_RCX,
    UC_X86_REG_R8,
)

if TYPE_CHECKING:  # pragma: no cover
    from harness import Harness

# macOS/x86_64 `struct stat` (the $INODE64 variant) is 144 bytes.
STAT_SIZE = 144
# macOS/x86_64 `struct statfs` is 2168 bytes; only the first fields matter here.
STATFS_SIZE = 2168

S_IFMT = 0o170000
S_IFDIR = 0o040000
S_IFREG = 0o100000

O_RDONLY = 0x0000
O_WRONLY = 0x0001
O_RDWR = 0x0002
O_CREAT = 0x0200
O_TRUNC = 0x0400
O_EXCL = 0x0800

_PROVISIONING_DIR = "/Users/Shared/adi"


class MacStubs:
    """A tiny synthetic macOS userland for the emulated CoreADI."""

    def __init__(self, harness: "Harness", *, log: bool = False) -> None:
        self.h = harness
        self.log = log
        self.files: dict[str, bytearray] = {}
        self.dirs: set[str] = {"/", "/Users", "/Users/Shared", _PROVISIONING_DIR}
        self.fds: dict[int, dict] = {}
        self.next_fd = 3
        self.urls: dict[int, str] = {}
        self._next_url = 0x60080000
        self._errno_addr: int | None = None
        self.home = "/Users/aditest"
        self.hostuuid = bytes.fromhex("00112233445566778899aabbccddeeff")
        # The whitebox loads a global such as `kCFURLIsDirectoryKey` as
        # `*(slot - mask)`, i.e. it sees the *object pointer* the cell holds,
        # not the cell address.  Build the reverse map it actually compares on.
        self.key_by_object = {
            harness.read_u64(cell): sym for sym, cell in harness._data_addr.items()
        }
        self._install()

    # -- helpers ----------------------------------------------------------
    def _a(self, index: int) -> int:
        regs = (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8)
        return self.h.uc.reg_read(regs[index])

    def _s(self, addr: int, limit: int = 4096) -> str:
        try:
            return self.h.read_cstr(addr, limit)
        except Exception:  # noqa: BLE001
            return ""

    def _errno(self) -> int:
        if self._errno_addr is None:
            self._errno_addr = self.h.scratch(8)
        return self._errno_addr

    def set_errno(self, value: int) -> None:
        self.h.write_u32(self._errno(), value)

    def errno_ptr(self, h: "Harness") -> int:
        """`___error()` -- the address the caller dereferences to read errno."""
        return self._errno()

    def _fail(self, err: int) -> int:
        self.set_errno(err)
        return -1

    def _note(self, msg: str) -> None:
        if self.log:
            print("      [fs]", msg, flush=True)

    # -- virtual filesystem ----------------------------------------------
    def _exists(self, path: str) -> bool:
        return path in self.files or path in self.dirs

    def _inode(self, path: str) -> int:
        """A stable, per-path inode.

        The store logic compares entries by inode, so a single shared value
        makes distinct files look like hard links of one another.
        """
        return 0x10000 + (zlib.crc32(path.encode()) & 0xFFFFF)

    def _fill_stat(self, addr: int, path: str, *, is_dir: bool, size: int = 0) -> None:
        buf = bytearray(STAT_SIZE)
        struct.pack_into("<I", buf, 0, 0x1000003)          # st_dev
        struct.pack_into("<H", buf, 4, (S_IFDIR if is_dir else S_IFREG) | 0o755)
        struct.pack_into("<H", buf, 6, 2 if is_dir else 1)  # st_nlink
        struct.pack_into("<Q", buf, 8, self._inode(path))   # st_ino
        struct.pack_into("<I", buf, 16, 501)               # st_uid
        struct.pack_into("<I", buf, 20, 20)                # st_gid
        struct.pack_into("<q", buf, 96, size)              # st_size
        struct.pack_into("<q", buf, 104, (size + 511) // 512)
        struct.pack_into("<i", buf, 112, 4096)             # st_blksize
        self.h.mem_write(addr, bytes(buf))

    # -- registration -----------------------------------------------------
    def _install(self) -> None:
        h = self.h
        h.register("open", self.open)
        h.register("close", self.close)
        h.register("read", self.read)
        h.register("write", self.write)
        h.register("lstat$INODE64", self.lstat)
        h.register("stat$INODE64", self.lstat)
        h.register("fstat$INODE64", self.fstat)
        h.register("statfs$INODE64", self.statfs)
        h.register("mkdir", self.mkdir)
        h.register("unlink", self.unlink)
        h.register("chmod", self.chmod)
        h.register("fchmod", self.fchmod)
        h.register("fcntl", self.fcntl)
        h.register("ftruncate", self.ftruncate)
        h.register("lockf", self.lockf)
        h.register("getenv", self.getenv)
        h.register("gettimeofday", self.gettimeofday)
        h.register("gethostuuid", self.gethostuuid)
        h.register("___error", self.errno_ptr)
        h.register("notify_post", lambda hh: 0)
        h.register("umask", lambda hh: 0o022)
        h.register("getuid", lambda hh: 501)
        h.register("arc4random", self.arc4random)
        h.register("arc4random_buf", self.arc4random_buf)
        h.register("NSVersionOfRunTimeLibrary", lambda hh: 0x10000_0000)
        h.register("CSBackupIsItemExcluded", lambda hh: 0)
        h.register("CSBackupSetItemExcluded", lambda hh: 1)
        h.register("CFFileSecuritySetMode", lambda hh: 1)
        h.register("CFRelease", lambda hh: 0)
        h.register("CFErrorGetCode", lambda hh: 0)
        h.register("CFErrorGetDomain", lambda hh: 0)
        h.register("CFURLCreateFromFileSystemRepresentation", self.cfurl_create)
        h.register("CFURLCopyResourcePropertyForKey", self.cfurl_copy_prop)
        h.register("CFURLSetResourcePropertyForKey", self.cfurl_set_prop)
        h.register("objc_msgSend", self.objc_msgSend)

    # -- libc -------------------------------------------------------------
    def open(self, h: "Harness") -> int:
        path = self._s(self._a(0))
        flags = self._a(1)
        self._note(f"open({path!r}, {flags:#x})")
        if path in self.files:
            if flags & O_TRUNC:
                self.files[path] = bytearray()
        elif flags & O_CREAT:
            self.files[path] = bytearray()
        elif path in self.dirs:
            return self._fail(_errno.EISDIR)
        else:
            return self._fail(_errno.ENOENT)
        fd = self.next_fd
        self.next_fd += 1
        self.fds[fd] = {"path": path, "off": 0, "flags": flags}
        return fd

    def close(self, h: "Harness") -> int:
        self.fds.pop(self._a(0), None)
        return 0

    def read(self, h: "Harness") -> int:
        fd, buf, n = self._a(0), self._a(1), self._a(2)
        info = self.fds.get(fd)
        if info is None:
            return self._fail(_errno.EBADF)
        data = self.files.get(info["path"], bytearray())
        chunk = bytes(data[info["off"]: info["off"] + n])
        self.h.mem_write(buf, chunk)
        info["off"] += len(chunk)
        return len(chunk)

    def write(self, h: "Harness") -> int:
        fd, buf, n = self._a(0), self._a(1), self._a(2)
        info = self.fds.get(fd)
        if info is None:
            return self._fail(_errno.EBADF)
        data = self.files.setdefault(info["path"], bytearray())
        payload = self.h.mem_read(buf, n)
        off = info["off"]
        if off > len(data):
            data.extend(b"\x00" * (off - len(data)))
        data[off: off + len(payload)] = payload
        info["off"] = off + len(payload)
        self._note(f"write({info['path']!r}, {n}B) -> size {len(data)}")
        return n

    def lstat(self, h: "Harness") -> int:
        path = self._s(self._a(0))
        buf = self._a(1)
        if path in self.files:
            self._fill_stat(buf, path, is_dir=False, size=len(self.files[path]))
            self._note(f"lstat({path!r}) -> file {len(self.files[path])}B")
            return 0
        if path in self.dirs:
            self._fill_stat(buf, path, is_dir=True)
            return 0
        self._note(f"lstat({path!r}) -> ENOENT")
        return self._fail(_errno.ENOENT)

    def fstat(self, h: "Harness") -> int:
        fd, buf = self._a(0), self._a(1)
        info = self.fds.get(fd)
        if info is None:
            return self._fail(_errno.EBADF)
        size = len(self.files.get(info["path"], b""))
        self._fill_stat(buf, info["path"], is_dir=False, size=size)
        return 0

    def statfs(self, h: "Harness") -> int:
        buf = self._a(1)
        raw = bytearray(STATFS_SIZE)
        struct.pack_into("<I", raw, 0, 0x1000003)  # f_bsize etc. left zero
        self.h.mem_write(buf, bytes(raw))
        return 0

    def mkdir(self, h: "Harness") -> int:
        path = self._s(self._a(0))
        self._note(f"mkdir({path!r})")
        if self._exists(path):
            return self._fail(_errno.EEXIST)
        self.dirs.add(path)
        return 0

    def unlink(self, h: "Harness") -> int:
        path = self._s(self._a(0))
        self._note(f"unlink({path!r})")
        if path in self.files:
            del self.files[path]
            return 0
        return self._fail(_errno.ENOENT)

    def chmod(self, h: "Harness") -> int:
        return 0 if self._exists(self._s(self._a(0))) else self._fail(_errno.ENOENT)

    def fchmod(self, h: "Harness") -> int:
        return 0

    def fcntl(self, h: "Harness") -> int:
        return 0

    def ftruncate(self, h: "Harness") -> int:
        fd, length = self._a(0), self._a(1)
        info = self.fds.get(fd)
        if info is None:
            return self._fail(_errno.EBADF)
        data = self.files.setdefault(info["path"], bytearray())
        del data[length:]
        data.extend(b"\x00" * (length - len(data)))
        return 0

    def lockf(self, h: "Harness") -> int:
        return 0

    def getenv(self, h: "Harness") -> int:
        name = self._s(self._a(0))
        values = {"HOME": self.home, "USER": "aditest", "TMPDIR": "/tmp/"}
        self._note(f"getenv({name!r})")
        value = values.get(name)
        if value is None:
            return 0
        addr = self.h.scratch(len(value) + 1)
        self.h.mem_write(addr, value.encode() + b"\x00")
        return addr

    def gettimeofday(self, h: "Harness") -> int:
        tv = self._a(0)
        if tv:
            # Real time by default. A frozen clock makes the whitebox OTP a constant, which Apple accepts
            # for only ~a minute after provisioning (EVIDENCE.md sections 8, 9). ADI_FROZEN_TIME=1 restores
            # the old behaviour (deterministic traces, reproducing the lease).
            now = 1700000000 if os.environ.get("ADI_FROZEN_TIME") else time.time()
            self.h.write_u64(tv, int(now))
            self.h.write_u64(tv + 8, int((now % 1) * 1_000_000))
        return 0

    def gethostuuid(self, h: "Harness") -> int:
        out = self._a(0)
        self.h.mem_write(out, self.hostuuid)
        self._note(f"gethostuuid -> {self.hostuuid.hex()}")
        return 0

    def arc4random(self, h: "Harness") -> int:
        return 0x12345678

    def arc4random_buf(self, h: "Harness") -> int:
        buf, n = self._a(0), self._a(1)
        self.h.mem_write(buf, bytes((i * 7 + 3) & 0xFF for i in range(n)))
        return 0

    # -- CoreFoundation ---------------------------------------------------
    def cfurl_create(self, h: "Harness") -> int:
        buf, length, is_dir = self._a(1), self._a(2), self._a(3)
        path = self.h.mem_read(buf, length).decode("utf-8", "replace")
        self._next_url += 0x10
        self.urls[self._next_url] = path
        self._note(f"CFURLCreate({path!r}, dir={bool(is_dir)}) -> {self._next_url:#x}")
        return self._next_url

    def _key_name(self, key: int) -> str | None:
        name = self.key_by_object.get(key)
        return None if name is None else name.lstrip("_")

    def cfurl_copy_prop(self, h: "Harness") -> int:
        url, key, out = self._a(0), self._a(1), self._a(2)
        path = self.urls.get(url, f"<{url:#x}>")
        name = self._key_name(key)
        self._note(f"CFURLGet({path!r}, {name})")
        is_dir = path in self.dirs
        true_val = self.h.read_u64(h._data_addr["_kCFBooleanTrue"])
        false_val = self.h.read_u64(h._data_addr["_kCFBooleanFalse"])
        if name == "kCFURLIsDirectoryKey":
            self.h.write_u64(out, true_val if is_dir else false_val)
            return 1
        if name == "kCFURLIsHiddenKey":
            self.h.write_u64(out, false_val)
            return 1
        if name in ("kCFURLFileSecurityKey", "kCFURLTypeIdentifierKey"):
            self.h.write_u64(out, 0x60080000)
            return 1
        return 0

    def cfurl_set_prop(self, h: "Harness") -> int:
        return 1

    def objc_msgSend(self, h: "Harness") -> int:
        sel = self.h.read_cstr(self._a(1))
        self._note(f"objc_msgSend({sel!r})")
        if sel == "processInfo":
            return self.h.object(0x100)
        if sel == "operatingSystem":
            return 0x0D
        if sel == "isOperatingSystemAtLeastVersion:":
            return 1
        return 0
