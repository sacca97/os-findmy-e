"""Heap regressions; no Apple binary, credentials, or network required."""

import unittest
from types import SimpleNamespace

from unicorn.x86_const import UC_X86_REG_RDI, UC_X86_REG_RSI

from macos_adi_emulator.adi import Adid
from macos_adi_emulator.adi_layout import HEAP_ADDRESS, HEAP_SIZE
from macos_adi_emulator.harness import EmulationError, Harness


class HeapTests(unittest.TestCase):
    def setUp(self):
        image = SimpleNamespace(
            macho=SimpleNamespace(bind_symbols=lambda: [], all_binds=lambda: []),
            map_into=lambda uc: None,
        )
        self.h = Harness(image)

    def test_free_reuses_and_coalesces_ranges(self):
        a = self.h.heap_alloc(0x100)
        b = self.h.heap_alloc(0x100)
        self.h.heap_free(a)
        self.h.heap_free(b)
        self.assertEqual(self.h.heap_alloc(HEAP_SIZE), HEAP_ADDRESS)

    def test_page_alignment_preserves_padding_and_live_allocations(self):
        a = self.h.heap_alloc(0x20)
        self.h.mem_write(a, b"live")
        mapping = self.h.heap_alloc(0x1000, alignment=0x1000)
        self.assertEqual(mapping % 0x1000, 0)
        b = self.h.heap_alloc(0x20)
        self.assertEqual(b, a + 0x20)
        self.h.heap_free(mapping)
        self.assertEqual(self.h.mem_read(a, 4), b"live")

    def test_exhaustion_fails_before_returning_unmapped_pointer(self):
        self.h.heap_alloc(HEAP_SIZE)
        with self.assertRaisesRegex(EmulationError, "heap exhausted"):
            self.h.heap_alloc(1)

    def test_libc_free_and_null(self):
        self.h.uc.reg_write(UC_X86_REG_RDI, 0x100)
        addr = self.h._malloc(self.h)
        self.h.uc.reg_write(UC_X86_REG_RDI, addr)
        self.h._free(self.h)
        self.h.uc.reg_write(UC_X86_REG_RDI, 0)
        self.h._free(self.h)
        self.assertEqual(self.h.heap_alloc(0x100), addr)

    def test_cstr_at_end_of_mapping(self):
        addr = HEAP_ADDRESS + HEAP_SIZE - 5
        self.h.mem_write(addr, b"test\0")
        self.assertEqual(self.h.read_cstr(addr), "test")

    def test_cstr_across_pages_and_at_length_limit(self):
        addr = HEAP_ADDRESS + 0xFFF
        self.h.mem_write(addr, b"a" * 130 + b"\0")
        self.assertEqual(self.h.read_cstr(addr), "a" * 130)
        self.assertEqual(self.h.read_cstr(addr, 65), "a" * 65)

    def test_repeated_otp_mapping_pattern_is_bounded_and_zero_filled(self):
        daemon = Adid.__new__(Adid)
        daemon.harness = self.h
        daemon._client = {}
        daemon._install_stubs()
        mmap = self.h._handlers["mmap"]
        munmap = self.h._handlers["munmap"]
        # RequestOTP creates four 0x81000-byte temporary mappings. Previously
        # its eighth call returned a pointer beyond the 16 MiB heap.
        for _ in range(100):
            addresses = []
            for _ in range(4):
                self.h.uc.reg_write(UC_X86_REG_RSI, 0x81000)
                addr = mmap(self.h)
                self.assertEqual(self.h.mem_read(addr, 4), bytes(4))
                self.assertEqual(self.h.mem_read(addr + 0x80FFC, 4), bytes(4))
                self.h.mem_write(addr, b"used")
                self.h.mem_write(addr + 0x80FFC, b"used")
                addresses.append(addr)
            for i in (3, 0, 2, 1):
                self.h.uc.reg_write(UC_X86_REG_RDI, addresses[i])
                self.h.uc.reg_write(UC_X86_REG_RSI, 0x81000)
                self.assertEqual(munmap(self.h), 0)
        self.assertEqual(self.h._heap_cur - HEAP_ADDRESS, 4 * 0x81000)
        self.assertFalse(self.h._heap_allocations)


if __name__ == "__main__":
    unittest.main()
