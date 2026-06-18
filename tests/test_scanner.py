"""Unit tests for the ROP gadget scanner.

Tests exercise ``scan_bytes`` (no PE header required) and the ``Gadget`` /
``Instruction`` data classes.  A minimal in-memory PE is used to test
``scan_file``.
"""

import io
import os
import struct
import tempfile
from typing import List

import pytest

from rop_scanner import Gadget, Instruction, scan_bytes
from rop_scanner.scanner import scan_file


# ---------------------------------------------------------------------------
# Helper: build a minimal valid x86 PE in memory so that scan_file can be
# tested without needing a real Windows DLL on disk.
# ---------------------------------------------------------------------------

def _build_minimal_pe(code: bytes, x64: bool = False) -> bytes:
    """Return a minimal PE32 (or PE32+) file containing *code* in .text."""

    machine = 0x8664 if x64 else 0x014C
    magic   = 0x020B if x64 else 0x010B  # PE32+ vs PE32

    # Fixed layout offsets
    pe_offset       = 0x40            # e_lfanew
    coff_offset     = pe_offset + 4   # right after "PE\0\0"
    num_sections    = 1
    opt_hdr_size    = 0xF0 if x64 else 0xE0
    section_offset  = coff_offset + 20 + opt_hdr_size   # COFF + optional
    raw_data_offset = section_offset + 40                # after one section hdr
    raw_data_offset = (raw_data_offset + 0x1FF) & ~0x1FF  # align to 512

    image_base   = 0x10000000
    section_rva  = 0x1000
    section_size = max(len(code), 0x200)

    image_size = section_rva + ((section_size + 0xFFF) & ~0xFFF)

    buf = bytearray(raw_data_offset + section_size)

    # --- DOS header ---
    buf[0:2] = b"MZ"
    struct.pack_into("<H", buf, 0x3C, pe_offset)   # e_lfanew

    # --- PE signature ---
    struct.pack_into("<I", buf, pe_offset, 0x00004550)  # "PE\0\0"

    # --- COFF / File header ---
    coff = coff_offset
    struct.pack_into("<H", buf, coff + 0,  machine)
    struct.pack_into("<H", buf, coff + 2,  num_sections)
    struct.pack_into("<I", buf, coff + 4,  0)            # TimeDateStamp
    struct.pack_into("<I", buf, coff + 8,  0)            # PointerToSymbolTable
    struct.pack_into("<I", buf, coff + 12, 0)            # NumberOfSymbols
    struct.pack_into("<H", buf, coff + 16, opt_hdr_size)
    struct.pack_into("<H", buf, coff + 18, 0x0002)       # Characteristics: EXE

    # --- Optional header ---
    opt = coff + 20
    struct.pack_into("<H", buf, opt + 0, magic)
    struct.pack_into("<I", buf, opt + 16, section_rva)  # AddressOfEntryPoint
    struct.pack_into("<I", buf, opt + 24, section_rva)  # BaseOfCode (PE32)
    if x64:
        struct.pack_into("<Q", buf, opt + 24, image_base)  # ImageBase (PE32+)
        struct.pack_into("<I", buf, opt + 56, image_size)  # SizeOfImage
        struct.pack_into("<I", buf, opt + 60, raw_data_offset)  # SizeOfHeaders
    else:
        struct.pack_into("<I", buf, opt + 28, section_rva)  # BaseOfData
        struct.pack_into("<I", buf, opt + 28 + 4, image_base)  # ImageBase (PE32)
        struct.pack_into("<I", buf, opt + 56, image_size)  # SizeOfImage
        struct.pack_into("<I", buf, opt + 60, raw_data_offset)  # SizeOfHeaders

    struct.pack_into("<I", buf, opt + 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", buf, opt + 36, 0x200)   # FileAlignment

    # DataDirectory count
    if x64:
        struct.pack_into("<I", buf, opt + 108, 16)
    else:
        struct.pack_into("<I", buf, opt + 92,  16)

    # --- Section header ---
    sec = section_offset
    buf[sec:sec+8] = b".text\x00\x00\x00"
    struct.pack_into("<I", buf, sec + 8,  section_size)       # VirtualSize
    struct.pack_into("<I", buf, sec + 12, section_rva)        # VirtualAddress
    struct.pack_into("<I", buf, sec + 16, section_size)       # SizeOfRawData
    struct.pack_into("<I", buf, sec + 20, raw_data_offset)    # PointerToRawData
    struct.pack_into("<I", buf, sec + 36,
                     0x60000020)  # CNT_CODE | MEM_EXECUTE | MEM_READ

    # --- Code ---
    buf[raw_data_offset:raw_data_offset + len(code)] = code

    return bytes(buf)


# ---------------------------------------------------------------------------
# Tests: Gadget / Instruction data classes
# ---------------------------------------------------------------------------

class TestInstruction:
    def test_str_with_operand(self):
        insn = Instruction(address=0x1000, mnemonic="pop", op_str="eax", size=1)
        assert str(insn) == "pop eax"

    def test_str_no_operand(self):
        insn = Instruction(address=0x1000, mnemonic="ret", op_str="", size=1)
        assert str(insn) == "ret"

    def test_repr(self):
        insn = Instruction(address=0x1000, mnemonic="nop", op_str="", size=1)
        assert "0x1000" in repr(insn)


class TestGadget:
    def _make(self, mnemonics):
        insns = [
            Instruction(address=0x1000 + i, mnemonic=m, op_str="", size=1)
            for i, m in enumerate(mnemonics)
        ]
        return Gadget(address=0x1000, instructions=insns)

    def test_str_format(self):
        g = self._make(["nop", "ret"])
        assert g.display_address in str(g)
        assert "nop" in str(g)
        assert "ret" in str(g)

    def test_equality_same_instructions(self):
        g1 = self._make(["pop eax", "ret"])
        g2 = self._make(["pop eax", "ret"])
        assert g1 == g2

    def test_inequality_different_instructions(self):
        g1 = self._make(["nop", "ret"])
        g2 = self._make(["ret"])
        assert g1 != g2

    def test_hashable(self):
        g = self._make(["nop", "ret"])
        s = {g}
        assert g in s

    def test_deduplication_in_set(self):
        g1 = self._make(["nop", "ret"])
        g2 = self._make(["nop", "ret"])
        assert len({g1, g2}) == 1


# ---------------------------------------------------------------------------
# Tests: scan_bytes – x86
# ---------------------------------------------------------------------------

class TestScanBytesX86:
    BASE = 0x10001000

    def _scan(self, data: bytes, depth: int = 5) -> List[Gadget]:
        return scan_bytes(data, base_address=self.BASE, max_gadget_depth=depth, arch="x86")

    def _texts(self, gadgets: List[Gadget]) -> List[str]:
        return [str(g) for g in gadgets]

    # --- basic RET gadget ---
    def test_single_ret(self):
        gadgets = self._scan(b"\xC3")
        assert len(gadgets) == 1
        assert gadgets[0].instructions[0].mnemonic == "ret"

    def test_ret_address(self):
        gadgets = self._scan(b"\xC3")
        assert gadgets[0].address == self.BASE

    # --- NOP ; RET ---
    def test_nop_ret(self):
        data = bytes([0x90, 0xC3])
        gadgets = self._scan(data)
        texts = self._texts(gadgets)
        assert any("nop" in t and "ret" in t for t in texts), texts

    def test_nop_ret_standalone_ret_also_present(self):
        data = bytes([0x90, 0xC3])
        gadgets = self._scan(data)
        texts = self._texts(gadgets)
        assert any(t.endswith(": ret") for t in texts), texts

    # --- POP ; RET ---
    def test_pop_eax_ret(self):
        data = bytes([0x58, 0xC3])   # POP EAX; RET
        gadgets = self._scan(data)
        texts = self._texts(gadgets)
        assert any("pop eax" in t and "ret" in t for t in texts), texts

    def test_pop_ecx_ret(self):
        data = bytes([0x59, 0xC3])   # POP ECX; RET
        gadgets = self._scan(data)
        texts = self._texts(gadgets)
        assert any("pop ecx" in t for t in texts), texts

    # --- RETN imm16 ---
    def test_retn_imm(self):
        data = bytes([0xC2, 0x08, 0x00])  # RETN 8
        gadgets = self._scan(data)
        assert len(gadgets) == 1
        assert gadgets[0].instructions[0].mnemonic == "ret"

    # --- RETF ---
    def test_retf(self):
        data = bytes([0xCB])   # RETF
        gadgets = self._scan(data)
        assert any(g.instructions[-1].mnemonic == "retf" for g in gadgets)

    # --- multi-instruction gadget ---
    def test_multi_instruction_gadget(self):
        # XOR EAX, EAX (0x31 0xC0); POP EBX (0x5B); RET (0xC3)
        data = bytes([0x31, 0xC0, 0x5B, 0xC3])
        gadgets = self._scan(data)
        texts = self._texts(gadgets)
        assert any("xor eax, eax" in t and "pop ebx" in t and "ret" in t
                   for t in texts), texts

    # --- depth limit ---
    def test_depth_limit_excludes_long_gadgets(self):
        # 5 NOPs then RET
        data = bytes([0x90] * 5 + [0xC3])
        gadgets_d2 = self._scan(data, depth=2)
        texts_d2 = self._texts(gadgets_d2)
        # depth=2 means at most 1 instruction before RET
        assert not any(t.count("nop") > 1 for t in texts_d2), texts_d2

    # --- branching instructions are excluded from non-final positions ---
    def test_no_intermediate_call(self):
        # CALL rel32 (0xE8 00 00 00 00); RET (0xC3)
        data = bytes([0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3])
        gadgets = self._scan(data)
        texts = self._texts(gadgets)
        # Only the standalone RET at the end should be found
        assert all("call" not in t for t in texts), texts

    def test_no_intermediate_jmp(self):
        # JMP rel8 (0xEB 00); RET (0xC3)
        data = bytes([0xEB, 0x00, 0xC3])
        gadgets = self._scan(data)
        texts = self._texts(gadgets)
        assert all("jmp" not in t for t in texts), texts

    # --- uniqueness ---
    def test_no_duplicate_gadgets(self):
        data = bytes([0x90, 0x90, 0xC3])
        gadgets = self._scan(data)
        strs = [str(g) for g in gadgets]
        assert len(strs) == len(set(strs))

    # --- output is address-sorted ---
    def test_results_sorted_by_address(self):
        # Two separate RET instructions
        data = bytes([0xC3, 0x90, 0xC3])
        gadgets = self._scan(data)
        addrs = [g.address for g in gadgets]
        assert addrs == sorted(addrs)


# ---------------------------------------------------------------------------
# Tests: scan_bytes – x64
# ---------------------------------------------------------------------------

class TestScanBytesX64:
    BASE = 0x140001000

    def test_pop_rax_ret(self):
        # POP RAX (0x58); RET (0xC3) – same encoding as x86
        data = bytes([0x58, 0xC3])
        gadgets = scan_bytes(data, base_address=self.BASE, arch="x64")
        texts = [str(g) for g in gadgets]
        # Capstone will decode 0x58 as 'pop rax' in 64-bit mode
        assert any("pop rax" in t and "ret" in t for t in texts), texts

    def test_base_address_reflected(self):
        data = bytes([0xC3])
        gadgets = scan_bytes(data, base_address=self.BASE, arch="x64")
        assert gadgets[0].address == self.BASE


# ---------------------------------------------------------------------------
# Tests: scan_file
# ---------------------------------------------------------------------------

class TestScanFile:
    def _write_pe(self, code: bytes, x64: bool = False) -> str:
        pe_bytes = _build_minimal_pe(code, x64=x64)
        fd, path = tempfile.mkstemp(suffix=".dll")
        os.write(fd, pe_bytes)
        os.close(fd)
        return path

    def test_scan_file_finds_ret(self):
        path = self._write_pe(bytes([0xC3]))
        try:
            gadgets = scan_file(path)
            assert len(gadgets) >= 1
            assert any(g.instructions[-1].mnemonic == "ret" for g in gadgets)
        finally:
            os.unlink(path)

    def test_scan_file_finds_pop_ret(self):
        path = self._write_pe(bytes([0x58, 0xC3]))
        try:
            gadgets = scan_file(path)
            texts = [str(g) for g in gadgets]
            assert any("pop eax" in t and "ret" in t for t in texts), texts
        finally:
            os.unlink(path)

    def test_scan_file_auto_arch_x86(self):
        path = self._write_pe(bytes([0xC3]), x64=False)
        try:
            gadgets = scan_file(path, arch="auto")
            assert len(gadgets) >= 1
        finally:
            os.unlink(path)

    def test_scan_file_auto_arch_x64(self):
        path = self._write_pe(bytes([0xC3]), x64=True)
        try:
            gadgets = scan_file(path, arch="auto")
            assert len(gadgets) >= 1
        finally:
            os.unlink(path)

    def test_scan_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            scan_file("/nonexistent/path/to/nothing.dll")

    def test_scan_file_invalid_pe(self):
        import pefile
        fd, path = tempfile.mkstemp(suffix=".dll")
        os.write(fd, b"not a PE file at all")
        os.close(fd)
        try:
            with pytest.raises(pefile.PEFormatError):
                scan_file(path)
        finally:
            os.unlink(path)

    def test_scan_file_depth_respected(self):
        # 10 NOPs then RET – with depth=2 we should not see 10-NOP gadgets
        code = bytes([0x90] * 10 + [0xC3])
        path = self._write_pe(code)
        try:
            gadgets = scan_file(path, max_gadget_depth=2)
            for g in gadgets:
                assert len(g.instructions) <= 2
        finally:
            os.unlink(path)
