"""Core ROP gadget scanning logic.

Public API
----------
scan_file(filepath, ...)
    Parse a PE file (DLL / EXE) and return all discovered ROP gadgets.

scan_bytes(data, ...)
    Scan raw bytes (no PE header) and return all discovered ROP gadgets.
    Useful for unit-testing individual code regions.
"""

from typing import Iterator, List, Set, Tuple

import capstone
import pefile

from .gadget import Gadget, Instruction
from .pe_parser import detect_arch, get_executable_sections

# ---------------------------------------------------------------------------
# RET opcode table: opcode byte -> total instruction length in bytes
# ---------------------------------------------------------------------------
#   0xC3  – near return (no operand)
#   0xC2  – near return with 16-bit stack displacement
#   0xCB  – far  return (no operand)
#   0xCA  – far  return with 16-bit stack displacement
_RET_LENGTHS = {0xC3: 1, 0xC2: 3, 0xCB: 1, 0xCA: 3}

# Mnemonics that are valid *only* as the last instruction of a gadget.
# Any of these appearing before the final instruction would break control flow.
_BRANCH_MNEMONICS: Set[str] = {
    "jmp", "je", "jne", "jz", "jnz", "ja", "jb", "jae", "jbe",
    "jg", "jl", "jge", "jle", "jo", "jno", "js", "jns", "jp", "jnp",
    "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne",
    "call", "int", "int3", "hlt", "ud2", "ud1",
}

# Maximum number of bytes a single x86/x64 instruction can occupy.
_MAX_INSN_BYTES = 15


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _find_ret_offsets(data: bytes) -> List[int]:
    """Return the byte offsets of every RET-family opcode in *data*."""
    return [i for i, b in enumerate(data) if b in _RET_LENGTHS]


def _make_cs(arch: str) -> capstone.Cs:
    """Return a configured Capstone disassembler for the given architecture."""
    if arch == "x64":
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = False
    return cs


def _gadgets_from_region(
    cs: capstone.Cs,
    data: bytes,
    region_base: int,
    max_gadget_depth: int,
) -> Iterator[Gadget]:
    """Yield unique gadgets found within a single contiguous memory region.

    Parameters
    ----------
    cs:
        Configured Capstone disassembler.
    data:
        Raw bytes of the region to scan.
    region_base:
        Absolute virtual address of the first byte of *data*.
    max_gadget_depth:
        Maximum number of instructions (including the final RET) per gadget.
    """
    seen: Set[Tuple[str, ...]] = set()

    for ret_off in _find_ret_offsets(data):
        ret_byte = data[ret_off]
        ret_end = ret_off + _RET_LENGTHS[ret_byte]

        # Search backwards from just before the RET up to max_gadget_depth
        # instructions * 15 bytes (the max length of one x86 instruction).
        max_lookback = min(ret_off, max_gadget_depth * _MAX_INSN_BYTES)

        for start in range(ret_off - max_lookback, ret_off + 1):
            segment = data[start:ret_end]
            start_va = region_base + start

            instructions: List[Instruction] = []
            for insn in cs.disasm(segment, start_va):
                instructions.append(
                    Instruction(
                        address=insn.address,
                        mnemonic=insn.mnemonic,
                        op_str=insn.op_str,
                        size=insn.size,
                    )
                )

            if not instructions:
                continue

            # Verify the disassembly covers exactly the bytes we fed it,
            # meaning every byte decoded cleanly (no invalid opcodes).
            total_bytes = sum(i.size for i in instructions)
            if total_bytes != ret_end - start:
                continue

            # The final instruction must be a RET variant.
            last = instructions[-1]
            if last.mnemonic not in ("ret", "retf"):
                continue

            # No branching / flow-breaking instructions before the final RET.
            if any(i.mnemonic in _BRANCH_MNEMONICS for i in instructions[:-1]):
                continue

            if len(instructions) > max_gadget_depth:
                continue

            key = tuple(str(i) for i in instructions)
            if key in seen:
                continue
            seen.add(key)

            yield Gadget(address=start_va, instructions=instructions)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_bytes(
    data: bytes,
    base_address: int = 0,
    max_gadget_depth: int = 5,
    arch: str = "x86",
) -> List[Gadget]:
    """Scan raw bytes for ROP gadgets.

    Parameters
    ----------
    data:
        Raw bytes to scan (e.g. the content of an executable section).
    base_address:
        Virtual address to assign to the first byte of *data*.
    max_gadget_depth:
        Maximum number of instructions (including the final RET) per gadget.
    arch:
        Target architecture: ``'x86'`` (32-bit) or ``'x64'`` (64-bit).

    Returns
    -------
    list[Gadget]
        Address-sorted list of unique gadgets.
    """
    cs = _make_cs(arch)
    gadgets = sorted(
        _gadgets_from_region(cs, data, base_address, max_gadget_depth),
        key=lambda g: g.address,
    )
    return gadgets


def scan_file(
    filepath: str,
    max_gadget_depth: int = 5,
    arch: str = "auto",
) -> List[Gadget]:
    """Scan a PE file (DLL or EXE) for ROP gadgets.

    Parameters
    ----------
    filepath:
        Path to the PE file on disk.
    max_gadget_depth:
        Maximum number of instructions (including the final RET) per gadget.
    arch:
        Target architecture: ``'auto'`` (detect from PE header), ``'x86'``,
        or ``'x64'``.

    Returns
    -------
    list[Gadget]
        Address-sorted list of unique gadgets discovered across all executable
        sections of the PE file.

    Raises
    ------
    FileNotFoundError
        If *filepath* does not exist.
    pefile.PEFormatError
        If the file is not a valid PE binary.
    """
    pe = pefile.PE(filepath)

    effective_arch = detect_arch(pe) if arch == "auto" else arch
    cs = _make_cs(effective_arch)

    image_base = pe.OPTIONAL_HEADER.ImageBase
    seen: Set[Tuple[str, ...]] = set()
    all_gadgets: List[Gadget] = []

    for rva, section_data in get_executable_sections(pe):
        region_base = image_base + rva
        for gadget in _gadgets_from_region(cs, section_data, region_base, max_gadget_depth):
            key = tuple(str(i) for i in gadget.instructions)
            if key not in seen:
                seen.add(key)
                all_gadgets.append(gadget)

    all_gadgets.sort(key=lambda g: g.address)
    return all_gadgets
