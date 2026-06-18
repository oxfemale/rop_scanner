"""PE file parsing utilities for extracting executable sections."""

from typing import List, Tuple

import pefile


# PE machine-type constants
_MACHINE_AMD64 = 0x8664
_MACHINE_I386 = 0x014C
_MACHINE_ARM64 = 0xAA64

# Section characteristic flag for executable memory
_SCN_MEM_EXECUTE = 0x20000000


def get_executable_sections(pe: pefile.PE) -> List[Tuple[int, bytes]]:
    """Return (virtual_address, raw_data) pairs for all executable sections.

    *virtual_address* is relative to the image base, i.e. the RVA that must be
    added to ``pe.OPTIONAL_HEADER.ImageBase`` to get an absolute address.
    """
    sections: List[Tuple[int, bytes]] = []
    for section in pe.sections:
        if section.Characteristics & _SCN_MEM_EXECUTE:
            sections.append((section.VirtualAddress, section.get_data()))
    return sections


def detect_arch(pe: pefile.PE) -> str:
    """Return ``'x64'`` for 64-bit PE files, ``'x86'`` otherwise."""
    machine = pe.FILE_HEADER.Machine
    if machine == _MACHINE_AMD64:
        return "x64"
    return "x86"
