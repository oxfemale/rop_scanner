"""Data classes representing disassembled instructions and ROP gadgets."""

from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class Instruction:
    """A single disassembled instruction."""

    address: int
    mnemonic: str
    op_str: str
    size: int

    def __str__(self) -> str:
        if self.op_str:
            return f"{self.mnemonic} {self.op_str}"
        return self.mnemonic

    def __repr__(self) -> str:
        return f"Instruction(0x{self.address:x}, {str(self)!r})"


@dataclass
class Gadget:
    """A ROP gadget: a sequence of instructions ending with a return."""

    address: int
    instructions: List[Instruction] = field(default_factory=list)

    @property
    def display_address(self) -> str:
        return f"0x{self.address:08x}"

    def _instruction_key(self) -> Tuple[str, ...]:
        return tuple(str(i) for i in self.instructions)

    def __str__(self) -> str:
        insns = " ; ".join(str(i) for i in self.instructions)
        return f"{self.display_address}: {insns}"

    def __repr__(self) -> str:
        return f"Gadget(address=0x{self.address:x}, instructions={self.instructions!r})"

    def __hash__(self) -> int:
        return hash(self._instruction_key())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Gadget):
            return NotImplemented
        return self._instruction_key() == other._instruction_key()
