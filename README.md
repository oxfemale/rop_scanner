# rop_scanner

Gadget scanner that finds ROP gadgets inside any Windows DLL — a utility you
can plug into any technique that requires ROP chains.

## Features

- Parses Windows PE files (DLL and EXE, 32-bit and 64-bit)
- Scans all executable sections for every RET-family opcode
- Searches backward for valid instruction sequences ending at each RET
- Filters out intermediate branching/flow-breaking instructions
- Deduplicates gadgets across sections
- Configurable gadget depth
- Simple command-line interface

## Requirements

```
pip install -r requirements.txt
```

Dependencies: `capstone` (disassembler), `pefile` (PE parser).

## Usage

```
python main.py <PE file> [options]

positional arguments:
  file                  Path to the target PE file (DLL or EXE)

options:
  -h, --help            show this help message and exit
  --depth N, -d N       Maximum number of instructions per gadget (default: 5)
  --arch {auto,x86,x64}, -a {auto,x86,x64}
                        Target architecture; 'auto' reads it from the PE header (default: auto)
  --output FILE, -o FILE
                        Write gadgets to FILE instead of stdout
```

### Examples

Scan a 32-bit DLL with default settings (depth 5, architecture auto-detected):

```
python main.py kernel32.dll
```

Scan a 64-bit DLL with depth 8 and save results to a file:

```
python main.py ntdll.dll --depth 8 --output ntdll_gadgets.txt
```

### Sample output

```
Found 1842 unique gadget(s) in 'kernel32.dll'
0x7c801234: pop eax ; ret
0x7c801567: xor eax, eax ; pop ebx ; ret
0x7c802abc: mov eax, ecx ; ret
...
```

## Python API

```python
from rop_scanner import scan_file, scan_bytes

# Scan a PE file
gadgets = scan_file("kernel32.dll", max_gadget_depth=5, arch="auto")
for g in gadgets:
    print(g)          # e.g.  0x7c801234: pop eax ; ret
    print(hex(g.address))
    for insn in g.instructions:
        print(insn.mnemonic, insn.op_str)

# Scan raw bytes (useful for shellcode analysis or testing)
code = bytes([0x58, 0xC3])   # POP EAX ; RET
gadgets = scan_bytes(code, base_address=0x10001000, arch="x86")
```

## Architecture

| Module | Responsibility |
|---|---|
| `rop_scanner/gadget.py` | `Instruction` and `Gadget` data classes |
| `rop_scanner/pe_parser.py` | PE header parsing, executable section extraction |
| `rop_scanner/scanner.py` | Core gadget-finding logic (`scan_file`, `scan_bytes`) |
| `main.py` | Command-line interface |

## Running tests

```
pytest tests/
```
