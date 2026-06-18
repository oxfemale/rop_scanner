<p align="right">
  <b>🇬🇧 English</b> ·
  <a href="README_ru.md">🇷🇺 Русский</a> ·
  <a href="README_ua.md">🇺🇦 Українська</a> ·
  <a href="README_ch.md">🇨🇳 中文</a> ·
  <a href="README_ge.md">🇩🇪 Deutsch</a> ·
  <a href="README_fr.md">🇫🇷 Français</a>
</p>

<p align="center">
  <img src="docs/img/banner.svg" alt="rop_scanner — offline PE → Zydis → ROP / JOP / syscall / pivot gadgets" width="100%"/>
</p>

# rop_scanner

**Cross-platform (Windows / Linux / macOS) offline hunter for ROP, JOP, syscall and stack-pivot gadgets in Windows PE files.** It parses DLL / EXE / SYS / CPL / OCX / DRV / EFI files directly from disk — never loading them into a process address space — decodes every byte with the [Zydis](https://github.com/zyantific/zydis) disassembler, and emits ranked gadgets in one of four formats: `text`, `json`, `ropper` or a ready-to-paste Python dictionary for `pwntools`.

> The idea and original write-up are by **0x12 Dark Development** ([@Salsa12__](https://twitter.com/Salsa12__)),
> [«Hunting ROP Gadgets in Windows DLLs»](https://medium.com/@s12deff/hunting-rop-gadgets-in-windows-dlls-3184e4eeba62).
> This project is an independent C++17 implementation and extension of those ideas.

---

## Table of contents

1. [Why this exists](#1-why-this-exists)
2. [What's inside and how it works](#2-whats-inside-and-how-it-works)
3. [Anatomy of a gadget](#3-anatomy-of-a-gadget)
4. [Classification: category × semantic](#4-classification-category--semantic)
5. [Building](#5-building)
6. [Quick start](#6-quick-start)
7. [Full CLI reference](#7-full-cli-reference)
8. [Run scenarios](#8-run-scenarios)
9. [The Qt6 GUI](#9-the-qt6-gui)
10. [Use in exploit development](#10-use-in-exploit-development)
11. [Comparison with alternatives](#11-comparison-with-alternatives)
12. [Where else this fits](#12-where-else-this-fits)
13. [Limitations](#13-limitations)
14. [Credits and legal](#14-credits-and-legal)

---

## 1. Why this exists

Any modern user-mode exploit on x86_64 Windows runs into the same wall: once you control RIP, you still have to get to **code execution** without tripping DEP / CFG / CET. The classic answer is **Return-Oriented Programming** — stitch together short fragments of already-loaded code (`pop rcx ; ret`, `xchg rax, rsp ; ret`, `syscall`, …) so that, executed via stack returns, they do the actual work for you — usually walking up to `VirtualProtect` or a direct `syscall NtProtectVirtualMemory` to flip the shellcode page RWX.

<p align="center">
  <img src="docs/img/exploit-chain.svg" alt="Where rop_scanner fits in an exploit chain" width="100%"/>
</p>

This only works if you have a **good catalogue of gadgets** — concrete RVAs inside modules that you can be sure are mapped into the victim process. And that's where the pain starts:

- **MSVC doesn't emit "convenient" gadgets** out of the box. `pop rcx ; pop rdx ; pop r8 ; pop r9 ; ret` (the Windows x64 calling convention) is almost never present as a natural epilogue. It has to be discovered as a **side effect of starting the decoder on an off-by-one boundary**.
- **CFG, XFG, CET Shadow Stack** kill some candidates. You need to know which RVAs are valid indirect-call targets (`IMAGE_LOAD_CONFIG_DIRECTORY.GuardCFFunctionTable`) so you can either aim at them or avoid them.
- **Bad bytes** (`\x00`, `\x0a`, `\x0d`, protocol terminators, validation markers) wipe out half the results of any "generic" scanner.
- **Cross-module search.** The real prize is gadgets that exist in **every module that's loaded by default**. Any `pop rcx ; ret` tied to a specific DLL breaks if the victim runs a different Windows build or has a different module set.

`rop_scanner` tackles those four head-on: full Zydis-grade decoding, CFG / `.pdata` / EAT parsing, bad-byte filtering at search time, and a batch mode that aggregates by `(asm)` across dozens of modules. One `.cpp` file or all of `C:\Windows\System32` — same command.

---

## 2. What's inside and how it works

<p align="center">
  <img src="docs/img/pipeline.svg" alt="Pipeline: PE → pe_loader → ending finder → back-decoder → classify" width="100%"/>
</p>

Five stages, each in its own `.cpp`:

| Stage | File | What it does |
|---|---|---|
| PE parsing | [pe_loader.cpp](src/pe_loader.cpp) + [pe_types.h](src/pe_types.h) | MZ → PE\\0\\0 → sections → `IMAGE_DIRECTORY_ENTRY_EXPORT`, `_EXCEPTION` (.pdata RUNTIME_FUNCTION), `_LOAD_CONFIG` (CFG GuardCF table) |
| Ending discovery | [scanner.cpp](src/scanner.cpp) | for every byte in a section, Zydis is asked to decode one instruction at that offset. If the result is an acceptable terminator (`ret`, `ret imm16`, `syscall`, `sysenter`, `jmp reg`, `call reg`), record it |
| Back-decoding | [scanner.cpp](src/scanner.cpp) | for each ending, try every starting offset from `endPos - maxBytes` up to `endPos`. Decode forward with Zydis; the chain is valid iff it terminates **exactly** at the ending within `--max-insn` instructions and contains no control-flow instructions in its body |
| Classification | [gadget.cpp](src/gadget.cpp) | category (by terminator) + semantic (by body effect) + score (0–100) with boosts for the Windows x64 ABI |
| Annotation | [symbol_resolver.cpp](src/symbol_resolver.cpp) | nearest export from EAT, containing function from `.pdata`, optional PDB via `dbghelp` (Windows-only), CFG-valid flag |

Core principles:

- **Full decoder.** The first cut shipped a hand-rolled ~250-line mini-decoder that knew only `pop reg`, `ret`, a few `mov` and `add rsp`. Zydis 4.1 covers all of x86 / x86_64, including VEX / EVEX, non-trivial `mov [mem], reg`, `lea`, `cmov*`, `pushfq` / `popfq`, and any memory operand. That gives you a real `write-mem` / `read-mem` search that the early version (and many "small" scanners) simply can't do — and classification stays cheap by walking Zydis's structured operands directly.
- **No side effects.** The binary parser never calls `LoadLibrary`, never hands bytes to a JIT or anything else with side effects. You can safely scan known-malicious samples.
- **One artifact.** A self-contained executable with no runtime dependencies beyond libc / libstdc++. On Windows you additionally pick up an *optional* dependency on `dbghelp.dll` (which ships in every Windows install).

---

## 3. Anatomy of a gadget

<p align="center">
  <img src="docs/img/anatomy.svg" alt="Anatomy of a gadget: bytes → instructions → terminator" width="100%"/>
</p>

In one frame: the raw seven bytes `59 5A 41 58 41 59 C3` are decoded by Zydis into five instructions — `pop rcx`, `pop rdx`, `pop r8` (REX.B + pop), `pop r9` (REX.B + pop), `ret`. Terminator: `C3` (`ret`). Body: four unconditional pops that do exactly what the Windows x64 calling convention needs — load the first four argument registers (`rcx / rdx / r8 / r9`) from whatever sits on the stack.

`rop_scanner` finds this kind of gadget in any sufficiently large PE on an off-by-one byte boundary. With +10 score for every `pop rXX` matching the x64 ABI and +15 for `xchg rax, rsp` / `leave`, this chain scores a perfect **100/100**.

---

## 4. Classification: category × semantic

<p align="center">
  <img src="docs/img/taxonomy.svg" alt="Two-axis taxonomy: category by terminator, semantic by body effect" width="100%"/>
</p>

Every gadget is labeled on **two independent axes**, both available as substring filters via `--filter`:

- **Category** describes *how* the gadget ends. This axis determines where the gadget plugs in: `rop` chains via the stack, `jop` via a register indirect jmp/call, `syscall` exits to the kernel, `pivot` switches RSP.
- **Semantic** describes *what* the gadget does between start and terminator: load a constant, copy a register, write or read memory, do arithmetic, switch the stack.

Why it matters: `--filter "write-mem"` will find **every** write-what-where primitive (`mov [rax], rdx ; ret`, `mov [rcx+0x10], r8 ; ret`, …) regardless of how it ends. `--filter "load-const"` finds all argument loaders.

---

## 5. Building

> All builds need a **C++17** compiler and **CMake ≥ 3.16**. Zydis is pulled in automatically via `FetchContent` on first configure.

### Windows  (MSVC / Visual Studio 2019+)

From a *Developer Command Prompt for VS 2022* (or a regular cmd after `call vcvars64.bat`):

```cmd
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
:: -> build\bin\rop_scanner.exe
```

`dbghelp.lib` is linked automatically for the optional `--pdb` PDB resolver. If Ninja isn't installed, drop `-G Ninja` and MSBuild will handle it.

Expected tail of the build output:

```
[42/43] Building CXX object CMakeFiles/rop_scanner.dir/src/scanner.cpp.obj
[43/43] Linking CXX executable bin/rop_scanner.exe
```

### Linux  (GCC / Clang)

Tested on Ubuntu 22.04 + GCC 11.4. No system dependencies beyond `cmake`, a C++ compiler, and `make`/`ninja`:

```sh
sudo apt install -y cmake g++ make            # Debian/Ubuntu
# or
sudo dnf install -y cmake gcc-c++ make        # Fedora/RHEL

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
# -> build/bin/rop_scanner
```

GCC < 9 split `<filesystem>` into `libstdc++fs` — CMake links it for you automatically. On Clang 10+ and GCC 9+ you need nothing extra.

### macOS  (Apple Clang)

You need only the Xcode Command Line Tools (`xcode-select --install`) and any CMake (Homebrew or the official one):

```sh
brew install cmake          # one-time
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
# -> build/bin/rop_scanner
```

Both Apple Silicon (arm64) and Intel (x86_64) work — `rop_scanner` only **reads** PE bytes, never executes them, so the host architecture is irrelevant.

> On Linux / macOS the `--pdb` flag is accepted but silently does nothing (no `dbghelp`). EAT + `.pdata` resolution still gives you almost exactly what a stripped public PDB would for any public Windows DLL.

### Bit-for-bit cross-platform consistency

The exact same x64 `ntdll.dll` produces **identical** output on all three platforms:

| Platform | Compiler | `exports` | `.pdata` | `cfg` | first hit for `pop rsi ; pop rdi ; ret` |
|---|---|---|---|---|---|
| Windows 11 x64 | MSVC 19.43 | 2516 | 5679 | 2197 | `0x000026B9` — `RtlGetUserInfoHeap+0xB9` |
| macOS arm64 | AppleClang 21 | 2516 | 5679 | 2197 | `0x000026B9` — `RtlGetUserInfoHeap+0xB9` |
| Linux x64  | GCC 11.4   | 2516 | 5679 | 2197 | `0x000026B9` — `RtlGetUserInfoHeap+0xB9` |

`static_assert` on the size of every PE structure in [pe_types.h](src/pe_types.h) guarantees this.

---

## 6. Quick start

The first minute:

```sh
# 1. Plain scan of ntdll.dll
./build/bin/rop_scanner /path/to/ntdll.dll | head -40
```

Expected first page (for x64 ntdll.dll on Windows 11):

```text
[+] module: ntdll.dll arch=x64 machine=0x8664 image_base=0x180000000
    sections=15 exports=2516 pdata=5679 cfg=2197
[+] gadgets: 17243

[pivot/stack-pivot] score=100 section=.text rva=0x0011F03A
  symbol: RtlCaptureContext2+0xFA
  function: fn_0x11EF40+0xFA
  bytes: 48 83 C4 30 59 C3
  asm  : add rsp, 0x30 ; pop rcx ; ret

[rop/load-const] score=70 section=.text rva=0x000026B9
  symbol: RtlGetUserInfoHeap+0xB9
  function: fn_0x2600+0xB9
  bytes: 5E 5F C3
  asm  : pop rsi ; pop rdi ; ret
...
```

The first line is the module passport; below it come the gadgets sorted by descending score. Each gadget shows: `[category/semantic]`, score, section, RVA and file offset, EAT symbol (`RtlGetUserInfoHeap+0xB9`), enclosing function from `.pdata`, raw bytes, decoded mnemonics.

---

## 7. Full CLI reference

```text
Usage:
  rop_scanner <pe-file> [pe-file ...] [options]
  rop_scanner --dir <path> [--recursive] [options]
```

### Scanning

| Flag | Default | Meaning |
|---|---|---|
| `--max-bytes N` | 10 | How far back from the terminator to try as a start. Lower → faster, higher → more off-by-one "inter-instruction" gadgets. |
| `--max-insn N`  | 5 | Maximum instructions per gadget, including the terminator. Practically useful chains rarely exceed 6. |
| `--min-score N` | 0 | Drop everything below the threshold. For real exploit work I use 60-70. |
| `--filter TEXT` | — | Case-insensitive substring searched in `asm + section + category + semantic + symbol + function`. One of the most powerful flags: you can search by disasm (`"pop rcx ; pop rdx"`), by semantic (`"write-mem"`), by symbol (`"Rtl"`), by category (`"pivot"`). |
| `--badbytes B,…` | — | Comma-separated list of "bad" bytes: `00,0a,0d,20`. A gadget whose raw bytes contain **any** of these gets dropped. This is the exact filter you want for string-based vulnerabilities (`strcpy`, `sprintf`, `gets`, etc.). |
| `--limit N` | 0 (all) | Keep only the top-N after sorting. |

### CFG (Control Flow Guard)

| Flag | Meaning |
|---|---|
| `--only-cfg`    | Keep only RVAs listed in `IMAGE_LOAD_CONFIG_DIRECTORY.GuardCFFunctionTable`. If your RIP-takeover path goes through an indirect call with CFG check, these are the only gadgets that are even legal. |
| `--exclude-cfg` | The opposite — drop CFG-valid targets. Useful when you're chaining gadgets through `ret` (CFG doesn't check ret-targets) but want to minimize collisions. |

### Symbols

| Flag | Meaning |
|---|---|
| `--no-symbols` | Skip EAT / `.pdata` annotation. Noticeably faster in batch mode. |
| `--pdb`        | Use `dbghelp.dll` for PDB resolution. Honors `_NT_SYMBOL_PATH`. Silently no-op on Linux / macOS. |

### Batch mode

| Flag | Meaning |
|---|---|
| `--dir PATH`  | Scan every PE under the directory. Recognized extensions: `dll exe sys cpl ocx drv efi`. |
| `--recursive` | Recurse into subdirectories. |

In batch mode, gadgets are deduplicated by `(asm)` across **different modules** and ranked by `module_count desc, score desc`. The top of the list is the most "ubiquitous" gadgets.

### Output format

| `--format …` | Output |
|---|---|
| `text` (default) | Human-readable |
| `json` | Everything as structured JSON. In batch mode includes the list of containing modules. |
| `ropper` | `0x180012345: pop rcx; ret;` — drop-in for `ropper` / `ROPgadget` consumers |
| `pwntools` | A valid Python dictionary with image_base, RVA, asm and symbol — `cat output.py >> exploit.py` |

### Misc

| Flag | Meaning |
|---|---|
| `--help`, `-h`, `/?` | Show help |

---

## 8. Run scenarios

### Case 1.  Win x64 calling-convention helpers

Goal — find the classic loader for the first four WinAPI argument registers:

```sh
rop_scanner ntdll.dll \
  --filter "pop rcx ; pop rdx ; pop r8" \
  --max-insn 6 \
  --limit 10
```

If the gadget isn't present as a clean sequence (and in ntdll it really is rare), the scanner will find off-by-one equivalents:

```text
[rop/load-const] score=92 section=.text rva=0x001255F4
  symbol: tan+0x3F4
  bytes: 5C C1 F2 0F 59 C2 F2 0F
  asm  : pop rsp ; shl edx, 0x0F ; pop rcx ; ret 0xFF2
```

These are bytes inside the body of `tan()` (the math function from libm) starting on a non-natural instruction boundary.

### Case 2.  Stack pivot for a misaligned stack

When RIP is hijacked at a point where the stack alignment is unpredictable, you need a **pivot** — usually `xchg rax, rsp ; ret` or `add rsp, 0x__ ; ret`:

```sh
rop_scanner ntdll.dll --filter "pivot" --min-score 95 --limit 5
```

You get ready candidates with exact RVAs and `.pdata` function names.

### Case 3.  Write-what-where

Search is **semantic**, not by instruction text:

```sh
rop_scanner ntdll.dll --filter "write-mem" --badbytes 00 --min-score 70
```

Output: every `mov [reg+disp], reg ; ret` equivalent with no NUL bytes in the payload.

### Case 4.  Bad-byte-aware  (full chain under `strcpy`)

```sh
rop_scanner ntdll.dll \
  --filter "pop rcx ; ret" \
  --badbytes 00,0a,0d,20,3b \
  --format pwntools > rop_chunk.py
```

`--badbytes` drops anything with a NUL byte (string termination), `\n`/`\r` (if the vuln is in an HTTP header), space, and `;`. `--format pwntools` is a ready dictionary you can `import` straight away.

### Case 5.  Cross-module search for guaranteed-loaded gadgets

<p align="center">
  <img src="docs/img/batch-hunt.svg" alt="Cross-module hunt across System32" width="100%"/>
</p>

```sh
rop_scanner --dir C:\Windows\System32 \
  --filter "syscall" \
  --min-score 80 \
  --no-symbols \
  --limit 50
```

Finds every two-byte `0F 05` and any longer sequence ending in `syscall`. Sorted by number of modules containing it. The gadgets at the top of the list are the most reliable foundation for a chain: they survive Windows rebuilds and version moves.

### Case 6.  CFG-aware indirect-call hijack

```sh
rop_scanner ntdll.dll --only-cfg --filter "jmp r" --limit 20
```

Finds `jmp reg` gadgets that CFG permits as indirect-call targets — i.e. legal landing pads for an indirect-call hijack on CET-defended Windows 10/11.

### Case 7.  Symbol-annotated + JSON for pipelines

```sh
set _NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols
rop_scanner ntdll.dll \
  --pdb \
  --min-score 70 \
  --format json > ntdll_gadgets.json
```

Produces a structured catalogue with PDB symbol names for later import into IDE / IDA scripts / your own gadget scheduler.

### Case 8.  Driver scanning

```sh
rop_scanner C:\Windows\System32\drivers\hidusb.sys --filter "syscall" --limit 5
```

Drivers parse exactly like regular PE32+ files — applicable to kernel-side gadget hunting without modifications.

---

## 9. The Qt6 GUI

If you'd rather not remember the flags, there's a cross-platform Qt6 GUI (with Qt5 fallback) that builds from the same source tree and just shells out to the CLI with the right arguments.

<p align="center">
  <img src="docs/img/gui-mockup.svg" alt="rop_scanner Qt GUI" width="100%"/>
</p>

**What it does:**

- File or directory selection via `Browse…` or **drag-and-drop** straight onto the window.
- Every CLI flag exposed as a form field (`--max-bytes`, `--max-insn`, `--min-score`, `--filter`, `--badbytes`, `--limit`, `--only-cfg`/`--exclude-cfg`, `--no-symbols`, `--pdb`, `--recursive`).
- Auto-detects the `rop_scanner` binary (next to the GUI, in `../bin`, in `../../build/bin`, in the macOS `.app` bundle's `Resources/`).
- Streaming output into a built-in dark console.
- **Copy cmdline** — assembles the exact shell command that would reproduce the run from a terminal. Handy for exploit-dev notes or handing off to a teammate.
- **Save output…** — writes `.txt`, `.json` or `.py` (chosen by `--format`).
- `QSettings` persistence of every field between launches.
- Cleanly tears down a stuck scan on `Cancel` (sends `SIGKILL`).

**Where the code lives:** [gui/](gui/) — a separate CMake target. Three files: [`MainWindow.cpp`](gui/src/MainWindow.cpp) (form + slots), [`ScannerRunner.cpp`](gui/src/ScannerRunner.cpp) (a thin `QProcess` wrapper), [`main.cpp`](gui/src/main.cpp) (entry point). Links against `Qt6::Widgets` or `Qt5::Widgets`, whichever is found first.

### Building the GUI

The GUI is an **optional** add-on to the main build. The same build scripts handle it, you just flip a flag.

#### macOS

```sh
brew install qt           # one-time
GUI=1 ./mac_build.sh
open build/bin/rop_scanner_gui.app
```

#### Linux  (Debian / Ubuntu)

```sh
sudo apt install qt6-base-dev libvulkan-dev
GUI=1 ./linux_build.sh
./build/bin/rop_scanner_gui
```

(on Fedora/RHEL replace `qt6-base-dev libvulkan-dev` with `qt6-qtbase-devel vulkan-headers`).

#### Windows

Install Qt6 one of these ways:

1. The official installer: <https://qt.io/download-open-source>
2. `vcpkg install qt6-base`
3. MSYS2: `pacman -S mingw-w64-x86_64-qt6-base`

Then point CMake at the install via an env var and run:

```cmd
set QT_PREFIX=C:\Qt\6.6.0\msvc2019_64
windows_build.bat build gui
build\bin\rop_scanner_gui.exe
```

### What you'll see

Top — mode selector (single file / directory batch), target path, recurse checkbox. Below it the **Scanning** group with numeric fields and the search filter, **CFG / Symbols** with a CFG-filter radio group and the `--no-symbols` / `--pdb` checkboxes. Below those — the output format dropdown, `Copy cmdline` / `Save output…` buttons, the `rop_scanner` binary path with auto-detect, and the big `▶ Run scan` button. At the bottom — a status line and a dark console that streams stdout (white) and stderr (amber) live.

---

## 10. Use in exploit development

The typical workflow:

1. **Pin the target environment** — which Windows build, which modules are guaranteed-loaded, which mitigations (CFG / XFG / CET / Shadow Stack).
2. **Snapshot those modules** into files (either grab from a clean install, or extract from your VM).
3. **Run `rop_scanner` in batch mode** on those files with `--no-symbols` for speed and `--format json` for downstream tooling. You'll get a catalogue of ~tens of thousands of gadgets.
4. **Narrow down** to the specific task:
   - write primitive → `--filter "write-mem"`
   - taking control of `rcx/rdx/r8/r9` → `--filter "load-const"` + verify the RVA
   - pivot → `--filter "pivot" --min-score 95`
   - syscall → `--filter "syscall"`
5. **Apply `--badbytes`** for the input string format of your vulnerability.
6. **If the exploit goes through an indirect call** — add `--only-cfg`.
7. **Stitch the chain.** `--format pwntools` saves half an hour here.

The same flow works for both user-mode (a browser, a parser, an RDP client) and kernel-mode (table overwrites, ROP in driver context).

### Not just Windows targets

A PE file is just a file; the decoder — Zydis — is just an x86 / x86_64 decoder. So `rop_scanner` is perfectly happy to scan:

- **MinGW-built PEs on Linux** — for cross-compile exploits and tests.
- **Windows malware** on a Linux / macOS reverse-engineering box — without any risk of loading it.
- **UEFI firmware** (`.efi` extension) — also a PE.
- **Old drivers** that have no PDBs.

---

## 11. Comparison with alternatives

| Tool | x86/x64 | PE | ELF | Mach-O | Semantic | Cross-module | CFG-aware | PDB | Cross-platform binary |
|---|---|---|---|---|---|---|---|---|---|
| **rop_scanner** | ✅ | ✅ | — | — | ✅ | ✅ | ✅ | ✅ (Win) | **✅ Win / Linux / mac** |
| ROPgadget (Python) | ✅ | ✅ | ✅ | ✅ | — | — | — | — | ✅ |
| ropper (Python) | ✅ | ✅ | ✅ | ✅ | — | — | — | — | ✅ |
| rp++ | ✅ | ✅ | ✅ | ✅ | — | — | — | — | ✅ |
| angrop | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | — | ✅ (slow) |

`rop_scanner` wins where the job is *Windows-specific*: semantics, CFG, `.pdata`, and cross-module search across `System32`. And it builds and runs where you most likely want to author the exploit — your own workstation.

---

## 12. Where else this fits

- **Malware analysis.** Pull every potential ROP chain out of a suspicious DLL / EXE without running it. Compare gadget tables before and after suspected unpacking — if the body bytes changed, your unpacker fired.
- **Threat hunting / detection engineering.** Snapshot your clean Windows host (batch-scan `System32`), then repeat regularly. Diff between runs = library mods = a reason to look at who touched them. (Microsoft patches ntdll on a predictable cadence and the gadget catalogue moves accordingly; anything that doesn't line up with Win Update is suspicious.)
- **Reverse engineering.** A gadget catalogue is a map of a function's "hot spots": where the short epilogues are, where syscalls live, where pivots are. Makes disassembly easier to read.
- **CTF.** Pwn-category PE challenges are a textbook fit. `--format pwntools` saves hours.
- **Teaching.** A good visualization of how ROP actually works: the student sees raw bytes, Zydis-decoded mnemonics, classification, score. Every stage is two screens of code.
- **Compiler-hardening audit.** Want to see how much your own build with `cl.exe /GS /guard:cf` actually starved an attacker? Compare the `pivot` counter under `--only-cfg` before and after flipping the flags.

---

## 13. Limitations

- **x86 and x86_64 only.** PE files for ARM64 / IA64 / RISC-V are rejected up front — Zydis doesn't know them.
- **`.pdata` parsing is x64-only** (`RUNTIME_FUNCTION`). On x86, SEH lives elsewhere; we don't use it.
- **CFG parsing.** We read the standard `IMAGE_LOAD_CONFIG_DIRECTORY` through `GuardFlags`. If Microsoft ever shifts that struct layout, we'll have to follow.
- **No CET / XFG-awareness** at the semantic level (XFG type-hashes aren't considered). On the v0.7 backlog.
- **Single-thread.** Batch-scanning `C:\Windows\System32` (~1500 PEs) takes a few minutes. Parallelization is roughly ten lines via `std::async`; in the backlog.
- **PDB only on Windows** (via `dbghelp`). On Linux / macOS you could wire up `llvm-pdbutil`, but it's not done — EAT is usually enough for public modules.

---

## 14. Credits and legal

- The original idea and approach: **0x12 Dark Development** ([@Salsa12__](https://twitter.com/Salsa12__))
  — the article [«Hunting ROP Gadgets in Windows DLLs»](https://medium.com/@s12deff/hunting-rop-gadgets-in-windows-dlls-3184e4eeba62) on Medium.
- The decoder: **[Zydis](https://github.com/zyantific/zydis)** by Florian Bernd and team — pulled in via `FetchContent` on the first CMake configure.
- This project is an independent C++17 reimplementation. The idea is from the article; the code is written from scratch.

**Intended use:** analysis of binaries that you either own or have explicit authorization to study — your own software, training labs, CTFs, authorized penetration tests, defensive research, education. Neither the author of the original idea nor the author of this implementation accepts responsibility for misuse.
