# Release binaries

Pre-built executables of `rop_scanner` for four platforms. These are the **CLI** binaries only — for the optional Qt GUI you still have to build from source (see [`../README.md`](../README.md#9-the-qt6-gui)).

| File | OS / Arch | Format | Built on | Compiler |
|---|---|---|---|---|
| [`rop_scanner-linux-x64`](rop_scanner-linux-x64) | Linux x86_64 | ELF, dynamically linked, stripped | Ubuntu 22.04 | GCC 11.4 |
| [`rop_scanner-macos-arm64`](rop_scanner-macos-arm64) | macOS Apple Silicon | Mach-O arm64 | macOS 15+ | Apple Clang 21 |
| [`rop_scanner-windows-x64.exe`](rop_scanner-windows-x64.exe) | Windows 64-bit | PE32+ x86-64, console | Windows 11 + VS 2022 | MSVC 19.43 |
| [`rop_scanner-windows-x86.exe`](rop_scanner-windows-x86.exe) | Windows 32-bit | PE32 i386, console | Windows 11 + VS 2022 | MSVC 19.43 (amd64_x86 cross) |

[`SHA256SUMS.txt`](SHA256SUMS.txt) — verify with `shasum -a 256 -c SHA256SUMS.txt` (macOS / Linux) or `certutil -hashfile <file> SHA256` (Windows).

## Runtime requirements

- **Linux**: glibc 2.31+ (Ubuntu 20.04+, RHEL 9+, anything reasonably recent). The binary is dynamically linked against the system libc / libstdc++.
- **macOS**: macOS 12+ on Apple Silicon (M-series). For Intel macs you'll need to build from source — `brew install cmake && ./mac_build.sh`.
- **Windows**: any 64-bit or 32-bit Windows from Windows 7 onward should be fine. No Visual C++ runtime DLLs needed.

## Note on PE file architecture

`rop_scanner` only **reads** the bytes of the PE file you pass it; the host architecture you run it on has nothing to do with the target architecture of the PE you're scanning. Use any of these four binaries on any of those four host OSes to analyze a Windows x86 or x86_64 PE file. ARM64 / IA64 / RISC-V PE files are explicitly rejected — Zydis doesn't know how to decode them.

## Want the GUI?

The Qt6 GUI front-end requires Qt to be installed on the host. There are no pre-built GUI bundles in this folder — instead see the [main README](../README.md#9-the-qt6-gui) for one-line build commands per platform.

## Quick sanity check after download

```sh
# Linux / macOS
./rop_scanner-linux-x64 --help | head -3
./rop_scanner-macos-arm64 --help | head -3

# Windows
rop_scanner-windows-x64.exe --help
rop_scanner-windows-x86.exe --help
```

Expected first line: `rop_scanner — ROP/JOP/syscall/pivot gadget hunter for Windows PE files`.
