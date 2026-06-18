# Release binaries

Pre-built binaries of `rop_scanner` organized by build type and platform.

```
releases/
├── console/                              # CLI binaries, no Qt needed
│   ├── console_linux_x64/
│   ├── console_apple-silicon/
│   ├── console_windows_x64/
│   └── console_windows_32/
└── gui/                                  # Qt-based GUI, Qt runtime bundled or required
    ├── gui_linux_x64/
    ├── gui_apple-silicon/
    ├── gui_windows_x64/
    └── gui_windows_32/
```

[`SHA256SUMS.txt`](SHA256SUMS.txt) — verify with `shasum -a 256 -c SHA256SUMS.txt` (Linux / macOS) or `certutil -hashfile <file> SHA256` (Windows).

## Console (CLI)

| Path | OS / Arch | Format | Built with |
|---|---|---|---|
| [`console/console_linux_x64/rop_scanner`](console/console_linux_x64/rop_scanner) | Linux x86_64 | ELF, dynamically linked, stripped | GCC 11.4 (Ubuntu 22.04) |
| [`console/console_apple-silicon/rop_scanner`](console/console_apple-silicon/rop_scanner) | macOS arm64 | Mach-O arm64 | Apple Clang 21 |
| [`console/console_windows_x64/rop_scanner.exe`](console/console_windows_x64/rop_scanner.exe) | Windows 64-bit | PE32+ x86-64, console subsystem | MSVC 19.43 / Ninja |
| [`console/console_windows_32/rop_scanner.exe`](console/console_windows_32/rop_scanner.exe) | Windows 32-bit | PE32 i386, console subsystem | MSVC 19.43 (amd64_x86 cross) |

**Runtime requirements:** none beyond a glibc 2.31+ for Linux (Ubuntu 20.04 / RHEL 9+) and macOS 12+ for Apple Silicon. Windows binaries don't need a VC++ runtime.

## GUI (Qt6 / Qt5)

| Path | OS / Arch | Qt | Notes |
|---|---|---|---|
| [`gui/gui_linux_x64/rop_scanner_gui`](gui/gui_linux_x64/rop_scanner_gui) | Linux x86_64 | Qt 6.2 (system) | Needs `qt6-base` runtime: `sudo apt install libqt6widgets6`. **Not portable.** |
| [`gui/gui_apple-silicon/rop_scanner_gui.app/`](gui/gui_apple-silicon/rop_scanner_gui.app) | macOS arm64 | Qt 6.11 (bundled via `macdeployqt`) | Fully self-contained — double-click to launch. |
| [`gui/gui_windows_x64/rop_scanner_gui.exe`](gui/gui_windows_x64/rop_scanner_gui.exe) | Windows 64-bit | Qt 6.7.3 (bundled via `windeployqt`) | Run from this directory; Qt DLLs ship alongside. |
| [`gui/gui_windows_32/rop_scanner_gui.exe`](gui/gui_windows_32/rop_scanner_gui.exe) | Windows 32-bit | Qt 5.15.2 (bundled via `windeployqt`) | Run from this directory; Qt DLLs ship alongside. Uses Qt5 because modern Qt6 dropped Win32 MSVC builds. |

**Why three platforms ship Qt and Linux doesn't:** on Windows `windeployqt` and on macOS `macdeployqt` produce a self-contained bundle as their standard output. Linux has no first-class equivalent shipped with Qt itself (AppImage is the usual answer but is a separate tool); for Linux desktops it's idiomatic to depend on the distro's `qt6-base` package, which is one `apt`/`dnf` away.

## Note on target PE architecture

`rop_scanner` only **reads** the bytes of the PE you give it; the host OS / arch you run it on has no relationship to the target arch of the PE you're scanning. Use any of these four host platforms to analyze a Windows x86 or x86_64 PE. ARM64 / IA64 / RISC-V PE files are rejected up front — Zydis doesn't decode them.

## Smoke check after download

```sh
# Linux
./console/console_linux_x64/rop_scanner --help | head -3

# macOS
./console/console_apple-silicon/rop_scanner --help | head -3
open ./gui/gui_apple-silicon/rop_scanner_gui.app

# Windows  (cmd.exe)
console\console_windows_x64\rop_scanner.exe --help
gui\gui_windows_x64\rop_scanner_gui.exe
```

The first line of console output for any of these should be:

```
rop_scanner — ROP/JOP/syscall/pivot gadget hunter for Windows PE files
```
