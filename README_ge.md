<p align="right">
  <a href="README.md">🇬🇧 English</a> ·
  <a href="README_ru.md">🇷🇺 Русский</a> ·
  <a href="README_ua.md">🇺🇦 Українська</a> ·
  <a href="README_ch.md">🇨🇳 中文</a> ·
  <b>🇩🇪 Deutsch</b> ·
  <a href="README_fr.md">🇫🇷 Français</a>
</p>

<p align="center">
  <img src="docs/img/banner.svg" alt="rop_scanner — offline PE → Zydis → ROP / JOP / syscall / pivot gadgets" width="100%"/>
</p>

# rop_scanner

**Plattformübergreifender (Windows / Linux / macOS) Offline-Scanner für ROP-, JOP-, Syscall- und Stack-Pivot-Gadgets in Windows-PE-Dateien.** Er parst DLL- / EXE- / SYS- / CPL- / OCX- / DRV- / EFI-Dateien direkt von der Festplatte, ohne sie jemals in einen Prozess-Adressraum zu laden, dekodiert jedes Byte mit dem Disassembler [Zydis](https://github.com/zyantific/zydis) und gibt ranghöhe-sortierte Gadgets in einem von vier Formaten aus: `text`, `json`, `ropper` oder ein direkt einsetzbares Python-Dictionary für `pwntools`.

> Idee und Original-Artikel von **0x12 Dark Development** ([@Salsa12__](https://twitter.com/Salsa12__)),
> [„Hunting ROP Gadgets in Windows DLLs"](https://medium.com/@s12deff/hunting-rop-gadgets-in-windows-dlls-3184e4eeba62).
> Dieses Projekt ist eine eigenständige C++17-Implementierung und Erweiterung dieser Ideen.

---

## Inhaltsverzeichnis

1. [Warum das hier existiert](#1-warum-das-hier-existiert)
2. [Was drinsteckt und wie es funktioniert](#2-was-drinsteckt-und-wie-es-funktioniert)
3. [Anatomie eines Gadgets](#3-anatomie-eines-gadgets)
4. [Klassifikation: Kategorie × Semantik](#4-klassifikation-kategorie--semantik)
5. [Bauen](#5-bauen)
6. [Schnellstart](#6-schnellstart)
7. [Vollständige CLI-Referenz](#7-vollständige-cli-referenz)
8. [Anwendungsszenarien](#8-anwendungsszenarien)
9. [Die Qt6-GUI](#9-die-qt6-gui)
10. [Einsatz in der Exploit-Entwicklung](#10-einsatz-in-der-exploit-entwicklung)
11. [Vergleich mit Alternativen](#11-vergleich-mit-alternativen)
12. [Weitere Einsatzgebiete](#12-weitere-einsatzgebiete)
13. [Einschränkungen](#13-einschränkungen)
14. [Credits und rechtlicher Hinweis](#14-credits-und-rechtlicher-hinweis)

---

## 1. Warum das hier existiert

Jeder moderne User-Mode-Exploit unter x86_64-Windows stößt an dieselbe Mauer: Sobald man RIP unter Kontrolle hat, muss man immer noch **Code-Ausführung** erreichen, ohne DEP / CFG / CET zu reißen. Die klassische Antwort ist **Return-Oriented Programming** — kurze Fragmente bereits geladenen Codes (`pop rcx ; ret`, `xchg rax, rsp ; ret`, `syscall`, …) so aneinanderreihen, dass sie, über Stack-Returns aktiviert, die eigentliche Arbeit für dich erledigen — meist bis zu `VirtualProtect` oder einem direkten `syscall NtProtectVirtualMemory`, um die Shellcode-Seite RWX zu setzen.

<p align="center">
  <img src="docs/img/exploit-chain.svg" alt="Where rop_scanner fits in an exploit chain" width="100%"/>
</p>

Das funktioniert nur, wenn man einen **brauchbaren Gadget-Katalog** hat — konkrete RVAs innerhalb von Modulen, die garantiert im Opferprozess gemappt sind. Und genau da fängt der Schmerz an:

- **MSVC produziert keine „bequemen" Gadgets** out of the box. `pop rcx ; pop rdx ; pop r8 ; pop r9 ; ret` (die Windows-x64-Aufrufkonvention) existiert fast nie als natürlicher Epilog. Es muss als **Nebeneffekt eines Instruktionsversatzes** entdeckt werden — also indem der Decoder an einer ungeradzahligen Byte-Grenze startet.
- **CFG, XFG, CET Shadow Stack** killen einen Teil der Kandidaten. Du musst wissen, welche RVAs gültige Indirect-Call-Ziele sind (`IMAGE_LOAD_CONFIG_DIRECTORY.GuardCFFunctionTable`), um entweder auf sie zu zielen oder sie zu vermeiden.
- **Bad Bytes** (`\x00`, `\x0a`, `\x0d`, Protokoll-Terminatoren, Validierungs-Marker) räumen die Hälfte der Ergebnisse jedes „generischen" Scanners ab.
- **Modulübergreifende Suche.** Die wirklich wertvollen Gadgets sind die, die **in jedem standardmäßig geladenen Modul** existieren. Jedes `pop rcx ; ret`, das an eine spezifische DLL gebunden ist, geht kaputt, sobald das Opfer ein anderes Windows-Build oder einen anderen Modulsatz lädt.

`rop_scanner` packt diese vier Punkte direkt an: volles Zydis-Decoding, CFG-/`.pdata`-/EAT-Parsing, Bad-Byte-Filterung zur Suchzeit, und ein Batch-Modus, der nach `(asm)` über Dutzende Module hinweg aggregiert. Eine `.cpp`-Datei oder das gesamte `C:\Windows\System32` — derselbe Befehl.

---

## 2. Was drinsteckt und wie es funktioniert

<p align="center">
  <img src="docs/img/pipeline.svg" alt="Pipeline: PE → pe_loader → ending finder → back-decoder → classify" width="100%"/>
</p>

Fünf Stufen, jede in einer eigenen `.cpp`:

| Stufe | Datei | Was sie macht |
|---|---|---|
| PE-Parsing | [pe_loader.cpp](src/pe_loader.cpp) + [pe_types.h](src/pe_types.h) | MZ → PE\\0\\0 → Sektionen → `IMAGE_DIRECTORY_ENTRY_EXPORT`, `_EXCEPTION` (.pdata RUNTIME_FUNCTION), `_LOAD_CONFIG` (CFG GuardCF-Tabelle) |
| Suche nach Terminatoren | [scanner.cpp](src/scanner.cpp) | Für jedes Byte einer Sektion fragt Zydis nach einer Instruktion an diesem Offset. Ist das Ergebnis ein akzeptabler Terminator (`ret`, `ret imm16`, `syscall`, `sysenter`, `jmp reg`, `call reg`), wird er notiert |
| Rückwärts-Decoding | [scanner.cpp](src/scanner.cpp) | Für jeden Terminator werden alle Startoffsets von `endPos - maxBytes` bis `endPos` ausprobiert. Vorwärts dekodieren mit Zydis; die Kette ist gültig genau dann, wenn sie innerhalb von `--max-insn` Instruktionen **exakt** auf dem Terminator endet und im Body keine Control-Flow-Instruktion enthält |
| Klassifikation | [gadget.cpp](src/gadget.cpp) | Kategorie (nach Terminator) + Semantik (nach Body-Effekt) + Score (0–100) mit Boosts für die Windows-x64-ABI |
| Annotation | [symbol_resolver.cpp](src/symbol_resolver.cpp) | Nächstes Export-Symbol aus der EAT, umschließende Funktion aus `.pdata`, optional PDB via `dbghelp` (nur Windows), CFG-valid-Flag |

Leitprinzipien:

- **Vollständiger Decoder.** Die erste Version hatte einen handgeschriebenen ~250-Zeilen-Mini-Decoder, der nur `pop reg`, `ret`, ein paar `mov`-Varianten und `add rsp` kannte. Zydis 4.1 deckt das gesamte x86 / x86_64 ab, inklusive VEX / EVEX, nicht-trivialer `mov [mem], reg`, `lea`, `cmov*`, `pushfq` / `popfq` und beliebige Memory-Operanden. Das ergibt eine echte `write-mem` / `read-mem`-Suche, die der ersten Version (und vielen „kleinen" Scannern) schlicht fehlt — und die Klassifikation bleibt günstig, weil sie direkt Zydis' strukturierte Operanden durchläuft.
- **Keine Seiteneffekte.** Der Parser ruft niemals `LoadLibrary` auf, übergibt nie Bytes an einen JIT oder irgendetwas anderes mit Seiteneffekten. Du kannst bekannt bösartige Samples gefahrlos scannen.
- **Ein Artefakt.** Eine eigenständige ausführbare Datei ohne Laufzeitabhängigkeiten außer libc / libstdc++. Unter Windows kommt eine *optionale* Abhängigkeit von `dbghelp.dll` dazu (die in jeder Windows-Installation enthalten ist).

---

## 3. Anatomie eines Gadgets

<p align="center">
  <img src="docs/img/anatomy.svg" alt="Anatomy of a gadget: bytes → instructions → terminator" width="100%"/>
</p>

In einem Bild: Die rohen sieben Bytes `59 5A 41 58 41 59 C3` werden von Zydis in fünf Instruktionen dekodiert — `pop rcx`, `pop rdx`, `pop r8` (REX.B + pop), `pop r9` (REX.B + pop), `ret`. Terminator: `C3` (`ret`). Body: vier unbedingte Pops, die genau das tun, was die Windows-x64-Aufrufkonvention braucht — die ersten vier Argument-Register (`rcx / rdx / r8 / r9`) von dem laden, was am Stack liegt.

`rop_scanner` findet so ein Gadget in jeder ausreichend großen PE auf einer Nicht-Standard-Byte-Grenze. Mit +10 Score pro `pop rXX` aus der x64-ABI und +15 für `xchg rax, rsp` / `leave` erreicht diese Kette die volle **100/100**.

---

## 4. Klassifikation: Kategorie × Semantik

<p align="center">
  <img src="docs/img/taxonomy.svg" alt="Two-axis taxonomy: category by terminator, semantic by body effect" width="100%"/>
</p>

Jedes Gadget bekommt **zwei unabhängige Tags**, beide stehen als Substring-Filter über `--filter` zur Verfügung:

- **Category** beschreibt, **wie** das Gadget endet. Diese Achse bestimmt die Rolle in der Kette: `rop` wird per Stack eingespielt, `jop` per registerindirektem jmp/call, `syscall` ist der Sprung in den Kernel, `pivot` wechselt RSP.
- **Semantic** beschreibt, **was** das Gadget zwischen Start und Terminator tut: Konstante laden, Register kopieren, Speicher schreiben/lesen, Arithmetik, Stack umschalten.

Nützlichkeit: `--filter "write-mem"` findet **jedes** Write-What-Where-Primitiv (`mov [rax], rdx ; ret`, `mov [rcx+0x10], r8 ; ret`, …), unabhängig davon, wie es endet. `--filter "load-const"` findet alle „Argument-Lader".

---

## 5. Bauen

> Alle Builds brauchen einen **C++17**-Compiler und **CMake ≥ 3.16**. Zydis wird beim ersten Configure automatisch via `FetchContent` geholt.

### Windows  (MSVC / Visual Studio 2019+)

Aus einer *Developer Command Prompt for VS 2022* (oder einer gewöhnlichen cmd nach `call vcvars64.bat`):

```cmd
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
:: -> build\bin\rop_scanner.exe
```

`dbghelp.lib` wird automatisch für den optionalen `--pdb`-PDB-Resolver gelinkt. Wenn Ninja nicht installiert ist, lasse `-G Ninja` weg, MSBuild kommt damit klar.

Erwartetes Ende der Build-Ausgabe:

```
[42/43] Building CXX object CMakeFiles/rop_scanner.dir/src/scanner.cpp.obj
[43/43] Linking CXX executable bin/rop_scanner.exe
```

### Linux  (GCC / Clang)

Auf Ubuntu 22.04 + GCC 11.4 getestet. Keine Systemabhängigkeiten außer `cmake`, einem C++-Compiler und `make`/`ninja`:

```sh
sudo apt install -y cmake g++ make            # Debian/Ubuntu
# oder
sudo dnf install -y cmake gcc-c++ make        # Fedora/RHEL

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
# -> build/bin/rop_scanner
```

GCC < 9 hat `<filesystem>` in `libstdc++fs` abgespalten — CMake linkt es automatisch dazu. Bei Clang 10+ und GCC 9+ braucht es nichts Weiteres.

### macOS  (Apple Clang)

Du brauchst nur die Xcode Command Line Tools (`xcode-select --install`) und irgendein CMake (Homebrew oder offiziell):

```sh
brew install cmake          # einmalig
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
# -> build/bin/rop_scanner
```

Apple Silicon (arm64) und Intel (x86_64) funktionieren beide — `rop_scanner` **liest** PE-Bytes nur, führt sie nie aus, sodass die Host-Architektur irrelevant ist.

> Auf Linux / macOS wird `--pdb` zwar akzeptiert, hat aber keine Wirkung (kein `dbghelp`). EAT + `.pdata`-Resolver funktionieren weiterhin und liefern bei öffentlichen Windows-DLLs fast genau das, was ein stripped Public-PDB liefern würde.

### Bit-für-Bit-Konsistenz über Plattformen

Dieselbe x64-`ntdll.dll` produziert auf allen drei Plattformen **identische** Ausgaben:

| Plattform | Compiler | `exports` | `.pdata` | `cfg` | erster Treffer für `pop rsi ; pop rdi ; ret` |
|---|---|---|---|---|---|
| Windows 11 x64 | MSVC 19.43 | 2516 | 5679 | 2197 | `0x000026B9` — `RtlGetUserInfoHeap+0xB9` |
| macOS arm64 | AppleClang 21 | 2516 | 5679 | 2197 | `0x000026B9` — `RtlGetUserInfoHeap+0xB9` |
| Linux x64  | GCC 11.4   | 2516 | 5679 | 2197 | `0x000026B9` — `RtlGetUserInfoHeap+0xB9` |

`static_assert` auf jede PE-Struktur-Größe in [pe_types.h](src/pe_types.h) garantiert das.

---

## 6. Schnellstart

Die erste Minute:

```sh
# 1. Plain-Scan von ntdll.dll
./build/bin/rop_scanner /path/to/ntdll.dll | head -40
```

Erwartete erste Seite (für die x64-ntdll.dll von Windows 11):

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

Die erste Zeile ist der Modul-Steckbrief; danach folgen Gadgets nach absteigendem Score. Jedes zeigt: `[category/semantic]`, Score, Sektion, RVA und Dateioffset, EAT-Symbol (`RtlGetUserInfoHeap+0xB9`), umschließende Funktion aus `.pdata`, rohe Bytes, dekodierte Mnemonics.

---

## 7. Vollständige CLI-Referenz

```text
Usage:
  rop_scanner <pe-file> [pe-file ...] [options]
  rop_scanner --dir <path> [--recursive] [options]
```

### Scannen

| Flag | Default | Bedeutung |
|---|---|---|
| `--max-bytes N` | 10 | Wie viele Bytes vor dem Terminator als Startpunkt ausprobiert werden. Kleiner → schneller, größer → mehr „Zwischen-Instruktions"-Gadgets an unkonventionellen Grenzen. |
| `--max-insn N` | 5 | Maximale Instruktionen pro Gadget inklusive Terminator. Praktisch nützliche Ketten sind selten länger als 6. |
| `--min-score N` | 0 | Alles unter dem Schwellwert verwerfen. Für echte Exploit-Arbeit nehme ich 60–70. |
| `--filter TEXT` | — | Case-insensitive Substring-Suche über `asm + section + category + semantic + symbol + function`. Eines der mächtigsten Flags: nach Disasm (`"pop rcx ; pop rdx"`), nach Semantik (`"write-mem"`), nach Symbol (`"Rtl"`), nach Kategorie (`"pivot"`). |
| `--badbytes B,…` | — | Komma-getrennte Liste verbotener Bytes: `00,0a,0d,20`. Gadgets, deren Rohbytes **irgendeines** dieser Bytes enthalten, fliegen raus. Genau der Filter, den man bei String-basierten Schwachstellen braucht (`strcpy`, `sprintf`, `gets`, …). |
| `--limit N` | 0 (alle) | Nach dem Sortieren nur die Top-N behalten. |

### CFG (Control Flow Guard)

| Flag | Bedeutung |
|---|---|
| `--only-cfg`    | Nur RVAs behalten, die in `IMAGE_LOAD_CONFIG_DIRECTORY.GuardCFFunctionTable` aufgeführt sind. Wenn dein RIP-Hijack über einen indirekten Call mit CFG-Check läuft, sind das die einzigen legalen Gadgets. |
| `--exclude-cfg` | Das Gegenteil — CFG-valid-Ziele verwerfen. Nützlich, wenn du Gadgets über `ret` aneinanderreihst (CFG prüft Ret-Ziele nicht) und Kollisionen minimieren willst. |

### Symbole

| Flag | Bedeutung |
|---|---|
| `--no-symbols` | EAT- / `.pdata`-Annotation überspringen. Im Batch deutlich schneller. |
| `--pdb`        | `dbghelp.dll` für PDB-Resolution nutzen. Respektiert `_NT_SYMBOL_PATH`. Unter Linux / macOS still wirkungslos. |

### Batch-Modus

| Flag | Bedeutung |
|---|---|
| `--dir PATH`  | Jede PE unterhalb des Verzeichnisses scannen. Erkannte Erweiterungen: `dll exe sys cpl ocx drv efi`. |
| `--recursive` | In Unterverzeichnisse rekursieren. |

Im Batch-Modus werden Gadgets nach `(asm)` über **verschiedene Module hinweg** dedupliziert und nach `module_count desc, score desc` sortiert. Oben in der Liste stehen die „allgegenwärtigen" Gadgets.

### Ausgabeformat

| `--format …` | Ausgabe |
|---|---|
| `text` (Default) | Menschenlesbar |
| `json` | Vollständig strukturiertes JSON. Im Batch-Modus mit Liste der enthaltenden Module. |
| `ropper` | `0x180012345: pop rcx; ret;` — drop-in für `ropper` / `ROPgadget`-Konsumenten |
| `pwntools` | Gültiges Python-Dictionary mit image_base, RVA, asm und Symbol — `cat output.py >> exploit.py` |

### Sonstiges

| Flag | Bedeutung |
|---|---|
| `--help`, `-h`, `/?` | Hilfe anzeigen |

---

## 8. Anwendungsszenarien

### Fall 1.  Win-x64-Calling-Convention-Helfer

Ziel — den klassischen Lader für die ersten vier WinAPI-Argument-Register finden:

```sh
rop_scanner ntdll.dll \
  --filter "pop rcx ; pop rdx ; pop r8" \
  --max-insn 6 \
  --limit 10
```

Wenn das Gadget nicht sauber existiert (in ntdll ist es tatsächlich selten), findet der Scanner versetzte Äquivalente von selbst:

```text
[rop/load-const] score=92 section=.text rva=0x001255F4
  symbol: tan+0x3F4
  bytes: 5C C1 F2 0F 59 C2 F2 0F
  asm  : pop rsp ; shl edx, 0x0F ; pop rcx ; ret 0xFF2
```

Das sind Bytes im Body von `tan()` (der Mathematik-Funktion aus libm), die an einer Nicht-Standard-Instruktionsgrenze starten.

### Fall 2.  Stack-Pivot bei unausgerichtetem Stack

Wird RIP an einem Punkt gekapert, an dem der Stack unvorhersehbar ausgerichtet ist, brauchst du einen **Pivot** — meist `xchg rax, rsp ; ret` oder `add rsp, 0x__ ; ret`:

```sh
rop_scanner ntdll.dll --filter "pivot" --min-score 95 --limit 5
```

Liefert direkt brauchbare Kandidaten mit exakten RVAs und `.pdata`-Funktionsnamen.

### Fall 3.  Write-What-Where

Die Suche ist **semantisch**, nicht textuell:

```sh
rop_scanner ntdll.dll --filter "write-mem" --badbytes 00 --min-score 70
```

Ausgabe — alle `mov [reg+disp], reg ; ret`-Äquivalente ohne NULL-Bytes.

### Fall 4.  Bad-Byte-Aware  (komplette Kette unter `strcpy`)

```sh
rop_scanner ntdll.dll \
  --filter "pop rcx ; ret" \
  --badbytes 00,0a,0d,20,3b \
  --format pwntools > rop_chunk.py
```

`--badbytes` schneidet alles mit NULL (String-Terminator), `\n`/`\r` (HTTP-Header), Space und `;` weg. `--format pwntools` liefert direkt ein einlesefertiges Dictionary.

### Fall 5.  Modulübergreifende Suche nach garantiert geladenen Gadgets

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

Findet alle 2-Byte-`0F 05` und komplexere Strukturen, die mit `syscall` enden. Sortiert nach Anzahl Module, in denen das Gadget existiert. Die obersten Gadgets sind die robusteste Basis für eine Kette: Sie überleben Windows-Rebuilds und Versionswechsel.

### Fall 6.  CFG-aware Indirect-Call-Hijack

```sh
rop_scanner ntdll.dll --only-cfg --filter "jmp r" --limit 20
```

Liefert `jmp reg`-Gadgets, auf die CFG springen lässt — also legale Landeplätze für einen Indirect-Call-Hijack auf CET-gehärteten Windows-10/11-Systemen.

### Fall 7.  Symbol-Annotation + JSON für Pipelines

```sh
set _NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols
rop_scanner ntdll.dll \
  --pdb \
  --min-score 70 \
  --format json > ntdll_gadgets.json
```

Strukturiertes Verzeichnis mit PDB-Symbolen — fertig für IDE / IDA-Skript / eigenen Gadget-Planer.

### Fall 8.  Treiber scannen

```sh
rop_scanner C:\Windows\System32\drivers\hidusb.sys --filter "syscall" --limit 5
```

Treiber werden wie reguläre PE32+-Dateien geparst — ohne Anpassungen für Kernel-Side-Gadget-Hunting verwendbar.

---

## 9. Die Qt6-GUI

Wer sich die Flags nicht merken will, bekommt eine plattformübergreifende Qt6-GUI (mit Qt5-Fallback), die aus demselben Quellbaum gebaut wird und einfach die CLI mit den richtigen Argumenten startet.

<p align="center">
  <img src="docs/img/gui-mockup.svg" alt="rop_scanner Qt GUI" width="100%"/>
</p>

**Was sie kann:**

- Datei- oder Verzeichnisauswahl per `Browse…` oder **Drag-and-Drop** direkt ins Fenster.
- Jedes CLI-Flag als Formularfeld (`--max-bytes`, `--max-insn`, `--min-score`, `--filter`, `--badbytes`, `--limit`, `--only-cfg`/`--exclude-cfg`, `--no-symbols`, `--pdb`, `--recursive`).
- Auto-Erkennung des `rop_scanner`-Binarys (neben der GUI, in `../bin`, in `../../build/bin`, im `Resources/`-Ordner eines macOS-Bundles).
- Streaming-Ausgabe in ein integriertes dunkles Terminal.
- **Copy cmdline** — baut den exakten Shell-Befehl, der den Lauf vom Terminal aus reproduziert. Praktisch für Exploit-Notes oder zum Weitergeben an Kollegen.
- **Save output…** — speichert als `.txt`, `.json` oder `.py` (nach `--format`).
- `QSettings`-Persistenz aller Felder über Sessions hinweg.
- Sauberes Abbrechen eines hängenden Scans über `Cancel` (sendet `SIGKILL`).

**Wo der Code liegt:** [gui/](gui/) — eigenes CMake-Target. Drei Dateien: [`MainWindow.cpp`](gui/src/MainWindow.cpp) (Formular + Slots), [`ScannerRunner.cpp`](gui/src/ScannerRunner.cpp) (dünner Wrapper um `QProcess`), [`main.cpp`](gui/src/main.cpp) (Entry-Point). Linkt gegen `Qt6::Widgets` oder `Qt5::Widgets`, je nachdem, was zuerst gefunden wird.

### GUI bauen

Die GUI ist ein **optionales** Add-on zum Hauptbuild. Dieselben Build-Skripte, ein zusätzliches Flag.

#### macOS

```sh
brew install qt           # einmalig
GUI=1 ./mac_build.sh
open build/bin/rop_scanner_gui.app
```

#### Linux  (Debian / Ubuntu)

```sh
sudo apt install qt6-base-dev libvulkan-dev
GUI=1 ./linux_build.sh
./build/bin/rop_scanner_gui
```

(Auf Fedora/RHEL ersetze `qt6-base-dev libvulkan-dev` durch `qt6-qtbase-devel vulkan-headers`).

#### Windows

Qt6 auf einem dieser Wege installieren:

1. Offizieller Installer: <https://qt.io/download-open-source>
2. `vcpkg install qt6-base`
3. MSYS2: `pacman -S mingw-w64-x86_64-qt6-base`

Dann CMake per Umgebungsvariable auf die Installation zeigen lassen und starten:

```cmd
set QT_PREFIX=C:\Qt\6.6.0\msvc2019_64
windows_build.bat build gui
build\bin\rop_scanner_gui.exe
```

### Was du im Fenster siehst

Oben — Moduswahl (Einzeldatei / Verzeichnis-Batch), Zielpfad, Recursive-Checkbox. Darunter die **Scanning**-Gruppe mit Zahlfeldern und Suchfilter, **CFG / Symbols** mit der CFG-Filter-Radiogruppe und den `--no-symbols`-/`--pdb`-Checkboxen. Dann das Format-Dropdown, `Copy cmdline`- / `Save output…`-Buttons, das `rop_scanner`-Binary-Pfadfeld mit Auto-Erkennung und der große `▶ Run scan`-Button. Unten — eine Statuszeile und eine dunkle Konsole, in die stdout (weiß) und stderr (gelb) live gestreamt werden.

---

## 10. Einsatz in der Exploit-Entwicklung

Typischer Workflow:

1. **Zielumgebung festnageln** — welches Windows-Build, welche Module sind garantiert geladen, welche Mitigationen (CFG / XFG / CET / Shadow Stack).
2. **Snapshots dieser Module** in Dateien ziehen (entweder aus einer sauberen Installation oder aus deiner VM).
3. **`rop_scanner` im Batch-Modus** auf diesen Dateien laufen lassen, mit `--no-symbols` für Tempo und `--format json` für die Pipeline. Du bekommst einen Katalog mit ~Zehntausenden Gadgets.
4. **Eingrenzen** auf die konkrete Aufgabe:
   - Write-Primitive → `--filter "write-mem"`
   - Kontrolle über `rcx/rdx/r8/r9` → `--filter "load-const"` + RVA-Prüfung
   - Pivot → `--filter "pivot" --min-score 95`
   - Syscall → `--filter "syscall"`
5. **`--badbytes` setzen**, passend zum Eingabe-String-Format der Schwachstelle.
6. **Geht der Exploit über einen indirekten Call** — `--only-cfg` dazu.
7. **Kette zusammensetzen.** `--format pwntools` spart hier eine halbe Stunde.

Das funktioniert gleich für User-Mode (Browser, Parser, RDP-Client) und Kernel-Mode (Tabellenüberschreibung, ROP im Driver-Kontext).

### Nicht nur Windows-Ziele

Eine PE-Datei ist nur eine Datei; der Decoder Zydis ist nur ein x86-/x86_64-Decoder. Also scannt `rop_scanner` problemlos:

- **MinGW-gebaute PEs auf Linux** — für Cross-Compile-Exploits und Tests.
- **Windows-Malware** auf einer Linux-/macOS-RE-Box — ohne jedes Risiko, dass etwas geladen wird.
- **UEFI-Firmware** (Endung `.efi`) — auch eine PE.
- **Alte Treiber**, für die es keine PDBs gibt.

---

## 11. Vergleich mit Alternativen

| Tool | x86/x64 | PE | ELF | Mach-O | Semantik | Cross-Module | CFG-aware | PDB | Plattformübergr. Binary |
|---|---|---|---|---|---|---|---|---|---|
| **rop_scanner** | ✅ | ✅ | — | — | ✅ | ✅ | ✅ | ✅ (Win) | **✅ Win / Linux / mac** |
| ROPgadget (Python) | ✅ | ✅ | ✅ | ✅ | — | — | — | — | ✅ |
| ropper (Python) | ✅ | ✅ | ✅ | ✅ | — | — | — | — | ✅ |
| rp++ | ✅ | ✅ | ✅ | ✅ | — | — | — | — | ✅ |
| angrop | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | — | ✅ (langsam) |

`rop_scanner` gewinnt da, wo das Problem *Windows-spezifisch* ist: Semantik, CFG, `.pdata`, modulübergreifende Suche über `System32`. Und es baut und läuft genau da, wo man Exploits am liebsten schreibt — auf der eigenen Workstation.

---

## 12. Weitere Einsatzgebiete

- **Malware-Analyse.** Alle potenziellen ROP-Ketten aus einer verdächtigen DLL/EXE ziehen, ohne sie laufen zu lassen. Gadget-Tabellen vor und nach dem vermuteten Unpacking vergleichen — wenn sich die Body-Bytes geändert haben, ist der Unpacker gelaufen.
- **Threat Hunting / Detection Engineering.** Snapshot deines sauberen Windows-Hosts (Batch-Scan über `System32`), dann regelmäßig wiederholen. Differenzen zwischen Läufen = Bibliotheksveränderungen = Grund zu schauen, wer da Hand angelegt hat. (Microsoft patcht ntdll vorhersehbar und der Gadget-Bestand verschiebt sich entsprechend; alles, was nicht zum Win-Update passt, ist verdächtig.)
- **Reverse Engineering.** Ein Gadget-Katalog ist eine Karte der „Hotspots" einer Funktion: wo die kurzen Epilogen sitzen, wo Syscalls leben, wo die Pivots sind. Macht das Lesen von Disasm leichter.
- **CTF.** PE-Challenges in der Pwn-Kategorie sind ein Lehrbuchfall. `--format pwntools` spart Stunden.
- **Lehre.** Eine gute Visualisierung, wie ROP überhaupt funktioniert: Der Studierende sieht rohe Bytes, Zydis-dekodierte Mnemonics, Klassifikation, Score. Jede Stufe ist zwei Bildschirme Code.
- **Compiler-Hardening-Audit.** Du willst wissen, wie sehr dein eigener Build mit `cl.exe /GS /guard:cf` Angreifern Gadgets weggenommen hat? Vergleiche den `pivot`-Zähler unter `--only-cfg` vor und nach dem Umlegen der Flags.

---

## 13. Einschränkungen

- **Nur x86 und x86_64.** PE-Dateien für ARM64 / IA64 / RISC-V werden explizit abgelehnt — Zydis kennt sie nicht.
- **`.pdata`-Parsing nur x64** (`RUNTIME_FUNCTION`). Auf x86 lebt SEH woanders; wir nutzen das nicht.
- **CFG-Parsing.** Wir lesen das Standard-`IMAGE_LOAD_CONFIG_DIRECTORY` bis zum Feld `GuardFlags`. Sollte Microsoft das Struct-Layout je ändern, müssen wir nachziehen.
- **Kein CET-/XFG-Bewusstsein** auf semantischer Ebene (XFG-Type-Hashes werden nicht berücksichtigt). Für v0.7 vorgesehen.
- **Single-Thread.** Batch-Scan über `C:\Windows\System32` (~1500 PEs) dauert ein paar Minuten. Parallelisierung wären etwa zehn Zeilen via `std::async`; steht im Backlog.
- **PDB nur unter Windows** (via `dbghelp`). Auf Linux / macOS könnte man `llvm-pdbutil` einbauen, ist aber nicht geschehen — EAT reicht für öffentliche Module meist aus.

---

## 14. Credits und rechtlicher Hinweis

- Ursprüngliche Idee und Ansatz: **0x12 Dark Development** ([@Salsa12__](https://twitter.com/Salsa12__))
  — der Artikel [„Hunting ROP Gadgets in Windows DLLs"](https://medium.com/@s12deff/hunting-rop-gadgets-in-windows-dlls-3184e4eeba62) auf Medium.
- Decoder: **[Zydis](https://github.com/zyantific/zydis)** von Florian Bernd und Team — wird beim ersten CMake-Configure via `FetchContent` geholt.
- Dieses Projekt ist eine eigenständige C++17-Reimplementierung. Die Idee stammt aus dem Artikel; der Code ist von Grund auf neu geschrieben.

**Bestimmungsgemäße Nutzung:** Analyse von Binaries, die du entweder besitzt oder ausdrücklich autorisiert bist zu untersuchen — eigene Software, Trainings-Labs, CTFs, autorisierte Pentests, defensive Forschung, Lehre. Weder der Autor der ursprünglichen Idee noch der Autor dieser Implementierung übernimmt Verantwortung für Missbrauch.
