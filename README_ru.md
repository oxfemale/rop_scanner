<p align="right">
  <a href="README.md">🇬🇧 English</a> ·
  <b>🇷🇺 Русский</b> ·
  <a href="README_ua.md">🇺🇦 Українська</a> ·
  <a href="README_ch.md">🇨🇳 中文</a> ·
  <a href="README_ge.md">🇩🇪 Deutsch</a> ·
  <a href="README_fr.md">🇫🇷 Français</a>
</p>

<p align="center">
  <img src="docs/img/banner.svg" alt="rop_scanner — offline PE → Zydis → ROP / JOP / syscall / pivot gadgets" width="100%"/>
</p>

# rop_scanner

**Кросс-платформенный (Windows / Linux / macOS) автономный охотник за ROP, JOP, syscall и stack-pivot гаджетами в Windows PE-файлах.** Парсит DLL/EXE/SYS/CPL/OCX/DRV/EFI напрямую с диска, никогда не загружая их в адресное пространство процесса, декодирует все байты движком [Zydis](https://github.com/zyantific/zydis) и выдаёт ранжированные гаджеты в одном из четырёх форматов: `text`, `json`, `ropper` или готовый Python-словарь для `pwntools`.

> Идея и оригинальная статья — **0x12 Dark Development** ([@Salsa12__](https://twitter.com/Salsa12__)),
> [«Hunting ROP Gadgets in Windows DLLs»](https://medium.com/@s12deff/hunting-rop-gadgets-in-windows-dlls-3184e4eeba62).
> Этот проект — независимая C++17-реализация того же подхода и расширение его идей.

---

## Содержание

1. [Зачем это нужно](#1-зачем-это-нужно)
2. [Что внутри и как оно устроено](#2-что-внутри-и-как-оно-устроено)
3. [Анатомия гаджета](#3-анатомия-гаджета)
4. [Классификация: категория × семантика](#4-классификация-категория--семантика)
5. [Сборка](#5-сборка)
6. [Быстрый старт](#6-быстрый-старт)
7. [Полный CLI-reference](#7-полный-cli-reference)
8. [Кейсы запуска](#8-кейсы-запуска)
9. [GUI на Qt6](#9-gui-на-qt6)
10. [Применение при разработке эксплойтов](#10-применение-при-разработке-эксплойтов)
11. [Сравнение с альтернативами](#11-сравнение-с-альтернативами)
12. [Где ещё это применимо](#12-где-ещё-это-применимо)
13. [Ограничения](#13-ограничения)
14. [Кредиты и юридическое](#14-кредиты-и-юридическое)

---

## 1. Зачем это нужно

Эксплоит современного user-mode приложения на x86_64 Windows почти всегда упирается в одно: после захвата RIP надо как-то получить **исполнение кода**, не нарушив DEP/CFG/CET. Классический ответ — **Return-Oriented Programming**: собрать «программу» из коротких кусочков уже загруженного в адресное пространство кода (`pop rcx ; ret`, `xchg rax, rsp ; ret`, `syscall` и т.д.), которые при последовательной активации через стек сами выполнят нужную работу — обычно дойдут до `VirtualProtect` или прямого `syscall NtProtectVirtualMemory`, помечая страницу с шеллкодом как RWX.

<p align="center">
  <img src="docs/img/exploit-chain.svg" alt="Где rop_scanner живёт в цепочке эксплойта" width="100%"/>
</p>

Это работает, если у вас есть **каталог пригодных гаджетов** — точные RVA внутри тех модулей, которые гарантированно загружены в процесс жертвы. И вот здесь начинаются проблемы:

- **MSVC не генерирует «удобных» гаджетов** в чистом виде. `pop rcx ; pop rdx ; pop r8 ; pop r9 ; ret` (соглашение вызова x64 Windows) почти никогда не существует как штатная эпилог-последовательность. Его приходится **искать как побочный эффект сдвига инструкций**, то есть стартовать декодер на нечётной границе.
- **CFG, XFG, CET Shadow Stack** отсекают часть кандидатов. Нужно знать, какие RVA являются легитимными indirect-call таргетами (`IMAGE_LOAD_CONFIG_DIRECTORY.GuardCFFunctionTable`), чтобы либо целить ровно в них, либо наоборот их избегать.
- **Bad bytes** (`\x00`, `\x0a`, `\x0d`, маркеры терминаторов протокола, символы валидации) обнуляют половину результатов любого «обычного» сканера.
- **Кросс-модульный поиск**. По-настоящему ценные гаджеты — те, что есть **в любом загруженном по умолчанию модуле**. Любой `pop rcx ; ret`, привязанный к конкретной DLL, ломается, если у жертвы другая версия Windows или другой набор подгружаемых модулей.

`rop_scanner` решает эти четыре проблемы напрямую: полное Zydis-декодирование, парсинг CFG/`.pdata`/EAT, отказ от плохих байт на этапе фильтрации, и batch-режим с агрегацией по `(asm)` через десятки модулей. Один файл `.cpp` или весь `C:\Windows\System32` — одна команда.

---

## 2. Что внутри и как оно устроено

<p align="center">
  <img src="docs/img/pipeline.svg" alt="Pipeline: PE → pe_loader → ending finder → back-decoder → classify" width="100%"/>
</p>

Пять стадий, каждая разнесена в свой `.cpp`:

| Стадия | Файл | Что делает |
|---|---|---|
| Парсинг PE | [pe_loader.cpp](src/pe_loader.cpp) + [pe_types.h](src/pe_types.h) | MZ → PE\\0\\0 → секции → `IMAGE_DIRECTORY_ENTRY_EXPORT`, `_EXCEPTION` (.pdata RUNTIME_FUNCTION), `_LOAD_CONFIG` (CFG GuardCF table) |
| Поиск окончаний | [scanner.cpp](src/scanner.cpp) | для каждого байта секции — Zydis пробует декодировать там одну инструкцию. Если это `ret`, `ret imm16`, `syscall`, `sysenter`, `jmp reg` или `call reg` — это потенциальный конец |
| Back-декодирование | [scanner.cpp](src/scanner.cpp) | для каждого окончания пробуем все стартовые смещения от `endPos - maxBytes` до `endPos`. Декодируем вперёд. Цепочка валидна, если она ровно упирается в окончание за `≤ maxInsn` инструкций и в теле нет управляющих переходов |
| Классификация | [gadget.cpp](src/gadget.cpp) | категория (по терминатору) + семантика (по эффекту тела) + скор (0–100) с бустами под x64 Windows ABI |
| Аннотации | [symbol_resolver.cpp](src/symbol_resolver.cpp) | ближайший экспорт из EAT, охватывающая функция из `.pdata`, опционально PDB через `dbghelp` (только Windows), пометка CFG-валидный/невалидный таргет |

Опорные принципы:

- **Полный декодер.** В первой версии стоял ручной мини-декодер на ~250 строк, который понимал только `pop reg`, `ret`, несколько `mov` и `add rsp`. Zydis 4.1 покрывает весь x86/x86_64, включая VEX/EVEX, нестандартные `mov [mem], reg`, `lea`, `cmov*`, `pushfq/popfq`, и любые memory operands. Это даёт реальный `write-mem` / `read-mem` поиск, которого не было в первой версии и которого нет у многих «маленьких» сканеров.
- **Никаких side-effect-ов.** Парсер бинарника никогда не вызывает `LoadLibrary`, никогда не отдаёт байты JIT/декодеру с побочным эффектом. Можно безопасно сканировать заведомо вредоносные образцы.
- **Один входной артефакт.** Самодостаточный исполняемый файл без рантайм-зависимостей кроме libc/libstdc++. На Windows прибавляется опциональная зависимость от `dbghelp.dll` (есть в любой Windows).

---

## 3. Анатомия гаджета

<p align="center">
  <img src="docs/img/anatomy.svg" alt="Anatomy of a gadget: bytes → instructions → terminator" width="100%"/>
</p>

В одном кадре: исходные семь байт `59 5A 41 58 41 59 C3` декодируются Zydis-ом в пять инструкций — `pop rcx`, `pop rdx`, `pop r8` (REX.B+pop), `pop r9` (REX.B+pop), `ret`. Терминатор — `C3` (`ret`). Тело — четыре безусловных `pop`-а, которые делают именно то, что нужно соглашению вызова x64 Windows: загрузить регистры `rcx/rdx/r8/r9` (первые четыре аргумента WinAPI) тем, что лежит на стеке.

`rop_scanner` находит такой гаджет в любом достаточно крупном PE на нечётной границе. Бустер скора +10 за каждый `pop rXX` из x64-ABI и +15 за `xchg rax, rsp` / `leave` даёт этой цепочке итоговые **100/100**.

---

## 4. Классификация: категория × семантика

<p align="center">
  <img src="docs/img/taxonomy.svg" alt="Two-axis taxonomy: category by terminator, semantic by body effect" width="100%"/>
</p>

Каждый гаджет помечен **по двум осям независимо**, и оба тега доступны как substring-фильтр в `--filter`:

- **Category** говорит о том, **как** гаджет завершается. Эта ось определяет место в цепочке: `rop` подставляется через стек, `jop` — через регистровый jmp/call, `syscall` — выход в ядро, `pivot` — смена RSP.
- **Semantic** говорит о том, **что** гаджет делает между стартом и терминатором: грузит константу, копирует регистр, пишет/читает память, делает арифметику, переключает стек.

Полезность: `--filter "write-mem"` найдёт **все** примитивы write-what-where (`mov [rax], rdx ; ret`, `mov [rcx+0x10], r8 ; ret`, ...) безотносительно того, как именно они кончаются. А `--filter "load-const"` — все «загрузчики аргументов».

---

## 5. Сборка

> Все сборки требуют **C++17** компилятор и **CMake ≥ 3.16**. Zydis подтягивается автоматически через `FetchContent` при первом конфиге.

### Windows  (MSVC / Visual Studio 2019+)

Из *Developer Command Prompt for VS 2022* (или из обычного cmd после `call vcvars64.bat`):

```cmd
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
:: -> build\bin\rop_scanner.exe
```

При линковке автоматически подключается `dbghelp.lib` для опционального PDB-резолва через `--pdb`. Если Ninja нет — уберите `-G Ninja`, MSBuild справится сам.

Ожидаемый вывод последней стадии:

```
[42/43] Building CXX object CMakeFiles/rop_scanner.dir/src/scanner.cpp.obj
[43/43] Linking CXX executable bin/rop_scanner.exe
```

### Linux  (GCC / Clang)

Проверено на Ubuntu 22.04 + GCC 11.4 на стенде `core-jmp.org`. Никаких системных зависимостей кроме `cmake`, `gcc-c++` (или `g++`) и `make`/`ninja`:

```sh
sudo apt install -y cmake g++ make            # Debian/Ubuntu
# или
sudo dnf install -y cmake gcc-c++ make        # Fedora/RHEL

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
# -> build/bin/rop_scanner
```

GCC < 9 расщеплял `<filesystem>` в `libstdc++fs` — CMake это сам прицепит. На Clang 10+ и GCC 9+ ничего дополнительно не нужно.

### macOS  (Apple Clang)

Нужен только Xcode Command Line Tools (`xcode-select --install`) и любой CMake (Homebrew или официальный):

```sh
brew install cmake          # один раз
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
# -> build/bin/rop_scanner
```

Apple Silicon (arm64) и Intel (x86_64) оба работают — `rop_scanner` лишь **читает** байты PE-файла, никогда не исполняет их, поэтому архитектура хоста не имеет значения.

> На Linux/macOS флаг `--pdb` принимается, но игнорируется молча (нет `dbghelp`). EAT + `.pdata` резолв работают штатно и дают для публичных Windows-DLL почти то же самое, что вернул бы стрипованный публичный PDB.

### Bit-for-bit совместимость

Один и тот же `ntdll.dll` (x64) даёт **идентичные** результаты на всех трёх платформах:

| Платформа | Компилятор | `exports` | `.pdata` | `cfg` | первый хит `pop rsi ; pop rdi ; ret` |
|---|---|---|---|---|---|
| Windows 11 x64 | MSVC 19.43 | 2516 | 5679 | 2197 | `0x000026B9` — `RtlGetUserInfoHeap+0xB9` |
| macOS arm64 | AppleClang 21 | 2516 | 5679 | 2197 | `0x000026B9` — `RtlGetUserInfoHeap+0xB9` |
| Linux x64  | GCC 11.4   | 2516 | 5679 | 2197 | `0x000026B9` — `RtlGetUserInfoHeap+0xB9` |

`static_assert` на каждый размер PE-структуры в [pe_types.h](src/pe_types.h) гарантирует это.

---

## 6. Быстрый старт

Первая минута:

```sh
# 1. Базовый прогон по ntdll.dll
./build/bin/rop_scanner /path/to/ntdll.dll | head -40
```

Ожидаемая первая страница вывода (для x64 ntdll.dll Windows 11):

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

Первая строка — паспорт модуля; затем гаджеты в порядке убывания скора. У каждого: пометка `[category/semantic]`, скор, секция, RVA и file offset, символ (`RtlGetUserInfoHeap+0xB9` — это EAT), охватывающая функция из `.pdata`, сырые байты, декомпиляция.

---

## 7. Полный CLI-reference

```text
Usage:
  rop_scanner <pe-file> [pe-file ...] [options]
  rop_scanner --dir <path> [--recursive] [options]
```

### Сканирование

| Флаг | Дефолт | Смысл |
|---|---|---|
| `--max-bytes N` | 10 | Сколько байт назад от терминатора пробовать как старт. Меньше — быстрее, больше — больше «межинструкционных» гаджетов на нечётной границе. |
| `--max-insn N` | 5 | Максимум инструкций в гаджете, включая терминатор. Реально полезные цепочки редко длиннее 6. |
| `--min-score N` | 0 | Отсечь всё ниже порога. Для практической работы я ставлю 60-70. |
| `--filter TEXT` | — | Substring (case-insensitive) ищется в `asm + section + category + semantic + symbol + function`. Один из самых мощных флагов: можно искать по дизасму (`"pop rcx ; pop rdx"`), по семантике (`"write-mem"`), по символу (`"Rtl"`), по категории (`"pivot"`). |
| `--badbytes B,…` | — | Список «плохих» байт через запятую: `00,0a,0d,20`. Гаджет, содержащий **любой** из них в своих байтах, отбрасывается. Это ровно тот фильтр, который нужен для строковых уязвимостей (`strcpy`, `sprintf`, `gets` и пр.). |
| `--limit N` | 0 (все) | Оставить только топ-N после сортировки. |

### CFG (Control Flow Guard)

| Флаг | Смысл |
|---|---|
| `--only-cfg` | Только те RVA, что числятся в `IMAGE_LOAD_CONFIG_DIRECTORY.GuardCFFunctionTable`. Если ваш RIP-override идёт через indirect call с проверкой CFG — только эти гаджеты вообще можно использовать. |
| `--exclude-cfg` | Наоборот — выкинуть CFG-точки. Полезно, когда вы стрингуете гаджеты через `ret` (CFG не проверяет ret-targets), но хотите минимизировать конфликты. |

### Символы

| Флаг | Смысл |
|---|---|
| `--no-symbols` | Не делать EAT/`.pdata` аннотацию. Заметно быстрее на батче. |
| `--pdb` | Использовать `dbghelp.dll` для PDB-резолва. Уважает `_NT_SYMBOL_PATH`. На Linux/macOS принимается, но не делает ничего. |

### Batch-режим

| Флаг | Смысл |
|---|---|
| `--dir PATH` | Сканировать все PE под директорией. Распознаются расширения `dll exe sys cpl ocx drv efi`. |
| `--recursive` | Рекурсивно. |

В batch-режиме гаджеты дедуплицируются по `(asm)` через **разные модули** и ранжируются по `module_count desc, score desc`. То есть наверху списка — самые «вездесущие» гаджеты.

### Формат вывода

| `--format …` | Что получаем |
|---|---|
| `text` (по умолчанию) | Человекочитаемый |
| `json` | Вся информация в структурированном виде. В batch-режиме — со списком модулей. |
| `ropper` | `0x180012345: pop rcx; ret;` — формат, совместимый с парсерами `ropper`/`ROPgadget` |
| `pwntools` | Валидный Python-словарь с image_base, RVA, asm и symbol — `cat output.py >> exploit.py` |

### Прочее

| Флаг | Смысл |
|---|---|
| `--help`, `-h`, `/?` | Помощь |

---

## 8. Кейсы запуска

### Кейс 1.  Win x64 calling-convention helpers

Цель — найти классическую заправку первых четырёх аргументов WinAPI:

```sh
rop_scanner ntdll.dll \
  --filter "pop rcx ; pop rdx ; pop r8" \
  --max-insn 6 \
  --limit 10
```

Если гаджет не находится в чистом виде (а в ntdll он действительно редок), скан сам найдёт «межинструкционные» эквиваленты:

```text
[rop/load-const] score=92 section=.text rva=0x001255F4
  symbol: tan+0x3F4
  bytes: 5C C1 F2 0F 59 C2 F2 0F
  asm  : pop rsp ; shl edx, 0x0F ; pop rcx ; ret 0xFF2
```

Это — байты из тела `tan()` (математическая функция из libm), стартующие на нечётной границе.

### Кейс 2.  Стек-пивот для misaligned stack

Когда RIP захвачен в момент, где стек выровнен непредсказуемо, нужен **пивот** — обычно `xchg rax, rsp ; ret` или `add rsp, 0x__ ; ret`:

```sh
rop_scanner ntdll.dll --filter "pivot" --min-score 95 --limit 5
```

Получаем готовые кандидаты с точными RVA и Pdata-функциями.

### Кейс 3.  Write-what-where

Поиск **семантический**, не по тексту инструкции:

```sh
rop_scanner ntdll.dll --filter "write-mem" --badbytes 00 --min-score 70
```

Выход — все `mov [reg+disp], reg ; ret`-эквиваленты без нулей в байтах.

### Кейс 4.  Bad-byte-aware  (полная цепочка под `strcpy`)

```sh
rop_scanner ntdll.dll \
  --filter "pop rcx ; ret" \
  --badbytes 00,0a,0d,20,3b \
  --format pwntools > rop_chunk.py
```

`--badbytes` отрезает всё с нулевым байтом (строка обрежется), `\n`/`\r` (если уязвимость в HTTP-заголовке), пробелом и `;`. `--format pwntools` — готовый словарь, который можно сразу импортировать.

### Кейс 5.  Кросс-модульный поиск гарантированно загруженных гаджетов

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

Найдёт все 2-байтные `0F 05` и более сложные конструкции, заканчивающиеся `syscall`. Сортировка по числу модулей, в которых гаджет присутствует. Гаджеты из топа списка — самый надёжный фундамент цепочки: они выживут пересоберки Windows и переход на другую сборку.

### Кейс 6.  CFG-aware indirect call hijack

```sh
rop_scanner ntdll.dll --only-cfg --filter "jmp r" --limit 20
```

Найдёт `jmp reg` гаджеты, на которые CFG разрешает прыжки — то есть допустимые мишени для indirect-call хайджека на CET-defended Windows 10/11.

### Кейс 7.  Аннотация символами + сохранение в JSON для пайплайна

```sh
set _NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols
rop_scanner ntdll.dll \
  --pdb \
  --min-score 70 \
  --format json > ntdll_gadgets.json
```

Получаем структурированный каталог с PDB-символами для последующей загрузки в IDE/IDA-script/собственный планировщик.

### Кейс 8.  Сканирование драйвера

```sh
rop_scanner C:\Windows\System32\drivers\hidusb.sys --filter "syscall" --limit 5
```

Драйверы парсятся ровно как обычные PE32+ — для kernel-side гаджет-хантинга применимо без модификаций.

---

## 9. GUI на Qt6

Для тех, кто не хочет вспоминать флаги — есть кросс-платформенный GUI на Qt6 (с фолбэком на Qt5), который собирается из того же дерева и просто запускает CLI с нужными параметрами.

<p align="center">
  <img src="docs/img/gui-mockup.svg" alt="rop_scanner Qt GUI" width="100%"/>
</p>

**Что умеет:**

- Выбор файла или директории через `Browse…` или **drag-and-drop** прямо в окно.
- Все CLI-флаги представлены полями формы (`--max-bytes`, `--max-insn`, `--min-score`, `--filter`, `--badbytes`, `--limit`, `--only-cfg`/`--exclude-cfg`, `--no-symbols`, `--pdb`, `--recursive`).
- Авто-детект пути к `rop_scanner` (рядом с GUI, в `../bin`, в `../../build/bin`, в `Resources/` бандла на macOS).
- Стриминговый вывод результатов в встроенный тёмный терминал.
- **Copy cmdline** — собирает точную shell-команду, которая бы повторила запуск из терминала. Удобно для документации эксплойта или передачи коллеге.
- **Save output…** — сохранение в `.txt`, `.json` или `.py` (выбирается по `--format`).
- `QSettings`-персистентность всех полей между запусками.
- Корректное завершение зависшего сканирования по `Cancel` (отправляет `SIGKILL`).

**Где живёт код:** [gui/](gui/) — отдельный CMake-таргет. Три файла: [`MainWindow.cpp`](gui/src/MainWindow.cpp) (форма + слоты), [`ScannerRunner.cpp`](gui/src/ScannerRunner.cpp) (обёртка над `QProcess`), [`main.cpp`](gui/src/main.cpp) (вход). Линкуется к `Qt6::Widgets` или `Qt5::Widgets` — что найдётся первым.

### Сборка GUI

GUI сборка — это **опциональный** add-on к основному билду. Используются те же build-скрипты, что и для CLI, плюс флаг.

#### macOS

```sh
brew install qt           # один раз
GUI=1 ./mac_build.sh
open build/bin/rop_scanner_gui.app
```

#### Linux  (Debian / Ubuntu)

```sh
sudo apt install qt6-base-dev libvulkan-dev
GUI=1 ./linux_build.sh
./build/bin/rop_scanner_gui
```

(на Fedora/RHEL вместо `qt6-base-dev libvulkan-dev` используется `qt6-qtbase-devel vulkan-headers`).

#### Windows

Установите Qt6 одним из способов:

1. Официальный установщик: <https://qt.io/download-open-source>
2. `vcpkg install qt6-base`
3. MSYS2: `pacman -S mingw-w64-x86_64-qt6-base`

Затем укажите префикс через переменную окружения и запустите:

```cmd
set QT_PREFIX=C:\Qt\6.6.0\msvc2019_64
windows_build.bat build gui
build\bin\rop_scanner_gui.exe
```

### Что увидите в окне

Верх — выбор режима (один файл / батч директории), путь до цели, чекбокс рекурсии. Дальше **Scanning** с числовыми полями и поисковым фильтром, **CFG / Symbols** с радиогруппой CFG-фильтра и чекбоксами `--no-symbols` / `--pdb`. Под ними — выпадающий формат вывода, кнопки `Copy cmdline` / `Save output…`, поле пути к самому `rop_scanner` (с авто-детектом) и большая кнопка `▶ Run scan`. Внизу — статус-строка и тёмная консоль, куда стримится stdout (белым) и stderr (жёлтым) в реальном времени.

---

## 10. Применение при разработке эксплойтов

Типичный workflow:

1. **Зафиксировать целевую среду** — какая билд-версия Windows, какие модули гарантированно загружены, какая защита (CFG / XFG / CET / Shadow Stack).
2. **Снять образы** этих модулей в файлы (либо взять из чистой инсталляции, либо вытянуть из вашей VM).
3. **Прогнать `rop_scanner` в batch-режиме** на этих файлах с `--no-symbols` для быстроты и `--format json` для пайплайна. Получить каталог из ~десятка тысяч гаджетов.
4. **Сузить** под конкретную задачу:
   - примитив записи → `--filter "write-mem"`
   - получение управления `rcx/rdx/r8/r9` → `--filter "load-const"` + проверка по RVA
   - пивот → `--filter "pivot" --min-score 95`
   - системный вызов → `--filter "syscall"`
5. **Прогнать `--badbytes`** под формат входной строки уязвимости.
6. **Если эксплойт идёт через indirect call** — добавить `--only-cfg`.
7. **Сложить цепочку**. `--format pwntools` экономит здесь полчаса.

Это работает одинаково и для user-mode (браузер, парсер, RDP-клиент), и для kernel-mode (через подмену таблиц, ROP в driver-context).

### Не только Windows-таргеты

PE-файл — это просто файл; декодер — Zydis — это просто декодер x86/x86_64. Поэтому `rop_scanner` спокойно сканирует:

- **MinGW-собранные PE на Linux** — для cross-compile эксплойтов и тестов.
- **Windows-malware** на Linux/macOS reverse-engineering box — без риска что-либо загрузить.
- **Прошивки UEFI** (расширение `.efi`) — это тоже PE.
- **Старые драйверы**, для которых нет PDB.

---

## 11. Сравнение с альтернативами

| Инструмент | x86/x64 | PE | ELF | Mach-O | Семантика | Cross-module | CFG-aware | PDB | Кросс-платформ. бинарь |
|---|---|---|---|---|---|---|---|---|---|
| **rop_scanner** | ✅ | ✅ | — | — | ✅ | ✅ | ✅ | ✅ (Win) | **✅ Win/Linux/mac** |
| ROPgadget (Python) | ✅ | ✅ | ✅ | ✅ | — | — | — | — | ✅ |
| ropper (Python) | ✅ | ✅ | ✅ | ✅ | — | — | — | — | ✅ |
| rp++ | ✅ | ✅ | ✅ | ✅ | — | — | — | — | ✅ |
| angrop | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | — | ✅ (медленный) |

`rop_scanner` выигрывает там, где задача *Windows-специфичная*: семантика, CFG, `.pdata`, кросс-модульный поиск по `System32`. И при этом собирается и работает там, где удобнее редактору эксплойта — на его рабочей машине.

---

## 12. Где ещё это применимо

- **Malware analysis.** Извлечь все потенциальные ROP-цепочки из подозрительного DLL/EXE без его запуска. Сравнить таблицу гаджетов до и после распаковки/анпэкера — байты тела изменились → unpacker отработал.
- **Threat hunting / detection engineering.** Snapshot вашей чистой Windows-станции (батч-скан `System32`), затем повторять регулярно. Diff между прогонами = модификации в библиотеках = повод посмотреть, чьи это руки. (Microsoft патчит ntdll регулярно, и состав гаджетов меняется предсказуемо; всё, что не сходится с патчем Win Update — подозрительно.)
- **Reverse engineering.** Каталог гаджетов — это карта «горячих точек» функции: где находятся короткие эпилоги, где `syscall`, где пивоты. Облегчает чтение дизасма.
- **CTF.** PE-челленджи на pwn-категории — типичный кейс. `--format pwntools` экономит часы.
- **Обучение.** Хорошая визуализация того, как ROP вообще работает: студент видит сырые байты, их декодирование Zydis-ом, классификацию, скор. Заглянуть в код любой стадии — два экрана.
- **Аудит compiler hardening.** Хочется понять, насколько ваш собственный билд `cl.exe /GS /guard:cf` действительно лишил атакующего гаджетов? Сравните счётчик `pivot` гаджетов в `--only-cfg` режиме до и после изменения флагов.

---

## 13. Ограничения

- **Только x86 и x86_64.** PE-файлы под ARM64/IA64/RISC-V отвергаются явно — Zydis их не знает.
- **`.pdata` парсинг — только x64** (`RUNTIME_FUNCTION`). На x86 SEH живёт иначе, мы это не используем.
- **CFG-парсинг.** Берём стандартный `IMAGE_LOAD_CONFIG_DIRECTORY` до поля `GuardFlags`. Если у Microsoft появится новая структура с другими офсетами — придётся дописать.
- **Без CET/XFG-awareness** на уровне семантики (XFG type-hashes не учитываются). По плану в v0.7.
- **Single-thread.** Батч-скан `C:\Windows\System32` (~1500 PE) занимает несколько минут. Параллелизация — это десять строк через `std::async`, есть в backlog.
- **PDB только под Windows** (через `dbghelp`). На Linux/macOS можно прикрутить `llvm-pdbutil`, но пока не сделано — EAT обычно достаточно для публичных модулей.

---

## 14. Кредиты и юридическое

- Оригинальная идея и подход: **0x12 Dark Development** ([@Salsa12__](https://twitter.com/Salsa12__))
  — статья [«Hunting ROP Gadgets in Windows DLLs»](https://medium.com/@s12deff/hunting-rop-gadgets-in-windows-dlls-3184e4eeba62) на Medium.
- Декодер: **[Zydis](https://github.com/zyantific/zydis)** by Florian Bernd и команда — тянется через `FetchContent` при первой конфигурации CMake.
- Этот проект — самостоятельная реализация на C++17, идея взята из статьи; код написан с нуля.

**Назначение:** анализ бинарных файлов, которые вы либо владеете, либо имеете прямую авторизацию исследовать — собственное ПО, тренировочные стенды, CTF, авторизованные пентесты, defensive research, образовательные цели. Ни автор оригинальной идеи, ни автор этой реализации не несут ответственности за злоупотребления.
