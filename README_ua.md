<p align="right">
  <a href="README.md">🇬🇧 English</a> ·
  <a href="README_ru.md">🇷🇺 Русский</a> ·
  <b>🇺🇦 Українська</b> ·
  <a href="README_ch.md">🇨🇳 中文</a> ·
  <a href="README_ge.md">🇩🇪 Deutsch</a> ·
  <a href="README_fr.md">🇫🇷 Français</a>
</p>

<p align="center">
  <img src="docs/img/banner.svg" alt="rop_scanner — offline PE → Zydis → ROP / JOP / syscall / pivot gadgets" width="100%"/>
</p>

# rop_scanner

**Кросплатформений (Windows / Linux / macOS) офлайн-мисливець за ROP, JOP, syscall та stack-pivot гаджетами у Windows PE-файлах.** Парсить DLL / EXE / SYS / CPL / OCX / DRV / EFI безпосередньо з диска — ніколи не завантажуючи їх до адресного простору процесу, декодує кожен байт за допомогою дизасемблера [Zydis](https://github.com/zyantific/zydis) і видає ранжовані гаджети в одному з чотирьох форматів: `text`, `json`, `ropper` або готовий до вставки Python-словник для `pwntools`.

> Ідея та оригінальна стаття — **0x12 Dark Development** ([@Salsa12__](https://twitter.com/Salsa12__)),
> [«Hunting ROP Gadgets in Windows DLLs»](https://medium.com/@s12deff/hunting-rop-gadgets-in-windows-dlls-3184e4eeba62).
> Цей проєкт — незалежна C++17-реалізація та розширення тих ідей.

---

## Зміст

1. [Навіщо це потрібно](#1-навіщо-це-потрібно)
2. [Що всередині і як це працює](#2-що-всередині-і-як-це-працює)
3. [Анатомія гаджета](#3-анатомія-гаджета)
4. [Класифікація: категорія × семантика](#4-класифікація-категорія--семантика)
5. [Збірка](#5-збірка)
6. [Швидкий старт](#6-швидкий-старт)
7. [Повний CLI-довідник](#7-повний-cli-довідник)
8. [Сценарії запуску](#8-сценарії-запуску)
9. [GUI на Qt6](#9-gui-на-qt6)
10. [Застосування в розробці експлойтів](#10-застосування-в-розробці-експлойтів)
11. [Порівняння з альтернативами](#11-порівняння-з-альтернативами)
12. [Де ще це застосовно](#12-де-ще-це-застосовно)
13. [Обмеження](#13-обмеження)
14. [Подяки та юридичне](#14-подяки-та-юридичне)

---

## 1. Навіщо це потрібно

Будь-який сучасний user-mode експлойт на x86_64 Windows впирається в одне й те саме: після захоплення RIP треба якось отримати **виконання коду**, не порушивши DEP / CFG / CET. Класична відповідь — **Return-Oriented Programming**: зібрати «програму» з коротких шматочків уже завантаженого коду (`pop rcx ; ret`, `xchg rax, rsp ; ret`, `syscall` тощо), які при послідовній активації через стек самі виконають потрібну роботу — зазвичай дійдуть до `VirtualProtect` або прямого `syscall NtProtectVirtualMemory`, помітивши сторінку з шеллкодом як RWX.

<p align="center">
  <img src="docs/img/exploit-chain.svg" alt="Where rop_scanner fits in an exploit chain" width="100%"/>
</p>

Це працює, якщо у вас є **каталог придатних гаджетів** — точні RVA в тих модулях, які гарантовано завантажені у процес жертви. І ось тут починаються проблеми:

- **MSVC не генерує «зручних» гаджетів** у чистому вигляді. `pop rcx ; pop rdx ; pop r8 ; pop r9 ; ret` (угода виклику x64 Windows) майже ніколи не існує як штатна епілог-послідовність. Його доводиться **шукати як побічний ефект зсуву інструкцій**, тобто стартувати декодер на непарній границі.
- **CFG, XFG, CET Shadow Stack** відсікають частину кандидатів. Потрібно знати, які RVA є легітимними indirect-call таргетами (`IMAGE_LOAD_CONFIG_DIRECTORY.GuardCFFunctionTable`), щоб або цілити саме в них, або навпаки їх уникати.
- **Bad bytes** (`\x00`, `\x0a`, `\x0d`, маркери термінаторів протоколу, символи валідації) обнуляють половину результатів будь-якого «звичайного» сканера.
- **Крос-модульний пошук.** По-справжньому цінні гаджети — ті, що є **у будь-якому модулі, який завантажений за замовчуванням**. Будь-який `pop rcx ; ret`, прив'язаний до конкретної DLL, ламається, якщо у жертви інша версія Windows або інший набір модулів.

`rop_scanner` вирішує ці чотири проблеми безпосередньо: повне Zydis-декодування, парсинг CFG / `.pdata` / EAT, відмова від поганих байтів на етапі фільтрації, batch-режим з агрегацією за `(asm)` через десятки модулів. Один файл `.cpp` або весь `C:\Windows\System32` — одна команда.

---

## 2. Що всередині і як це працює

<p align="center">
  <img src="docs/img/pipeline.svg" alt="Pipeline: PE → pe_loader → ending finder → back-decoder → classify" width="100%"/>
</p>

П'ять стадій, кожна винесена у свій `.cpp`:

| Стадія | Файл | Що робить |
|---|---|---|
| Парсинг PE | [pe_loader.cpp](src/pe_loader.cpp) + [pe_types.h](src/pe_types.h) | MZ → PE\\0\\0 → секції → `IMAGE_DIRECTORY_ENTRY_EXPORT`, `_EXCEPTION` (.pdata RUNTIME_FUNCTION), `_LOAD_CONFIG` (CFG GuardCF table) |
| Пошук завершень | [scanner.cpp](src/scanner.cpp) | для кожного байта секції Zydis намагається декодувати там одну інструкцію. Якщо це `ret`, `ret imm16`, `syscall`, `sysenter`, `jmp reg` або `call reg` — це потенційний кінець |
| Back-декодування | [scanner.cpp](src/scanner.cpp) | для кожного завершення пробуємо всі стартові зміщення від `endPos - maxBytes` до `endPos`. Декодуємо вперед. Ланцюжок валідний, якщо він точно впирається в завершення за `≤ maxInsn` інструкцій і в тілі немає керуючих переходів |
| Класифікація | [gadget.cpp](src/gadget.cpp) | категорія (за термінатором) + семантика (за ефектом тіла) + скор (0–100) з бустами під x64 Windows ABI |
| Анотації | [symbol_resolver.cpp](src/symbol_resolver.cpp) | найближчий експорт з EAT, охоплювальна функція з `.pdata`, опціонально PDB через `dbghelp` (тільки Windows), позначка CFG-валідний/невалідний таргет |

Опорні принципи:

- **Повний декодер.** У першій версії стояв ручний міні-декодер на ~250 рядків, який розумів лише `pop reg`, `ret`, кілька `mov` і `add rsp`. Zydis 4.1 покриває весь x86 / x86_64, включно з VEX / EVEX, нестандартні `mov [mem], reg`, `lea`, `cmov*`, `pushfq` / `popfq` і будь-які memory operands. Це дає реальний `write-mem` / `read-mem` пошук, якого не було в першій версії і якого немає у багатьох «маленьких» сканерів.
- **Жодних side-effect-ів.** Парсер бінарника ніколи не викликає `LoadLibrary`, ніколи не віддає байти JIT/декодеру з побічним ефектом. Можна безпечно сканувати завідомо шкідливі зразки.
- **Один вихідний артефакт.** Самодостатній виконуваний файл без рантайм-залежностей крім libc/libstdc++. На Windows додається опціональна залежність від `dbghelp.dll` (є в будь-якій Windows).

---

## 3. Анатомія гаджета

<p align="center">
  <img src="docs/img/anatomy.svg" alt="Anatomy of a gadget: bytes → instructions → terminator" width="100%"/>
</p>

В одному кадрі: сім вихідних байтів `59 5A 41 58 41 59 C3` декодуються Zydis-ом у п'ять інструкцій — `pop rcx`, `pop rdx`, `pop r8` (REX.B+pop), `pop r9` (REX.B+pop), `ret`. Термінатор — `C3` (`ret`). Тіло — чотири безумовні `pop`-и, які роблять саме те, що потрібно угоді виклику x64 Windows: завантажити регістри `rcx/rdx/r8/r9` (перші чотири аргументи WinAPI) тим, що лежить на стеку.

`rop_scanner` знаходить такий гаджет у будь-якому достатньо великому PE на непарній границі. Бустер скору +10 за кожен `pop rXX` з x64-ABI і +15 за `xchg rax, rsp` / `leave` дає цьому ланцюжку підсумкові **100/100**.

---

## 4. Класифікація: категорія × семантика

<p align="center">
  <img src="docs/img/taxonomy.svg" alt="Two-axis taxonomy: category by terminator, semantic by body effect" width="100%"/>
</p>

Кожен гаджет помічений **за двома осями незалежно**, і обидва теги доступні як substring-фільтр у `--filter`:

- **Category** говорить про те, **як** гаджет завершується. Ця вісь визначає місце в ланцюжку: `rop` підставляється через стек, `jop` — через регістровий jmp/call, `syscall` — вихід у ядро, `pivot` — зміна RSP.
- **Semantic** говорить про те, **що** гаджет робить між стартом і термінатором: вантажить константу, копіює регістр, пише/читає пам'ять, робить арифметику, перемикає стек.

Корисність: `--filter "write-mem"` знайде **всі** примітиви write-what-where (`mov [rax], rdx ; ret`, `mov [rcx+0x10], r8 ; ret`, ...) безвідносно того, як саме вони закінчуються. А `--filter "load-const"` — усі «завантажувачі аргументів».

---

## 5. Збірка

> Усі збірки потребують **C++17** компілятор і **CMake ≥ 3.16**. Zydis підтягується автоматично через `FetchContent` при першому конфігу.

### Windows  (MSVC / Visual Studio 2019+)

З *Developer Command Prompt for VS 2022* (або зі звичайного cmd після `call vcvars64.bat`):

```cmd
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
:: -> build\bin\rop_scanner.exe
```

При лінкуванні автоматично підключається `dbghelp.lib` для опціонального PDB-резолву через `--pdb`. Якщо Ninja немає — приберіть `-G Ninja`, MSBuild впорається сам.

Очікуваний вивід останньої стадії:

```
[42/43] Building CXX object CMakeFiles/rop_scanner.dir/src/scanner.cpp.obj
[43/43] Linking CXX executable bin/rop_scanner.exe
```

### Linux  (GCC / Clang)

Перевірено на Ubuntu 22.04 + GCC 11.4. Жодних системних залежностей крім `cmake`, `g++` (або `gcc-c++`) і `make`/`ninja`:

```sh
sudo apt install -y cmake g++ make            # Debian/Ubuntu
# або
sudo dnf install -y cmake gcc-c++ make        # Fedora/RHEL

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
# -> build/bin/rop_scanner
```

GCC < 9 розщеплював `<filesystem>` у `libstdc++fs` — CMake це сам приліпить. На Clang 10+ і GCC 9+ нічого додаткового не потрібно.

### macOS  (Apple Clang)

Потрібен лише Xcode Command Line Tools (`xcode-select --install`) і будь-який CMake (Homebrew або офіційний):

```sh
brew install cmake          # один раз
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
# -> build/bin/rop_scanner
```

Apple Silicon (arm64) і Intel (x86_64) обидва працюють — `rop_scanner` лише **читає** байти PE-файлу, ніколи не виконує їх, тому архітектура хоста не має значення.

> На Linux/macOS прапорець `--pdb` приймається, але мовчки ігнорується (немає `dbghelp`). EAT + `.pdata` резолв працюють штатно і дають для публічних Windows-DLL майже те ж саме, що повернув би стрипований публічний PDB.

### Bit-for-bit сумісність

Один і той самий `ntdll.dll` (x64) дає **ідентичні** результати на всіх трьох платформах:

| Платформа | Компілятор | `exports` | `.pdata` | `cfg` | перший хіт `pop rsi ; pop rdi ; ret` |
|---|---|---|---|---|---|
| Windows 11 x64 | MSVC 19.43 | 2516 | 5679 | 2197 | `0x000026B9` — `RtlGetUserInfoHeap+0xB9` |
| macOS arm64 | AppleClang 21 | 2516 | 5679 | 2197 | `0x000026B9` — `RtlGetUserInfoHeap+0xB9` |
| Linux x64  | GCC 11.4   | 2516 | 5679 | 2197 | `0x000026B9` — `RtlGetUserInfoHeap+0xB9` |

`static_assert` на кожен розмір PE-структури в [pe_types.h](src/pe_types.h) гарантує це.

---

## 6. Швидкий старт

Перша хвилина:

```sh
# 1. Базовий прогон по ntdll.dll
./build/bin/rop_scanner /path/to/ntdll.dll | head -40
```

Очікувана перша сторінка виводу (для x64 ntdll.dll Windows 11):

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

Перший рядок — паспорт модуля; далі гаджети у порядку зменшення скору. У кожного: позначка `[category/semantic]`, скор, секція, RVA і file offset, символ (`RtlGetUserInfoHeap+0xB9` — це EAT), охоплювальна функція з `.pdata`, сирі байти, дизасемблер.

---

## 7. Повний CLI-довідник

```text
Usage:
  rop_scanner <pe-file> [pe-file ...] [options]
  rop_scanner --dir <path> [--recursive] [options]
```

### Сканування

| Прапорець | Дефолт | Сенс |
|---|---|---|
| `--max-bytes N` | 10 | Скільки байт назад від термінатора пробувати як старт. Менше — швидше, більше — більше «міжінструкційних» гаджетів на непарній границі. |
| `--max-insn N` | 5 | Максимум інструкцій у гаджеті, включно з термінатором. Реально корисні ланцюжки рідко довші за 6. |
| `--min-score N` | 0 | Відсікти все нижче порогу. Для практичної роботи я ставлю 60-70. |
| `--filter TEXT` | — | Substring (case-insensitive) шукається в `asm + section + category + semantic + symbol + function`. Один з найпотужніших прапорців: можна шукати за дизасмом (`"pop rcx ; pop rdx"`), за семантикою (`"write-mem"`), за символом (`"Rtl"`), за категорією (`"pivot"`). |
| `--badbytes B,…` | — | Список «поганих» байтів через кому: `00,0a,0d,20`. Гаджет, що містить **будь-який** з них у своїх байтах, відкидається. Це саме той фільтр, який потрібен для рядкових вразливостей (`strcpy`, `sprintf`, `gets` тощо). |
| `--limit N` | 0 (всі) | Залишити тільки топ-N після сортування. |

### CFG (Control Flow Guard)

| Прапорець | Сенс |
|---|---|
| `--only-cfg` | Тільки ті RVA, що числяться в `IMAGE_LOAD_CONFIG_DIRECTORY.GuardCFFunctionTable`. Якщо ваш RIP-override йде через indirect call з перевіркою CFG — тільки ці гаджети взагалі можна використовувати. |
| `--exclude-cfg` | Навпаки — викинути CFG-точки. Корисно, коли ви стрингуєте гаджети через `ret` (CFG не перевіряє ret-targets), але хочете мінімізувати конфлікти. |

### Символи

| Прапорець | Сенс |
|---|---|
| `--no-symbols` | Не робити EAT/`.pdata` анотацію. Помітно швидше на батчі. |
| `--pdb` | Використовувати `dbghelp.dll` для PDB-резолву. Поважає `_NT_SYMBOL_PATH`. На Linux/macOS приймається, але нічого не робить. |

### Batch-режим

| Прапорець | Сенс |
|---|---|
| `--dir PATH` | Сканувати всі PE під директорією. Розпізнаються розширення `dll exe sys cpl ocx drv efi`. |
| `--recursive` | Рекурсивно. |

У batch-режимі гаджети дедуплікуються за `(asm)` через **різні модулі** і ранжуються за `module_count desc, score desc`. Тобто нагорі списку — найбільш «всюдисущі» гаджети.

### Формат виводу

| `--format …` | Що отримуємо |
|---|---|
| `text` (за замовчуванням) | Зручний для людини |
| `json` | Уся інформація у структурованому вигляді. У batch-режимі — зі списком модулів. |
| `ropper` | `0x180012345: pop rcx; ret;` — формат, сумісний з парсерами `ropper`/`ROPgadget` |
| `pwntools` | Валідний Python-словник з image_base, RVA, asm і symbol — `cat output.py >> exploit.py` |

### Інше

| Прапорець | Сенс |
|---|---|
| `--help`, `-h`, `/?` | Допомога |

---

## 8. Сценарії запуску

### Кейс 1.  Win x64 calling-convention helpers

Мета — знайти класичне заправлення перших чотирьох аргументів WinAPI:

```sh
rop_scanner ntdll.dll \
  --filter "pop rcx ; pop rdx ; pop r8" \
  --max-insn 6 \
  --limit 10
```

Якщо гаджет не знаходиться в чистому вигляді (а в ntdll він справді рідкісний), скан сам знайде «міжінструкційні» еквіваленти:

```text
[rop/load-const] score=92 section=.text rva=0x001255F4
  symbol: tan+0x3F4
  bytes: 5C C1 F2 0F 59 C2 F2 0F
  asm  : pop rsp ; shl edx, 0x0F ; pop rcx ; ret 0xFF2
```

Це — байти з тіла `tan()` (математична функція з libm), стартуючі на непарній границі.

### Кейс 2.  Стек-півот для misaligned stack

Коли RIP захоплений у момент, де стек вирівняний непередбачувано, потрібен **півот** — зазвичай `xchg rax, rsp ; ret` або `add rsp, 0x__ ; ret`:

```sh
rop_scanner ntdll.dll --filter "pivot" --min-score 95 --limit 5
```

Отримуємо готові кандидати з точними RVA і Pdata-функціями.

### Кейс 3.  Write-what-where

Пошук **семантичний**, не за текстом інструкції:

```sh
rop_scanner ntdll.dll --filter "write-mem" --badbytes 00 --min-score 70
```

Вихід — усі `mov [reg+disp], reg ; ret`-еквіваленти без нулів у байтах.

### Кейс 4.  Bad-byte-aware  (повний ланцюжок під `strcpy`)

```sh
rop_scanner ntdll.dll \
  --filter "pop rcx ; ret" \
  --badbytes 00,0a,0d,20,3b \
  --format pwntools > rop_chunk.py
```

`--badbytes` відрізає все з нульовим байтом (рядок обріжеться), `\n`/`\r` (якщо вразливість в HTTP-заголовку), пробілом і `;`. `--format pwntools` — готовий словник, який можна одразу імпортувати.

### Кейс 5.  Крос-модульний пошук гарантовано завантажених гаджетів

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

Знайде всі 2-байтні `0F 05` і більш складні конструкції, що закінчуються `syscall`. Сортування за числом модулів, у яких гаджет присутній. Гаджети з топа списку — найнадійніший фундамент ланцюжка: вони виживуть перезбірку Windows і перехід на іншу збірку.

### Кейс 6.  CFG-aware indirect call hijack

```sh
rop_scanner ntdll.dll --only-cfg --filter "jmp r" --limit 20
```

Знайде `jmp reg` гаджети, на які CFG дозволяє стрибки — тобто допустимі мішені для indirect-call хайджеку на CET-defended Windows 10/11.

### Кейс 7.  Анотація символами + збереження у JSON для пайплайна

```sh
set _NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols
rop_scanner ntdll.dll \
  --pdb \
  --min-score 70 \
  --format json > ntdll_gadgets.json
```

Отримуємо структурований каталог з PDB-символами для подальшого завантаження в IDE/IDA-script/власний планувальник.

### Кейс 8.  Сканування драйвера

```sh
rop_scanner C:\Windows\System32\drivers\hidusb.sys --filter "syscall" --limit 5
```

Драйвери парсяться так само як звичайні PE32+ — застосовно до kernel-side гаджет-хантингу без модифікацій.

---

## 9. GUI на Qt6

Для тих, хто не хоче згадувати прапорці — є кросплатформений GUI на Qt6 (з фолбеком на Qt5), який збирається з того ж дерева і просто запускає CLI з потрібними параметрами.

<p align="center">
  <img src="docs/img/gui-mockup.svg" alt="rop_scanner Qt GUI" width="100%"/>
</p>

**Що вміє:**

- Вибір файла або директорії через `Browse…` або **drag-and-drop** прямо у вікно.
- Усі CLI-прапорці представлені полями форми (`--max-bytes`, `--max-insn`, `--min-score`, `--filter`, `--badbytes`, `--limit`, `--only-cfg`/`--exclude-cfg`, `--no-symbols`, `--pdb`, `--recursive`).
- Авто-детект шляху до `rop_scanner` (поряд з GUI, у `../bin`, у `../../build/bin`, у `Resources/` бандла на macOS).
- Стрімінговий вивід результатів у вбудований темний термінал.
- **Copy cmdline** — збирає точну shell-команду, яка б повторила запуск з терміналу. Зручно для документації експлойту або передачі колезі.
- **Save output…** — збереження у `.txt`, `.json` або `.py` (вибирається за `--format`).
- `QSettings`-персистентність усіх полів між запусками.
- Коректне завершення зависаючого сканування через `Cancel` (відправляє `SIGKILL`).

**Де живе код:** [gui/](gui/) — окремий CMake-таргет. Три файли: [`MainWindow.cpp`](gui/src/MainWindow.cpp) (форма + слоти), [`ScannerRunner.cpp`](gui/src/ScannerRunner.cpp) (обгортка над `QProcess`), [`main.cpp`](gui/src/main.cpp) (вхід). Лінкується до `Qt6::Widgets` або `Qt5::Widgets` — що знайдеться першим.

### Збірка GUI

GUI-збірка — це **опціональний** add-on до основної збірки. Використовуються ті ж build-скрипти, що й для CLI, плюс прапорець.

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

(на Fedora/RHEL замість `qt6-base-dev libvulkan-dev` використовується `qt6-qtbase-devel vulkan-headers`).

#### Windows

Встановіть Qt6 одним зі способів:

1. Офіційний інсталятор: <https://qt.io/download-open-source>
2. `vcpkg install qt6-base`
3. MSYS2: `pacman -S mingw-w64-x86_64-qt6-base`

Потім вкажіть префікс через змінну середовища і запустіть:

```cmd
set QT_PREFIX=C:\Qt\6.6.0\msvc2019_64
windows_build.bat build gui
build\bin\rop_scanner_gui.exe
```

### Що побачите у вікні

Верх — вибір режиму (один файл / батч директорії), шлях до цілі, чекбокс рекурсії. Далі **Scanning** з числовими полями і пошуковим фільтром, **CFG / Symbols** з радіогрупою CFG-фільтра і чекбоксами `--no-symbols` / `--pdb`. Під ними — випадаючий формат виводу, кнопки `Copy cmdline` / `Save output…`, поле шляху до самого `rop_scanner` (з авто-детектом) і велика кнопка `▶ Run scan`. Внизу — статус-рядок і темна консоль, куди стрімиться stdout (білим) і stderr (жовтим) у реальному часі.

---

## 10. Застосування в розробці експлойтів

Типовий workflow:

1. **Зафіксувати цільове середовище** — яка білд-версія Windows, які модулі гарантовано завантажені, який захист (CFG / XFG / CET / Shadow Stack).
2. **Зняти образи** цих модулів у файли (або взяти з чистої інсталяції, або витягти з вашої VM).
3. **Прогнати `rop_scanner` у batch-режимі** на цих файлах з `--no-symbols` для швидкості і `--format json` для пайплайна. Отримати каталог з ~десятка тисяч гаджетів.
4. **Звузити** під конкретну задачу:
   - примітив запису → `--filter "write-mem"`
   - отримання керування `rcx/rdx/r8/r9` → `--filter "load-const"` + перевірка за RVA
   - півот → `--filter "pivot" --min-score 95`
   - системний виклик → `--filter "syscall"`
5. **Прогнати `--badbytes`** під формат вхідного рядка вразливості.
6. **Якщо експлойт йде через indirect call** — додати `--only-cfg`.
7. **Зібрати ланцюжок.** `--format pwntools` економить тут пів години.

Це працює однаково і для user-mode (браузер, парсер, RDP-клієнт), і для kernel-mode (через підміну таблиць, ROP у driver-context).

### Не тільки Windows-таргети

PE-файл — це просто файл; декодер — Zydis — це просто декодер x86/x86_64. Тому `rop_scanner` спокійно сканує:

- **MinGW-зібрані PE на Linux** — для cross-compile експлойтів і тестів.
- **Windows-malware** на Linux/macOS reverse-engineering box — без ризику щось завантажити.
- **Прошивки UEFI** (розширення `.efi`) — це теж PE.
- **Старі драйвери**, для яких немає PDB.

---

## 11. Порівняння з альтернативами

| Інструмент | x86/x64 | PE | ELF | Mach-O | Семантика | Cross-module | CFG-aware | PDB | Кросплатф. бінарник |
|---|---|---|---|---|---|---|---|---|---|
| **rop_scanner** | ✅ | ✅ | — | — | ✅ | ✅ | ✅ | ✅ (Win) | **✅ Win/Linux/mac** |
| ROPgadget (Python) | ✅ | ✅ | ✅ | ✅ | — | — | — | — | ✅ |
| ropper (Python) | ✅ | ✅ | ✅ | ✅ | — | — | — | — | ✅ |
| rp++ | ✅ | ✅ | ✅ | ✅ | — | — | — | — | ✅ |
| angrop | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | — | ✅ (повільний) |

`rop_scanner` виграє там, де задача *Windows-специфічна*: семантика, CFG, `.pdata`, крос-модульний пошук по `System32`. І при цьому збирається і працює там, де зручніше редактору експлойту — на його робочій машині.

---

## 12. Де ще це застосовно

- **Malware analysis.** Витягти всі потенційні ROP-ланцюжки з підозрілого DLL/EXE без його запуску. Порівняти таблицю гаджетів до і після розпаковки/анпакера — байти тіла змінилися → unpacker відпрацював.
- **Threat hunting / detection engineering.** Snapshot вашої чистої Windows-станції (батч-скан `System32`), потім повторювати регулярно. Diff між прогонами = модифікації в бібліотеках = привід подивитися, чиї це руки. (Microsoft патчить ntdll регулярно, і склад гаджетів змінюється передбачувано; усе, що не сходиться з патчем Win Update — підозріле.)
- **Reverse engineering.** Каталог гаджетів — це карта «гарячих точок» функції: де знаходяться короткі епілоги, де `syscall`, де півоти. Полегшує читання дизасму.
- **CTF.** PE-челенджі на pwn-категорії — типовий кейс. `--format pwntools` економить години.
- **Навчання.** Хороша візуалізація того, як ROP взагалі працює: студент бачить сирі байти, їх декодування Zydis-ом, класифікацію, скор. Зазирнути в код будь-якої стадії — два екрани.
- **Аудит compiler hardening.** Хочеться зрозуміти, наскільки ваш власний білд `cl.exe /GS /guard:cf` дійсно позбавив атакувача гаджетів? Порівняйте лічильник `pivot` гаджетів у `--only-cfg` режимі до і після зміни прапорців.

---

## 13. Обмеження

- **Тільки x86 і x86_64.** PE-файли під ARM64/IA64/RISC-V відкидаються явно — Zydis їх не знає.
- **`.pdata` парсинг — тільки x64** (`RUNTIME_FUNCTION`). На x86 SEH живе інакше, ми це не використовуємо.
- **CFG-парсинг.** Беремо стандартний `IMAGE_LOAD_CONFIG_DIRECTORY` до поля `GuardFlags`. Якщо у Microsoft з'явиться нова структура з іншими офсетами — доведеться дописати.
- **Без CET/XFG-awareness** на рівні семантики (XFG type-hashes не враховуються). За планом у v0.7.
- **Single-thread.** Батч-скан `C:\Windows\System32` (~1500 PE) займає кілька хвилин. Паралелізація — це десять рядків через `std::async`, є в backlog.
- **PDB тільки під Windows** (через `dbghelp`). На Linux/macOS можна прикрутити `llvm-pdbutil`, але поки не зроблено — EAT зазвичай достатньо для публічних модулів.

---

## 14. Подяки та юридичне

- Оригінальна ідея і підхід: **0x12 Dark Development** ([@Salsa12__](https://twitter.com/Salsa12__))
  — стаття [«Hunting ROP Gadgets in Windows DLLs»](https://medium.com/@s12deff/hunting-rop-gadgets-in-windows-dlls-3184e4eeba62) на Medium.
- Декодер: **[Zydis](https://github.com/zyantific/zydis)** by Florian Bernd і команда — тягнеться через `FetchContent` при першій конфігурації CMake.
- Цей проєкт — самостійна реалізація на C++17, ідея взята зі статті; код написаний з нуля.

**Призначення:** аналіз бінарних файлів, якими ви або володієте, або маєте пряму авторизацію досліджувати — власне ПЗ, тренувальні стенди, CTF, авторизовані пентести, defensive research, освітні цілі. Ні автор оригінальної ідеи, ні автор цієї реалізації не несуть відповідальності за зловживання.
