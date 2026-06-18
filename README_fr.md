<p align="right">
  <a href="README.md">🇬🇧 English</a> ·
  <a href="README_ru.md">🇷🇺 Русский</a> ·
  <a href="README_ua.md">🇺🇦 Українська</a> ·
  <a href="README_ch.md">🇨🇳 中文</a> ·
  <a href="README_ge.md">🇩🇪 Deutsch</a> ·
  <b>🇫🇷 Français</b>
</p>

<p align="center">
  <img src="docs/img/banner.svg" alt="rop_scanner — offline PE → Zydis → ROP / JOP / syscall / pivot gadgets" width="100%"/>
</p>

# rop_scanner

**Chasseur multiplateforme (Windows / Linux / macOS) de gadgets ROP, JOP, syscall et stack-pivot dans les fichiers PE Windows, en mode hors-ligne.** Il parse les fichiers DLL / EXE / SYS / CPL / OCX / DRV / EFI directement depuis le disque — sans jamais les charger dans un espace d'adressage de processus — décode chaque octet via le désassembleur [Zydis](https://github.com/zyantific/zydis), et produit les gadgets classés par score dans l'un des quatre formats : `text`, `json`, `ropper`, ou un dictionnaire Python prêt à coller dans `pwntools`.

> Idée et article d'origine — **0x12 Dark Development** ([@Salsa12__](https://twitter.com/Salsa12__)),
> [« Hunting ROP Gadgets in Windows DLLs »](https://medium.com/@s12deff/hunting-rop-gadgets-in-windows-dlls-3184e4eeba62).
> Ce projet est une implémentation C++17 indépendante et une extension de ces idées.

---

## Sommaire

1. [À quoi ça sert](#1-à-quoi-ça-sert)
2. [Ce qu'il y a dedans et comment ça marche](#2-ce-quil-y-a-dedans-et-comment-ça-marche)
3. [Anatomie d'un gadget](#3-anatomie-dun-gadget)
4. [Classification : catégorie × sémantique](#4-classification--catégorie--sémantique)
5. [Compilation](#5-compilation)
6. [Démarrage rapide](#6-démarrage-rapide)
7. [Référence CLI complète](#7-référence-cli-complète)
8. [Scénarios d'utilisation](#8-scénarios-dutilisation)
9. [L'interface Qt6](#9-linterface-qt6)
10. [Utilisation en développement d'exploits](#10-utilisation-en-développement-dexploits)
11. [Comparaison avec les alternatives](#11-comparaison-avec-les-alternatives)
12. [Autres usages possibles](#12-autres-usages-possibles)
13. [Limites](#13-limites)
14. [Crédits et mentions légales](#14-crédits-et-mentions-légales)

---

## 1. À quoi ça sert

Tout exploit user-mode moderne sur x86_64 Windows finit par buter sur le même mur : une fois RIP sous contrôle, il faut encore atteindre **l'exécution de code** sans déclencher DEP / CFG / CET. La réponse classique est le **Return-Oriented Programming** — coudre ensemble de courts fragments de code déjà chargé (`pop rcx ; ret`, `xchg rax, rsp ; ret`, `syscall`, …) de sorte qu'enchaînés via des retours de pile ils fassent le vrai travail à votre place — typiquement remonter jusqu'à `VirtualProtect` ou un `syscall NtProtectVirtualMemory` direct pour rendre la page de shellcode RWX.

<p align="center">
  <img src="docs/img/exploit-chain.svg" alt="Where rop_scanner fits in an exploit chain" width="100%"/>
</p>

Cela ne marche que si l'on dispose d'un **bon catalogue de gadgets** — des RVA précises à l'intérieur de modules dont on est sûr qu'ils sont mappés dans le processus victime. Et c'est là que les ennuis commencent :

- **MSVC ne produit pas de gadgets « pratiques »** tels quels. `pop rcx ; pop rdx ; pop r8 ; pop r9 ; ret` (la convention d'appel x64 Windows) n'apparaît presque jamais comme épilogue naturel. Il faut le découvrir **comme effet de bord d'un décalage d'instructions**, c'est-à-dire en démarrant le décodeur sur une frontière non alignée.
- **CFG, XFG, CET Shadow Stack** éliminent une partie des candidats. Vous devez savoir quelles RVA sont des cibles indirect-call valides (`IMAGE_LOAD_CONFIG_DIRECTORY.GuardCFFunctionTable`) pour soit viser dedans, soit les éviter.
- **Bad bytes** (`\x00`, `\x0a`, `\x0d`, terminateurs de protocole, marqueurs de validation) annulent la moitié des résultats de n'importe quel scanner « générique ».
- **Recherche cross-module.** Les gadgets réellement précieux sont ceux qui existent **dans chaque module chargé par défaut**. Tout `pop rcx ; ret` lié à une DLL spécifique casse dès que la victime tourne sous une autre version de Windows ou charge un autre ensemble de modules.

`rop_scanner` traite ces quatre points de front : décodage complet par Zydis, parsing CFG / `.pdata` / EAT, filtrage des bad bytes au moment de la recherche, et un mode batch qui agrège par `(asm)` sur des dizaines de modules. Un seul `.cpp` ou tout `C:\Windows\System32` — même commande.

---

## 2. Ce qu'il y a dedans et comment ça marche

<p align="center">
  <img src="docs/img/pipeline.svg" alt="Pipeline: PE → pe_loader → ending finder → back-decoder → classify" width="100%"/>
</p>

Cinq étages, chacun dans son propre `.cpp` :

| Étage | Fichier | Ce qu'il fait |
|---|---|---|
| Parsing PE | [pe_loader.cpp](src/pe_loader.cpp) + [pe_types.h](src/pe_types.h) | MZ → PE\\0\\0 → sections → `IMAGE_DIRECTORY_ENTRY_EXPORT`, `_EXCEPTION` (.pdata RUNTIME_FUNCTION), `_LOAD_CONFIG` (table CFG GuardCF) |
| Découverte des terminateurs | [scanner.cpp](src/scanner.cpp) | pour chaque octet d'une section, on demande à Zydis de décoder une instruction à ce décalage. Si le résultat est un terminateur acceptable (`ret`, `ret imm16`, `syscall`, `sysenter`, `jmp reg`, `call reg`) il est noté |
| Décodage en arrière | [scanner.cpp](src/scanner.cpp) | pour chaque terminateur, on essaie toutes les positions de départ de `endPos - maxBytes` à `endPos`. On décode vers l'avant avec Zydis ; la chaîne est valide si et seulement si elle se termine **exactement** sur le terminateur en `≤ maxInsn` instructions et que le corps ne contient aucune instruction de contrôle de flux |
| Classification | [gadget.cpp](src/gadget.cpp) | catégorie (par terminateur) + sémantique (par effet du corps) + score (0–100) avec bonus pour l'ABI x64 Windows |
| Annotation | [symbol_resolver.cpp](src/symbol_resolver.cpp) | symbole exporté le plus proche depuis l'EAT, fonction englobante depuis `.pdata`, optionnellement PDB via `dbghelp` (Windows uniquement), drapeau cible CFG-valide |

Principes directeurs :

- **Décodeur complet.** La première version embarquait un mini-décodeur écrit à la main d'environ 250 lignes, qui ne connaissait que `pop reg`, `ret`, quelques `mov` et `add rsp`. Zydis 4.1 couvre tout x86 / x86_64, y compris VEX / EVEX, `mov [mem], reg` non triviaux, `lea`, `cmov*`, `pushfq` / `popfq` et n'importe quel opérande mémoire. Cela donne une vraie recherche `write-mem` / `read-mem` que la première version (et beaucoup de « petits » scanners) ne peut tout simplement pas faire — et la classification reste peu coûteuse en parcourant directement les opérandes structurés de Zydis.
- **Aucun effet de bord.** Le parseur binaire n'appelle jamais `LoadLibrary`, ne donne jamais d'octets à un JIT ou quoi que ce soit avec des effets de bord. Vous pouvez scanner sans risque des échantillons connus comme malveillants.
- **Un seul artefact.** Un exécutable autonome sans dépendance d'exécution autre que libc / libstdc++. Sur Windows s'ajoute une dépendance *optionnelle* à `dbghelp.dll` (présente dans toute installation Windows).

---

## 3. Anatomie d'un gadget

<p align="center">
  <img src="docs/img/anatomy.svg" alt="Anatomy of a gadget: bytes → instructions → terminator" width="100%"/>
</p>

D'un seul coup d'œil : les sept octets bruts `59 5A 41 58 41 59 C3` sont décodés par Zydis en cinq instructions — `pop rcx`, `pop rdx`, `pop r8` (REX.B + pop), `pop r9` (REX.B + pop), `ret`. Terminateur : `C3` (`ret`). Corps : quatre `pop` inconditionnels, qui font exactement ce dont la convention d'appel x64 Windows a besoin — charger les quatre premiers registres d'argument (`rcx / rdx / r8 / r9`) avec ce qui se trouve sur la pile.

`rop_scanner` retrouve ce genre de gadget dans tout PE suffisamment grand, sur une frontière d'octets non alignée. Avec +10 de score par `pop rXX` correspondant à l'ABI x64 et +15 pour `xchg rax, rsp` / `leave`, cette chaîne obtient le score plein de **100/100**.

---

## 4. Classification : catégorie × sémantique

<p align="center">
  <img src="docs/img/taxonomy.svg" alt="Two-axis taxonomy: category by terminator, semantic by body effect" width="100%"/>
</p>

Chaque gadget est étiqueté sur **deux axes indépendants**, tous deux exploitables comme filtres de sous-chaîne via `--filter` :

- **Category** décrit *comment* le gadget se termine. C'est cet axe qui détermine son rôle dans la chaîne : `rop` s'enchaîne via la pile, `jop` via un jmp/call indirect par registre, `syscall` est un saut vers le noyau, `pivot` change RSP.
- **Semantic** décrit *ce que* le gadget fait entre son début et son terminateur : charger une constante, copier un registre, écrire ou lire en mémoire, faire de l'arithmétique, basculer la pile.

Pourquoi c'est utile : `--filter "write-mem"` trouvera **chaque** primitive write-what-where (`mov [rax], rdx ; ret`, `mov [rcx+0x10], r8 ; ret`, …) indépendamment de la façon dont elles se terminent. `--filter "load-const"` retrouve tous les « chargeurs d'arguments ».

---

## 5. Compilation

> Toutes les compilations exigent un compilateur **C++17** et **CMake ≥ 3.16**. Zydis est récupéré automatiquement via `FetchContent` lors du premier configure.

### Windows  (MSVC / Visual Studio 2019+)

Depuis un *Developer Command Prompt for VS 2022* (ou un cmd classique après `call vcvars64.bat`) :

```cmd
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
:: -> build\bin\rop_scanner.exe
```

`dbghelp.lib` est lié automatiquement pour le résolveur PDB optionnel `--pdb`. Si Ninja n'est pas installé, retirez `-G Ninja` et MSBuild fera l'affaire.

Fin attendue de la sortie de build :

```
[42/43] Building CXX object CMakeFiles/rop_scanner.dir/src/scanner.cpp.obj
[43/43] Linking CXX executable bin/rop_scanner.exe
```

### Linux  (GCC / Clang)

Testé sur Ubuntu 22.04 + GCC 11.4. Aucune dépendance système au-delà de `cmake`, d'un compilateur C++ et de `make`/`ninja` :

```sh
sudo apt install -y cmake g++ make            # Debian/Ubuntu
# ou
sudo dnf install -y cmake gcc-c++ make        # Fedora/RHEL

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
# -> build/bin/rop_scanner
```

GCC < 9 a séparé `<filesystem>` dans `libstdc++fs` — CMake l'ajoute automatiquement. Avec Clang 10+ et GCC 9+, rien de plus.

### macOS  (Apple Clang)

Vous n'avez besoin que des Xcode Command Line Tools (`xcode-select --install`) et de n'importe quel CMake (Homebrew ou officiel) :

```sh
brew install cmake          # une seule fois
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
# -> build/bin/rop_scanner
```

Apple Silicon (arm64) et Intel (x86_64) fonctionnent tous deux — `rop_scanner` ne **lit** que des octets PE, jamais ne les exécute, donc l'architecture hôte n'a aucune importance.

> Sur Linux / macOS, l'option `--pdb` est acceptée mais silencieusement sans effet (pas de `dbghelp`). EAT + `.pdata` continuent de fonctionner et donnent, pour les DLLs Windows publiques, à peu près ce que donnerait un PDB public allégé.

### Cohérence bit-pour-bit entre plateformes

La même `ntdll.dll` x64 produit des sorties **identiques** sur les trois plateformes :

| Plateforme | Compilateur | `exports` | `.pdata` | `cfg` | premier hit pour `pop rsi ; pop rdi ; ret` |
|---|---|---|---|---|---|
| Windows 11 x64 | MSVC 19.43 | 2516 | 5679 | 2197 | `0x000026B9` — `RtlGetUserInfoHeap+0xB9` |
| macOS arm64 | AppleClang 21 | 2516 | 5679 | 2197 | `0x000026B9` — `RtlGetUserInfoHeap+0xB9` |
| Linux x64  | GCC 11.4   | 2516 | 5679 | 2197 | `0x000026B9` — `RtlGetUserInfoHeap+0xB9` |

Les `static_assert` sur la taille de chaque structure PE dans [pe_types.h](src/pe_types.h) garantissent ceci.

---

## 6. Démarrage rapide

La première minute :

```sh
# 1. Scan basique de ntdll.dll
./build/bin/rop_scanner /path/to/ntdll.dll | head -40
```

Première page attendue (pour la ntdll.dll x64 de Windows 11) :

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

La première ligne est la fiche d'identité du module ; viennent ensuite les gadgets triés par score décroissant. Chacun affiche : `[category/semantic]`, score, section, RVA et offset fichier, symbole EAT (`RtlGetUserInfoHeap+0xB9`), fonction englobante depuis `.pdata`, octets bruts, mnémoniques décodés.

---

## 7. Référence CLI complète

```text
Usage:
  rop_scanner <pe-file> [pe-file ...] [options]
  rop_scanner --dir <path> [--recursive] [options]
```

### Scan

| Option | Défaut | Signification |
|---|---|---|
| `--max-bytes N` | 10 | Combien d'octets en arrière du terminateur à essayer comme point de départ. Plus petit → plus rapide, plus grand → plus de gadgets « inter-instruction » sur des frontières décalées. |
| `--max-insn N`  | 5  | Nombre maximum d'instructions par gadget, terminateur inclus. Les chaînes vraiment utiles dépassent rarement 6. |
| `--min-score N` | 0  | Élimine tout ce qui est en dessous du seuil. Pour du travail d'exploit réel j'utilise 60-70. |
| `--filter TEXT` | —  | Recherche de sous-chaîne insensible à la casse dans `asm + section + category + semantic + symbol + function`. L'une des options les plus puissantes : on peut chercher par désassemblé (`"pop rcx ; pop rdx"`), par sémantique (`"write-mem"`), par symbole (`"Rtl"`), par catégorie (`"pivot"`). |
| `--badbytes B,…` | — | Liste d'octets « interdits » séparés par des virgules : `00,0a,0d,20`. Un gadget dont les octets bruts contiennent **n'importe lequel** de ceux-ci est rejeté. C'est le filtre exact dont on a besoin pour les vulnérabilités basées sur les chaînes (`strcpy`, `sprintf`, `gets`, etc.). |
| `--limit N` | 0 (tous) | Ne garder que les N premiers après tri. |

### CFG (Control Flow Guard)

| Option | Signification |
|---|---|
| `--only-cfg`    | Ne conserver que les RVA listés dans `IMAGE_LOAD_CONFIG_DIRECTORY.GuardCFFunctionTable`. Si votre prise de contrôle de RIP passe par un appel indirect avec contrôle CFG, ce sont les seuls gadgets légalement utilisables. |
| `--exclude-cfg` | L'inverse — rejeter les cibles CFG-valides. Utile quand vous enchaînez des gadgets via `ret` (CFG ne contrôle pas les cibles de ret) tout en voulant minimiser les collisions. |

### Symboles

| Option | Signification |
|---|---|
| `--no-symbols` | Sauter l'annotation EAT / `.pdata`. Nettement plus rapide en mode batch. |
| `--pdb`        | Utiliser `dbghelp.dll` pour la résolution PDB. Respecte `_NT_SYMBOL_PATH`. Silencieusement sans effet sur Linux / macOS. |

### Mode batch

| Option | Signification |
|---|---|
| `--dir PATH`  | Scanner tout PE sous le répertoire. Extensions reconnues : `dll exe sys cpl ocx drv efi`. |
| `--recursive` | Descendre dans les sous-répertoires. |

En mode batch, les gadgets sont dédupliqués par `(asm)` à travers **différents modules** et classés selon `module_count desc, score desc`. En haut de la liste se trouvent les gadgets les plus « omniprésents ».

### Format de sortie

| `--format …` | Sortie |
|---|---|
| `text` (défaut) | Lisible par un humain |
| `json` | Tout en JSON structuré. En mode batch inclut la liste des modules contenant chaque gadget. |
| `ropper` | `0x180012345: pop rcx; ret;` — directement consommable par `ropper` / `ROPgadget` |
| `pwntools` | Dictionnaire Python valide avec image_base, RVA, asm et symbole — `cat output.py >> exploit.py` |

### Divers

| Option | Signification |
|---|---|
| `--help`, `-h`, `/?` | Affiche l'aide |

---

## 8. Scénarios d'utilisation

### Cas 1.  Helpers pour la convention d'appel Win x64

Objectif — trouver le chargeur classique des quatre premiers registres d'argument WinAPI :

```sh
rop_scanner ntdll.dll \
  --filter "pop rcx ; pop rdx ; pop r8" \
  --max-insn 6 \
  --limit 10
```

Si le gadget n'existe pas tel quel (et dans ntdll il est effectivement rare), le scanner trouvera des équivalents décalés tout seul :

```text
[rop/load-const] score=92 section=.text rva=0x001255F4
  symbol: tan+0x3F4
  bytes: 5C C1 F2 0F 59 C2 F2 0F
  asm  : pop rsp ; shl edx, 0x0F ; pop rcx ; ret 0xFF2
```

Ce sont des octets internes au corps de `tan()` (la fonction mathématique de libm) démarrant sur une frontière non alignée.

### Cas 2.  Stack pivot pour une pile mal alignée

Quand RIP est détourné à un point où l'alignement de la pile est imprévisible, il faut un **pivot** — généralement `xchg rax, rsp ; ret` ou `add rsp, 0x__ ; ret` :

```sh
rop_scanner ntdll.dll --filter "pivot" --min-score 95 --limit 5
```

Vous obtenez des candidats prêts à l'emploi avec leurs RVA exactes et leurs noms de fonctions `.pdata`.

### Cas 3.  Write-what-where

La recherche est **sémantique**, non pas textuelle :

```sh
rop_scanner ntdll.dll --filter "write-mem" --badbytes 00 --min-score 70
```

Sortie — tous les équivalents `mov [reg+disp], reg ; ret` sans octet nul dans le payload.

### Cas 4.  Bad-byte-aware  (chaîne complète sous `strcpy`)

```sh
rop_scanner ntdll.dll \
  --filter "pop rcx ; ret" \
  --badbytes 00,0a,0d,20,3b \
  --format pwntools > rop_chunk.py
```

`--badbytes` rejette tout octet nul (la chaîne serait tronquée), `\n`/`\r` (si la vulnérabilité est dans un en-tête HTTP), l'espace et `;`. `--format pwntools` donne un dictionnaire directement importable.

### Cas 5.  Recherche cross-module de gadgets garantis chargés

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

Trouvera tous les `0F 05` sur deux octets et les constructions plus complexes se terminant par `syscall`. Tri par nombre de modules contenant le gadget. Les gadgets en tête de liste sont la base la plus fiable d'une chaîne : ils survivent aux recompilations de Windows et aux changements de version.

### Cas 6.  Détournement d'appel indirect CFG-aware

```sh
rop_scanner ntdll.dll --only-cfg --filter "jmp r" --limit 20
```

Trouvera les gadgets `jmp reg` que CFG autorise comme cibles — c'est-à-dire les points d'atterrissage légaux pour un détournement d'appel indirect sur Windows 10/11 protégé par CET.

### Cas 7.  Annotation des symboles + JSON pour pipeline

```sh
set _NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols
rop_scanner ntdll.dll \
  --pdb \
  --min-score 70 \
  --format json > ntdll_gadgets.json
```

Catalogue structuré avec symboles PDB pour chargement ultérieur dans un IDE / un script IDA / votre propre planificateur de gadgets.

### Cas 8.  Scan de pilote

```sh
rop_scanner C:\Windows\System32\drivers\hidusb.sys --filter "syscall" --limit 5
```

Les pilotes sont parsés comme n'importe quel PE32+ — applicable à la chasse aux gadgets côté noyau sans modification.

---

## 9. L'interface Qt6

Pour qui préfère ne pas mémoriser les flags, il y a une GUI multiplateforme en Qt6 (avec repli sur Qt5) qui se compile depuis le même arbre source et qui se contente d'invoquer la CLI avec les bons arguments.

<p align="center">
  <img src="docs/img/gui-mockup.svg" alt="rop_scanner Qt GUI" width="100%"/>
</p>

**Ce qu'elle fait :**

- Sélection de fichier ou répertoire via `Browse…` ou **glisser-déposer** directement sur la fenêtre.
- Chaque option CLI exposée comme champ de formulaire (`--max-bytes`, `--max-insn`, `--min-score`, `--filter`, `--badbytes`, `--limit`, `--only-cfg`/`--exclude-cfg`, `--no-symbols`, `--pdb`, `--recursive`).
- Auto-détection du binaire `rop_scanner` (à côté de la GUI, dans `../bin`, dans `../../build/bin`, dans `Resources/` d'un bundle macOS).
- Sortie streamée dans une console sombre intégrée.
- **Copy cmdline** — assemble la ligne shell exacte qui reproduirait l'exécution depuis un terminal. Pratique pour documenter un exploit ou le transmettre à un collègue.
- **Save output…** — sauvegarde en `.txt`, `.json` ou `.py` (choisi d'après `--format`).
- Persistance `QSettings` de tous les champs entre les lancements.
- Annulation propre d'un scan bloqué via `Cancel` (envoie `SIGKILL`).

**Où vit le code :** [gui/](gui/) — cible CMake distincte. Trois fichiers : [`MainWindow.cpp`](gui/src/MainWindow.cpp) (formulaire + slots), [`ScannerRunner.cpp`](gui/src/ScannerRunner.cpp) (fin wrapper autour de `QProcess`), [`main.cpp`](gui/src/main.cpp) (point d'entrée). Liaison avec `Qt6::Widgets` ou `Qt5::Widgets`, selon ce qui est trouvé en premier.

### Compiler la GUI

La GUI est un add-on **optionnel** au build principal. Mêmes scripts de compilation, un drapeau de plus.

#### macOS

```sh
brew install qt           # une seule fois
GUI=1 ./mac_build.sh
open build/bin/rop_scanner_gui.app
```

#### Linux  (Debian / Ubuntu)

```sh
sudo apt install qt6-base-dev libvulkan-dev
GUI=1 ./linux_build.sh
./build/bin/rop_scanner_gui
```

(sur Fedora/RHEL, remplacez `qt6-base-dev libvulkan-dev` par `qt6-qtbase-devel vulkan-headers`).

#### Windows

Installez Qt6 par l'un des moyens suivants :

1. L'installateur officiel : <https://qt.io/download-open-source>
2. `vcpkg install qt6-base`
3. MSYS2 : `pacman -S mingw-w64-x86_64-qt6-base`

Puis indiquez le préfixe via une variable d'environnement et lancez :

```cmd
set QT_PREFIX=C:\Qt\6.6.0\msvc2019_64
windows_build.bat build gui
build\bin\rop_scanner_gui.exe
```

### Ce que vous verrez dans la fenêtre

Le haut — sélecteur de mode (fichier unique / batch par répertoire), chemin de la cible, case à cocher récursivité. Dessous, le groupe **Scanning** avec les champs numériques et le filtre de recherche, **CFG / Symbols** avec le groupe de boutons radio du filtre CFG et les cases `--no-symbols` / `--pdb`. En dessous — la liste déroulante du format de sortie, les boutons `Copy cmdline` / `Save output…`, le chemin du binaire `rop_scanner` avec auto-détection, et le gros bouton `▶ Run scan`. Au bas — une ligne de statut et une console sombre où sont streamés stdout (en blanc) et stderr (en ambre) en temps réel.

---

## 10. Utilisation en développement d'exploits

Workflow typique :

1. **Figer l'environnement cible** — quel build Windows, quels modules sont garantis chargés, quelles mitigations (CFG / XFG / CET / Shadow Stack).
2. **Capturer les images** de ces modules dans des fichiers (soit depuis une installation propre, soit extraites depuis votre VM).
3. **Faire tourner `rop_scanner` en mode batch** sur ces fichiers avec `--no-symbols` pour la vitesse et `--format json` pour la pipeline. Vous obtenez un catalogue de ~dizaines de milliers de gadgets.
4. **Restreindre** à la tâche concrète :
   - primitive d'écriture → `--filter "write-mem"`
   - prise de contrôle de `rcx/rdx/r8/r9` → `--filter "load-const"` + vérification par RVA
   - pivot → `--filter "pivot" --min-score 95`
   - appel système → `--filter "syscall"`
5. **Appliquer `--badbytes`** selon le format de chaîne d'entrée de votre vulnérabilité.
6. **Si l'exploit passe par un appel indirect** — ajouter `--only-cfg`.
7. **Assembler la chaîne.** `--format pwntools` économise une demi-heure ici.

Ça marche pareil pour le user-mode (un navigateur, un parseur, un client RDP) et pour le kernel-mode (réécritures de tables, ROP dans le contexte d'un pilote).

### Pas seulement des cibles Windows

Un fichier PE n'est qu'un fichier ; le décodeur Zydis n'est qu'un décodeur x86 / x86_64. Aussi `rop_scanner` est-il tout à fait à l'aise pour scanner :

- **Des PE compilés sous MinGW depuis Linux** — pour des exploits cross-compilés et des tests.
- **Du malware Windows** sur une station Linux / macOS de reverse engineering — sans aucun risque de chargement.
- **Des firmwares UEFI** (extension `.efi`) — eux aussi des PE.
- **De vieux pilotes** sans PDB.

---

## 11. Comparaison avec les alternatives

| Outil | x86/x64 | PE | ELF | Mach-O | Sémantique | Cross-module | CFG-aware | PDB | Binaire multiplateforme |
|---|---|---|---|---|---|---|---|---|---|
| **rop_scanner** | ✅ | ✅ | — | — | ✅ | ✅ | ✅ | ✅ (Win) | **✅ Win / Linux / mac** |
| ROPgadget (Python) | ✅ | ✅ | ✅ | ✅ | — | — | — | — | ✅ |
| ropper (Python) | ✅ | ✅ | ✅ | ✅ | — | — | — | — | ✅ |
| rp++ | ✅ | ✅ | ✅ | ✅ | — | — | — | — | ✅ |
| angrop | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | — | ✅ (lent) |

`rop_scanner` gagne là où le problème est *spécifique à Windows* : sémantique, CFG, `.pdata`, recherche cross-module à travers `System32`. Et il se compile et tourne là où l'auteur d'exploits préfère travailler — sur sa propre machine.

---

## 12. Autres usages possibles

- **Analyse de malware.** Extraire toutes les chaînes ROP potentielles d'une DLL / EXE suspecte sans la faire tourner. Comparer les tables de gadgets avant et après un unpacking présumé — si les octets du corps ont changé, l'unpacker s'est exécuté.
- **Threat hunting / detection engineering.** Snapshot de votre poste Windows propre (batch-scan de `System32`), puis répétez régulièrement. Différences entre les exécutions = bibliothèques modifiées = motif d'aller voir qui y a touché. (Microsoft patche ntdll à cadence prévisible et le catalogue de gadgets bouge en conséquence ; tout ce qui ne colle pas avec Windows Update est suspect.)
- **Reverse engineering.** Un catalogue de gadgets est une carte des « points chauds » d'une fonction : où sont les épilogues courts, où vivent les syscalls, où se trouvent les pivots. Facilite la lecture du désassemblé.
- **CTF.** Les challenges pwn sur PE sont un cas d'école. `--format pwntools` économise des heures.
- **Pédagogie.** Belle visualisation du fonctionnement réel de ROP : l'étudiant voit les octets bruts, leur décodage par Zydis, la classification, le score. Chaque étage tient sur deux écrans de code.
- **Audit de durcissement compilateur.** Vous voulez voir à quel point votre propre build avec `cl.exe /GS /guard:cf` a vraiment privé l'attaquant de gadgets ? Comparez le compteur `pivot` en mode `--only-cfg` avant et après le changement de flags.

---

## 13. Limites

- **x86 et x86_64 uniquement.** Les PE pour ARM64 / IA64 / RISC-V sont rejetés d'emblée — Zydis ne les connaît pas.
- **Parsing `.pdata` x64 uniquement** (`RUNTIME_FUNCTION`). Sur x86, SEH vit ailleurs ; on ne s'en sert pas.
- **Parsing CFG.** Nous lisons la structure `IMAGE_LOAD_CONFIG_DIRECTORY` standard jusqu'au champ `GuardFlags`. Si Microsoft décale un jour la disposition, il faudra suivre.
- **Pas de prise en compte CET / XFG** au niveau sémantique (les type-hashes XFG ne sont pas pris en compte). Au backlog pour la v0.7.
- **Mono-thread.** Le batch-scan de `C:\Windows\System32` (~1500 PE) prend quelques minutes. La parallélisation tient en une dizaine de lignes via `std::async` ; au backlog.
- **PDB uniquement sous Windows** (via `dbghelp`). Sur Linux / macOS on pourrait brancher `llvm-pdbutil`, mais ça n'est pas fait — l'EAT suffit généralement pour les modules publics.

---

## 14. Crédits et mentions légales

- Idée et approche originales : **0x12 Dark Development** ([@Salsa12__](https://twitter.com/Salsa12__))
  — l'article [« Hunting ROP Gadgets in Windows DLLs »](https://medium.com/@s12deff/hunting-rop-gadgets-in-windows-dlls-3184e4eeba62) sur Medium.
- Le décodeur : **[Zydis](https://github.com/zyantific/zydis)** par Florian Bernd et son équipe — tiré via `FetchContent` au premier configure CMake.
- Ce projet est une réimplémentation C++17 indépendante. L'idée vient de l'article ; le code est écrit de zéro.

**Usage prévu :** analyse de binaires dont vous êtes soit propriétaire, soit explicitement autorisé à étudier — votre propre logiciel, des labs d'entraînement, des CTF, des tests de pénétration autorisés, de la recherche défensive, de l'enseignement. Ni l'auteur de l'idée originale ni l'auteur de cette implémentation n'assument la responsabilité d'un usage abusif.
