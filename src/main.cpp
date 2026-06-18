#include "output.h"
#include "pe_loader.h"
#include "scanner.h"

#include <cctype>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>

namespace rop {

namespace {

void Usage(std::ostream& os) {
    os <<
R"(rop_scanner — ROP/JOP/syscall/pivot gadget hunter for Windows PE files
                (offline parser; uses Zydis for decoding)

Usage:
  rop_scanner.exe <pe-file> [pe-file ...] [options]
  rop_scanner.exe --dir <path> [--recursive] [options]

Scanning:
  --max-bytes N        Max bytes before ending instruction (default 10)
  --max-insn  N        Max instructions per gadget (default 5)
  --min-score N        Drop gadgets with score < N (default 0)
  --filter   TEXT      Substring filter over asm/section/category/semantic/symbol
  --badbytes HEX,..    Reject gadgets containing any of these bytes
                       (example: --badbytes 00,0a,0d)
  --limit N            Keep only top-N gadgets after sorting (default: all)

CFG (PE Load Config):
  --only-cfg           Keep only gadgets at CFG-valid call targets
  --exclude-cfg        Drop gadgets at CFG-valid call targets

Symbols:
  --no-symbols         Skip EAT/.pdata annotation (faster)
  --pdb                Use dbghelp PDB resolution (respects _NT_SYMBOL_PATH)

Batch mode:
  --dir PATH           Scan every PE under PATH (extensions: dll/exe/sys/cpl/ocx/drv/efi)
  --recursive          Recurse into subdirectories with --dir

Output:
  --format FMT         text (default) | json | ropper | pwntools
  --help               This help

Examples:
  rop_scanner.exe C:\Windows\System32\ntdll.dll
  rop_scanner.exe ntdll.dll --filter "pop rcx" --badbytes 00,0a,0d --min-score 80
  rop_scanner.exe ntdll.dll --format pwntools > rop.py
  rop_scanner.exe --dir C:\Windows\System32 --filter "syscall" --limit 50
  rop_scanner.exe ntdll.dll --pdb --filter "Rtl"
)";
}

bool ParseBadBytes(const std::string& s, std::vector<uint8_t>& out) {
    std::string cur;
    auto flush = [&]() {
        if (cur.empty()) return true;
        if (cur.size() > 2) return false;
        for (char c : cur) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
        }
        out.push_back(static_cast<uint8_t>(std::stoul(cur, nullptr, 16)));
        cur.clear();
        return true;
    };
    for (char c : s) {
        if (c == ',' || c == ' ' || c == ';') {
            if (!flush()) return false;
        } else {
            cur.push_back(c);
        }
    }
    if (!flush()) return false;
    return !out.empty();
}

bool ParseFormat(const std::string& s, OutputFormat& out) {
    if (s == "text"     || s == "txt")  { out = OutputFormat::Text;     return true; }
    if (s == "json")                    { out = OutputFormat::Json;     return true; }
    if (s == "ropper"   || s == "rp")   { out = OutputFormat::Ropper;   return true; }
    if (s == "pwntools" || s == "py")   { out = OutputFormat::Pwntools; return true; }
    return false;
}

bool RequireValue(int& i, int argc, char** argv, const std::string& opt) {
    if (i + 1 >= argc) {
        std::cerr << "[-] missing value for " << opt << "\n";
        return false;
    }
    ++i;
    return true;
}

bool ParseArgs(int argc, char** argv, Options& opt) {
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];

        if (a == "--help" || a == "-h" || a == "/?") return false;

        if (a == "--dir")           { if (!RequireValue(i, argc, argv, a)) return false; opt.directory = argv[i]; }
        else if (a == "--recursive"){ opt.recursive = true; }
        else if (a == "--max-bytes"){ if (!RequireValue(i, argc, argv, a)) return false; opt.maxBytes = std::stoul(argv[i]); }
        else if (a == "--max-insn") { if (!RequireValue(i, argc, argv, a)) return false; opt.maxInsn  = std::stoul(argv[i]); }
        else if (a == "--min-score"){ if (!RequireValue(i, argc, argv, a)) return false; opt.minScore = std::stoi(argv[i]); }
        else if (a == "--filter")   { if (!RequireValue(i, argc, argv, a)) return false; opt.filter   = argv[i]; }
        else if (a == "--limit")    { if (!RequireValue(i, argc, argv, a)) return false; opt.limit    = std::stoul(argv[i]); }
        else if (a == "--badbytes") {
            if (!RequireValue(i, argc, argv, a)) return false;
            if (!ParseBadBytes(argv[i], opt.badBytes)) {
                std::cerr << "[-] bad --badbytes value: " << argv[i] << "\n";
                return false;
            }
        }
        else if (a == "--format") {
            if (!RequireValue(i, argc, argv, a)) return false;
            if (!ParseFormat(argv[i], opt.format)) {
                std::cerr << "[-] unknown --format: " << argv[i] << "\n";
                return false;
            }
        }
        else if (a == "--only-cfg")    { opt.onlyCfgTargets = true; }
        else if (a == "--exclude-cfg") { opt.excludeCfgTargets = true; }
        else if (a == "--no-symbols")  { opt.resolveSymbols = false; }
        else if (a == "--pdb")         { opt.resolvePdb = true; }
        else if (a == "--json")        { opt.format = OutputFormat::Json; }  // legacy
        else if (a.size() > 0 && a[0] == '-') {
            std::cerr << "[-] unknown option: " << a << "\n";
            return false;
        }
        else {
            opt.paths.push_back(a);
        }
    }

    if (opt.paths.empty() && opt.directory.empty()) {
        std::cerr << "[-] need at least one PE file or --dir\n";
        return false;
    }
    if (opt.maxBytes < 1 || opt.maxBytes > 64) {
        std::cerr << "[-] --max-bytes must be in [1, 64]\n";
        return false;
    }
    if (opt.maxInsn < 1 || opt.maxInsn > 16) {
        std::cerr << "[-] --max-insn must be in [1, 16]\n";
        return false;
    }
    if (opt.onlyCfgTargets && opt.excludeCfgTargets) {
        std::cerr << "[-] --only-cfg and --exclude-cfg are mutually exclusive\n";
        return false;
    }
    return true;
}

int RunSingle(const Options& opt) {
    int rc = 0;
    for (const std::string& path : opt.paths) {
        PeImage img;
        if (!LoadPe(path, img)) { rc = 2; continue; }

        std::vector<Gadget> gs = ScanImage(img, opt);

        switch (opt.format) {
            case OutputFormat::Text:     PrintText    (std::cout, &img, gs, opt); break;
            case OutputFormat::Json:     PrintJson    (std::cout, &img, gs, opt); break;
            case OutputFormat::Ropper:   PrintRopper  (std::cout, &img, gs, opt); break;
            case OutputFormat::Pwntools: PrintPwntools(std::cout, &img, gs, opt); break;
        }
    }
    return rc;
}

int RunBatch(const Options& opt) {
    BatchResult br = ScanDirectory(opt.directory, opt);
    switch (opt.format) {
        case OutputFormat::Json:
            PrintBatchJson(std::cout, br, opt); break;
        case OutputFormat::Ropper:
        case OutputFormat::Pwntools:
            std::cerr << "[!] format not supported in batch mode; falling back to text\n";
            [[fallthrough]];
        case OutputFormat::Text:
            PrintBatchText(std::cout, br, opt); break;
    }
    return 0;
}

} // namespace

} // namespace rop

int main(int argc, char** argv) {
    // Explicit --help / -h / /? → usage on stdout, exit 0.
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h" || a == "/?") {
            rop::Usage(std::cout);
            return 0;
        }
    }

    rop::Options opt;
    if (!rop::ParseArgs(argc, argv, opt)) {
        rop::Usage(std::cerr);
        return 1;
    }

    if (!opt.directory.empty()) {
        return rop::RunBatch(opt);
    }
    return rop::RunSingle(opt);
}
