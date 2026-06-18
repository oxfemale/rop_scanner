// rop_scanner.cpp
// Minimal reusable ROP/JOP/SROP gadget scanner for Windows PE files.
// Build:
//   cl /EHsc /std:c++17 rop_scanner.cpp /Fe:rop_scanner.exe
//
// Examples:
//   rop_scanner.exe C:\Windows\System32\ntdll.dll
//   rop_scanner.exe C:\Windows\System32\ntdll.dll --filter "pop rcx"
//   rop_scanner.exe C:\Windows\System32\ntdll.dll --json
//
// Notes:
//   - Offline PE parser: does not LoadLibraryA(), does not execute DllMain.
//   - This is a research/defensive analysis utility, not an exploit builder.
//   - Decoder is intentionally small and gadget-oriented. For production-grade
//     disassembly, replace DecodeOne() with Zydis or Capstone.

#define NOMINMAX
#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

struct Options {
    std::string path;
    size_t maxBytes = 10;
    size_t maxInsn = 5;
    bool json = false;
    std::string filter;
};

struct SectionView {
    std::string name;
    uint32_t rva = 0;
    uint32_t rawOffset = 0;
    uint32_t rawSize = 0;
    uint32_t virtualSize = 0;
    uint32_t characteristics = 0;
};

struct PeImage {
    std::vector<uint8_t> data;
    bool is64 = false;
    WORD machine = 0;
    std::vector<SectionView> sections;
};

struct DecodedInsn {
    size_t len = 0;
    std::string text;
    bool isEnding = false;
    bool isRet = false;
    bool isJmpReg = false;
    bool isCallReg = false;
    bool isSyscall = false;
    bool isPivot = false;
    bool useful = false;
};

struct Gadget {
    std::string section;
    uint32_t rva = 0;
    uint32_t fileOffset = 0;
    std::vector<uint8_t> bytes;
    std::vector<std::string> insns;
    std::string category;
    int score = 0;
};

static std::string ToLower(std::string s) {
    for (auto& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

static std::string HexU64(uint64_t v, int width = 0) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << std::setfill('0');
    if (width > 0) {
        oss << std::setw(width);
    }
    oss << v;
    return oss.str();
}

static std::string BytesToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (size_t i = 0; i < bytes.size(); i++) {
        if (i) {
            oss << " ";
        }
        oss << std::hex << std::uppercase << std::setfill('0')
            << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return oss.str();
}

static std::string JsonEscape(const std::string& s) {
    std::ostringstream oss;
    for (char c : s) {
        switch (c) {
        case '\\': oss << "\\\\"; break;
        case '"':  oss << "\\\""; break;
        case '\n': oss << "\\n";  break;
        case '\r': oss << "\\r";  break;
        case '\t': oss << "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                oss << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<int>(static_cast<unsigned char>(c));
            } else {
                oss << c;
            }
        }
    }
    return oss.str();
}

static bool ReadFileToVector(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return false;
    }

    f.seekg(0, std::ios::end);
    std::streamoff size = f.tellg();
    if (size <= 0) {
        return false;
    }

    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    f.read(reinterpret_cast<char*>(out.data()), size);
    return f.good();
}

template<typename T>
static bool PtrAt(const std::vector<uint8_t>& data, size_t off, const T*& out) {
    if (off > data.size() || sizeof(T) > data.size() - off) {
        return false;
    }
    out = reinterpret_cast<const T*>(data.data() + off);
    return true;
}

static std::string SectionName(const IMAGE_SECTION_HEADER& s) {
    char buf[9] = {};
    memcpy(buf, s.Name, 8);
    return std::string(buf);
}

static bool ParsePe(const std::string& path, PeImage& img) {
    if (!ReadFileToVector(path, img.data)) {
        std::cerr << "[-] Failed to read file: " << path << "\n";
        return false;
    }

    const IMAGE_DOS_HEADER* dos = nullptr;
    if (!PtrAt(img.data, 0, dos) || dos->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[-] Invalid DOS header\n";
        return false;
    }

    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) >= img.data.size()) {
        std::cerr << "[-] Invalid e_lfanew\n";
        return false;
    }

    const IMAGE_NT_HEADERS64* nt64 = nullptr;
    if (!PtrAt(img.data, static_cast<size_t>(dos->e_lfanew), nt64) ||
        nt64->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[-] Invalid NT header\n";
        return false;
    }

    img.machine = nt64->FileHeader.Machine;

    const IMAGE_FILE_HEADER& fh = nt64->FileHeader;
    const uint16_t magic = nt64->OptionalHeader.Magic;

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        img.is64 = true;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        img.is64 = false;
    } else {
        std::cerr << "[-] Unknown optional header magic\n";
        return false;
    }

    size_t sectionOff =
        static_cast<size_t>(dos->e_lfanew) +
        sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER) +
        fh.SizeOfOptionalHeader;

    for (WORD i = 0; i < fh.NumberOfSections; i++) {
        const IMAGE_SECTION_HEADER* sec = nullptr;
        if (!PtrAt(img.data, sectionOff + i * sizeof(IMAGE_SECTION_HEADER), sec)) {
            std::cerr << "[-] Section header out of range\n";
            return false;
        }

        SectionView sv;
        sv.name = SectionName(*sec);
        sv.rva = sec->VirtualAddress;
        sv.rawOffset = sec->PointerToRawData;
        sv.rawSize = sec->SizeOfRawData;
        sv.virtualSize = sec->Misc.VirtualSize;
        sv.characteristics = sec->Characteristics;

        if (sv.rawOffset < img.data.size()) {
            uint32_t maxRaw = static_cast<uint32_t>(
                std::min<size_t>(sv.rawSize, img.data.size() - sv.rawOffset)
            );
            sv.rawSize = maxRaw;
            img.sections.push_back(sv);
        }
    }

    return true;
}

static bool IsExecutable(const SectionView& s) {
    return (s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 && s.rawSize > 0;
}

static std::string RegName64(int reg) {
    static const char* regs[16] = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"
    };
    return regs[reg & 15];
}

static std::string RegName32(int reg) {
    static const char* regs[8] = {
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"
    };
    return regs[reg & 7];
}

static bool HasModRmRegDirect(uint8_t modrm) {
    return (modrm & 0xC0) == 0xC0;
}

static int ModRmReg(uint8_t modrm) {
    return (modrm >> 3) & 7;
}

static int ModRmRm(uint8_t modrm) {
    return modrm & 7;
}

static std::string Join(const std::vector<std::string>& xs, const std::string& sep) {
    std::ostringstream oss;
    for (size_t i = 0; i < xs.size(); i++) {
        if (i) {
            oss << sep;
        }
        oss << xs[i];
    }
    return oss.str();
}

// Small gadget-oriented x86/x64 decoder.
// It accepts only common short instructions useful in ROP/JOP analysis.
// Unknown instruction => invalid candidate.
static DecodedInsn DecodeOne(const uint8_t* p, size_t remain, bool is64) {
    DecodedInsn d;
    if (remain == 0) {
        return d;
    }

    size_t i = 0;
    bool rexW = false;
    bool rexR = false;
    bool rexB = false;

    if (is64 && remain >= 1 && p[i] >= 0x40 && p[i] <= 0x4F) {
        uint8_t rex = p[i++];
        rexW = (rex & 0x08) != 0;
        rexR = (rex & 0x04) != 0;
        rexB = (rex & 0x01) != 0;
        if (i >= remain) {
            return {};
        }
    }

    uint8_t op = p[i];

    auto regName = [&](int r) -> std::string {
        if (is64) {
            return RegName64(r);
        }
        return RegName32(r & 7);
    };

    auto regWithB = [&](int r) -> int {
        return r + ((is64 && rexB) ? 8 : 0);
    };

    auto regWithR = [&](int r) -> int {
        return r + ((is64 && rexR) ? 8 : 0);
    };

    // ret
    if (op == 0xC3) {
        d.len = i + 1;
        d.text = "ret";
        d.isEnding = true;
        d.isRet = true;
        return d;
    }

    // ret imm16
    if (op == 0xC2 && remain >= i + 3) {
        uint16_t imm = p[i + 1] | (static_cast<uint16_t>(p[i + 2]) << 8);
        d.len = i + 3;
        d.text = "ret " + HexU64(imm);
        d.isEnding = true;
        d.isRet = true;
        return d;
    }

    // syscall
    if (op == 0x0F && remain >= i + 2 && p[i + 1] == 0x05) {
        d.len = i + 2;
        d.text = "syscall";
        d.isEnding = true;
        d.isSyscall = true;
        d.useful = true;
        return d;
    }

    // nop
    if (op == 0x90) {
        d.len = i + 1;
        d.text = "nop";
        return d;
    }

    // leave
    if (op == 0xC9) {
        d.len = i + 1;
        d.text = "leave";
        d.isPivot = true;
        d.useful = true;
        return d;
    }

    // pop reg: 58+r
    if (op >= 0x58 && op <= 0x5F) {
        int r = regWithB(op - 0x58);
        d.len = i + 1;
        d.text = "pop " + regName(r);
        d.useful = true;
        if ((is64 && r == 4) || (!is64 && (r & 7) == 4)) {
            d.isPivot = true;
        }
        return d;
    }

    // push reg: 50+r
    if (op >= 0x50 && op <= 0x57) {
        int r = regWithB(op - 0x50);
        d.len = i + 1;
        d.text = "push " + regName(r);
        return d;
    }

    // xchg eax/reg or rax/reg: 90+r, except 90 nop handled above.
    if (op >= 0x91 && op <= 0x97) {
        int r = regWithB(op - 0x90);
        d.len = i + 1;
        std::string a = is64 && rexW ? "rax" : (is64 ? "eax" : "eax");
        d.text = "xchg " + a + ", " + regName(r);
        if ((is64 && r == 4) || (!is64 && (r & 7) == 4)) {
            d.isPivot = true;
            d.useful = true;
        }
        return d;
    }

    // add/sub rsp/esp, imm8: 48 83 C4 xx / 83 C4 xx
    // add/sub rsp/esp, imm32: 48 81 C4 xx xx xx xx / 81 C4 ...
    if ((op == 0x83 || op == 0x81) && remain >= i + 3) {
        uint8_t modrm = p[i + 1];
        int regop = ModRmReg(modrm);
        int rm = ModRmRm(modrm) + ((is64 && rexB) ? 8 : 0);

        bool direct = HasModRmRegDirect(modrm);
        bool isAdd = regop == 0;
        bool isSub = regop == 5;

        if (direct && (isAdd || isSub) && ((is64 && rm == 4) || (!is64 && (rm & 7) == 4))) {
            if (op == 0x83 && remain >= i + 3) {
                int8_t imm = static_cast<int8_t>(p[i + 2]);
                d.len = i + 3;
                d.text = std::string(isAdd ? "add " : "sub ") +
                         (is64 ? "rsp, " : "esp, ") +
                         HexU64(static_cast<uint8_t>(imm));
                d.isPivot = true;
                d.useful = true;
                return d;
            }

            if (op == 0x81 && remain >= i + 6) {
                uint32_t imm =
                    static_cast<uint32_t>(p[i + 2]) |
                    (static_cast<uint32_t>(p[i + 3]) << 8) |
                    (static_cast<uint32_t>(p[i + 4]) << 16) |
                    (static_cast<uint32_t>(p[i + 5]) << 24);
                d.len = i + 6;
                d.text = std::string(isAdd ? "add " : "sub ") +
                         (is64 ? "rsp, " : "esp, ") +
                         HexU64(imm);
                d.isPivot = true;
                d.useful = true;
                return d;
            }
        }
    }

    // jmp/call reg: FF /4 or FF /2 with modrm direct
    if (op == 0xFF && remain >= i + 2) {
        uint8_t modrm = p[i + 1];
        int regop = ModRmReg(modrm);
        int rm = regWithB(ModRmRm(modrm));

        if (HasModRmRegDirect(modrm) && regop == 4) {
            d.len = i + 2;
            d.text = "jmp " + regName(rm);
            d.isEnding = true;
            d.isJmpReg = true;
            d.useful = true;
            return d;
        }

        if (HasModRmRegDirect(modrm) && regop == 2) {
            d.len = i + 2;
            d.text = "call " + regName(rm);
            d.isEnding = true;
            d.isCallReg = true;
            d.useful = true;
            return d;
        }
    }

    // mov r/m, r and mov r, r/m with register-direct ModRM only.
    // 89 /r: mov r/m, r
    // 8B /r: mov r, r/m
    if ((op == 0x89 || op == 0x8B) && remain >= i + 2) {
        uint8_t modrm = p[i + 1];
        if (HasModRmRegDirect(modrm)) {
            int reg = regWithR(ModRmReg(modrm));
            int rm = regWithB(ModRmRm(modrm));

            d.len = i + 2;

            if (op == 0x89) {
                d.text = "mov " + regName(rm) + ", " + regName(reg);
            } else {
                d.text = "mov " + regName(reg) + ", " + regName(rm);
            }

            d.useful = true;
            return d;
        }
    }

    // xor r, r / xor r/m, r, register-direct only.
    if (op == 0x31 && remain >= i + 2) {
        uint8_t modrm = p[i + 1];
        if (HasModRmRegDirect(modrm)) {
            int reg = regWithR(ModRmReg(modrm));
            int rm = regWithB(ModRmRm(modrm));
            d.len = i + 2;
            d.text = "xor " + regName(rm) + ", " + regName(reg);
            d.useful = true;
            return d;
        }
    }

    // inc/dec register via FF /0 and FF /1, direct only.
    if (op == 0xFF && remain >= i + 2) {
        uint8_t modrm = p[i + 1];
        int regop = ModRmReg(modrm);
        int rm = regWithB(ModRmRm(modrm));

        if (HasModRmRegDirect(modrm) && regop == 0) {
            d.len = i + 2;
            d.text = "inc " + regName(rm);
            return d;
        }

        if (HasModRmRegDirect(modrm) && regop == 1) {
            d.len = i + 2;
            d.text = "dec " + regName(rm);
            return d;
        }
    }

    // add/sub reg, imm8 via 83 /0 or /5, register-direct non-stack.
    if (op == 0x83 && remain >= i + 3) {
        uint8_t modrm = p[i + 1];
        int regop = ModRmReg(modrm);
        int rm = regWithB(ModRmRm(modrm));

        if (HasModRmRegDirect(modrm) && (regop == 0 || regop == 5)) {
            int8_t imm = static_cast<int8_t>(p[i + 2]);
            d.len = i + 3;
            d.text = std::string(regop == 0 ? "add " : "sub ") +
                     regName(rm) + ", " + HexU64(static_cast<uint8_t>(imm));
            return d;
        }
    }

    return {};
}

static bool IsPotentialEndingAt(const uint8_t* p, size_t remain, bool is64) {
    if (remain == 0) {
        return false;
    }

    // ret
    if (p[0] == 0xC3) {
        return true;
    }

    // ret imm16
    if (p[0] == 0xC2 && remain >= 3) {
        return true;
    }

    // syscall
    if (p[0] == 0x0F && remain >= 2 && p[1] == 0x05) {
        return true;
    }

    // optional REX + FF E0-E7 / D0-D7 for jmp/call reg.
    size_t i = 0;
    if (is64 && p[i] >= 0x40 && p[i] <= 0x4F) {
        i++;
        if (i >= remain) {
            return false;
        }
    }

    if (p[i] == 0xFF && remain >= i + 2) {
        uint8_t modrm = p[i + 1];
        if (HasModRmRegDirect(modrm)) {
            int regop = ModRmReg(modrm);
            return regop == 2 || regop == 4;
        }
    }

    return false;
}

static bool DecodeCandidate(
    const uint8_t* base,
    size_t sectionSize,
    size_t start,
    size_t ending,
    bool is64,
    size_t maxInsn,
    Gadget& out)
{
    size_t pos = start;
    std::vector<std::string> insns;
    bool endingSeen = false;
    bool useful = false;
    bool pivot = false;
    bool ret = false;
    bool jop = false;
    bool syscall = false;

    while (pos <= ending && insns.size() < maxInsn) {
        DecodedInsn d = DecodeOne(base + pos, sectionSize - pos, is64);
        if (d.len == 0) {
            return false;
        }

        if (pos + d.len - 1 > ending) {
            return false;
        }

        insns.push_back(d.text);
        useful = useful || d.useful;
        pivot = pivot || d.isPivot;
        ret = ret || d.isRet;
        jop = jop || d.isJmpReg || d.isCallReg;
        syscall = syscall || d.isSyscall;

        pos += d.len;

        if (pos - 1 == ending && d.isEnding) {
            endingSeen = true;
            break;
        }

        if (d.isEnding && pos - 1 != ending) {
            return false;
        }
    }

    if (!endingSeen || pos != ending + 1) {
        return false;
    }

    if (insns.empty() || insns.size() > maxInsn) {
        return false;
    }

    // Avoid printing plain "ret" only unless user asks for very short gadgets.
    if (insns.size() == 1 && ret) {
        return false;
    }

    if (pivot) {
        out.category = "pivot";
        out.score = 95;
    } else if (syscall) {
        out.category = "syscall";
        out.score = 90;
    } else if (jop) {
        out.category = "jop";
        out.score = 75;
    } else if (useful && ret) {
        out.category = "rop";
        out.score = 70;
    } else if (ret) {
        out.category = "ret";
        out.score = 40;
    } else {
        out.category = "misc";
        out.score = 20;
    }

    // Boost common Windows x64 calling convention helpers.
    std::string text = ToLower(Join(insns, " ; "));
    if (text.find("pop rcx") != std::string::npos) out.score += 10;
    if (text.find("pop rdx") != std::string::npos) out.score += 10;
    if (text.find("pop r8")  != std::string::npos) out.score += 10;
    if (text.find("pop r9")  != std::string::npos) out.score += 10;
    if (text.find("add rsp") != std::string::npos) out.score += 10;
    if (text.find("xchg rax, rsp") != std::string::npos) out.score += 15;
    if (text.find("leave") != std::string::npos) out.score += 15;

    if (out.score > 100) {
        out.score = 100;
    }

    out.insns = insns;
    return true;
}

static std::vector<Gadget> ScanPe(const PeImage& img, const Options& opt) {
    std::vector<Gadget> found;
    std::set<std::string> dedup;

    for (const SectionView& sec : img.sections) {
        if (!IsExecutable(sec)) {
            continue;
        }

        const uint8_t* base = img.data.data() + sec.rawOffset;
        size_t size = sec.rawSize;

        for (size_t end = 0; end < size; end++) {
            if (!IsPotentialEndingAt(base + end, size - end, img.is64)) {
                continue;
            }

            size_t minStart = 0;
            if (end > opt.maxBytes) {
                minStart = end - opt.maxBytes;
            }

            for (size_t start = minStart; start <= end; start++) {
                Gadget g;
                if (!DecodeCandidate(base, size, start, end, img.is64, opt.maxInsn, g)) {
                    continue;
                }

                g.section = sec.name;
                g.fileOffset = sec.rawOffset + static_cast<uint32_t>(start);
                g.rva = sec.rva + static_cast<uint32_t>(start);
                g.bytes.assign(base + start, base + end + 1);

                std::string asmText = Join(g.insns, " ; ");
                std::string key = std::to_string(g.rva) + ":" + asmText;
                if (dedup.count(key)) {
                    continue;
                }

                if (!opt.filter.empty()) {
                    std::string f = ToLower(opt.filter);
                    std::string searchable =
                        ToLower(asmText + " " + g.section + " " + g.category);
                    if (searchable.find(f) == std::string::npos) {
                        continue;
                    }
                }

                dedup.insert(key);
                found.push_back(g);
            }
        }
    }

    std::sort(found.begin(), found.end(), [](const Gadget& a, const Gadget& b) {
        if (a.score != b.score) {
            return a.score > b.score;
        }
        return a.rva < b.rva;
    });

    return found;
}

static void PrintText(const PeImage& img, const std::vector<Gadget>& gadgets) {
    std::cout << "[+] Architecture: "
              << (img.is64 ? "x64" : "x86")
              << " Machine=" << HexU64(img.machine)
              << "\n";

    std::cout << "[+] Gadgets found: " << gadgets.size() << "\n\n";

    for (const auto& g : gadgets) {
        std::cout << "[" << g.category << "] "
                  << "score=" << g.score
                  << " section=" << g.section
                  << " rva=" << HexU64(g.rva, 8)
                  << " file=" << HexU64(g.fileOffset, 8)
                  << "\n";

        std::cout << "  bytes: " << BytesToHex(g.bytes) << "\n";
        std::cout << "  asm  : " << Join(g.insns, " ; ") << "\n\n";
    }
}

static void PrintJson(const PeImage& img, const std::vector<Gadget>& gadgets) {
    std::cout << "{\n";
    std::cout << "  \"arch\": \"" << (img.is64 ? "x64" : "x86") << "\",\n";
    std::cout << "  \"machine\": \"" << HexU64(img.machine) << "\",\n";
    std::cout << "  \"count\": " << gadgets.size() << ",\n";
    std::cout << "  \"gadgets\": [\n";

    for (size_t i = 0; i < gadgets.size(); i++) {
        const auto& g = gadgets[i];

        std::cout << "    {\n";
        std::cout << "      \"category\": \"" << JsonEscape(g.category) << "\",\n";
        std::cout << "      \"score\": " << g.score << ",\n";
        std::cout << "      \"section\": \"" << JsonEscape(g.section) << "\",\n";
        std::cout << "      \"rva\": \"" << HexU64(g.rva, 8) << "\",\n";
        std::cout << "      \"file_offset\": \"" << HexU64(g.fileOffset, 8) << "\",\n";
        std::cout << "      \"bytes\": \"" << JsonEscape(BytesToHex(g.bytes)) << "\",\n";
        std::cout << "      \"asm\": \"" << JsonEscape(Join(g.insns, " ; ")) << "\"\n";
        std::cout << "    }" << (i + 1 == gadgets.size() ? "" : ",") << "\n";
    }

    std::cout << "  ]\n";
    std::cout << "}\n";
}

static void Usage() {
    std::cout
        << "Usage:\n"
        << "  rop_scanner.exe <pe-file> [options]\n\n"
        << "Options:\n"
        << "  --max-bytes N    Max bytes before ending instruction, default 10\n"
        << "  --max-insn N     Max instructions per gadget, default 5\n"
        << "  --filter TEXT    Show only gadgets containing TEXT\n"
        << "  --json           JSON output\n"
        << "  --help           Show this help\n\n"
        << "Examples:\n"
        << "  rop_scanner.exe C:\\Windows\\System32\\ntdll.dll\n"
        << "  rop_scanner.exe C:\\Windows\\System32\\ntdll.dll --filter \"pop rcx\"\n"
        << "  rop_scanner.exe C:\\Windows\\System32\\kernelbase.dll --json\n";
}

static bool ParseArgs(int argc, char** argv, Options& opt) {
    if (argc < 2) {
        return false;
    }

    opt.path = argv[1];

    if (opt.path == "--help" || opt.path == "-h" || opt.path == "/?") {
        return false;
    }

    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];

        if (a == "--json") {
            opt.json = true;
        } else if (a == "--max-bytes") {
            if (i + 1 >= argc) {
                std::cerr << "[-] Missing value for --max-bytes\n";
                return false;
            }
            opt.maxBytes = static_cast<size_t>(std::stoul(argv[++i]));
        } else if (a == "--max-insn") {
            if (i + 1 >= argc) {
                std::cerr << "[-] Missing value for --max-insn\n";
                return false;
            }
            opt.maxInsn = static_cast<size_t>(std::stoul(argv[++i]));
        } else if (a == "--filter") {
            if (i + 1 >= argc) {
                std::cerr << "[-] Missing value for --filter\n";
                return false;
            }
            opt.filter = argv[++i];
        } else if (a == "--help" || a == "-h" || a == "/?") {
            return false;
        } else {
            std::cerr << "[-] Unknown option: " << a << "\n";
            return false;
        }
    }

    if (opt.maxBytes < 1 || opt.maxBytes > 64) {
        std::cerr << "[-] --max-bytes must be between 1 and 64\n";
        return false;
    }

    if (opt.maxInsn < 1 || opt.maxInsn > 16) {
        std::cerr << "[-] --max-insn must be between 1 and 16\n";
        return false;
    }

    return true;
}

int main(int argc, char** argv) {
    Options opt;

    if (!ParseArgs(argc, argv, opt)) {
        Usage();
        return 1;
    }

    PeImage img;
    if (!ParsePe(opt.path, img)) {
        return 2;
    }

    std::vector<Gadget> gadgets = ScanPe(img, opt);

    if (opt.json) {
        PrintJson(img, gadgets);
    } else {
        PrintText(img, gadgets);
    }

    return 0;
}
