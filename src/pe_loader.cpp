#include "pe_loader.h"
#include "pe_types.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <filesystem>

namespace rop {

using namespace pe;

namespace {

template<typename T>
bool PtrAt(const std::vector<uint8_t>& data, size_t off, const T*& out) {
    if (off > data.size() || sizeof(T) > data.size() - off) {
        return false;
    }
    out = reinterpret_cast<const T*>(data.data() + off);
    return true;
}

bool ReadFileToVector(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;

    f.seekg(0, std::ios::end);
    std::streamoff size = f.tellg();
    if (size <= 0) return false;

    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    f.read(reinterpret_cast<char*>(out.data()), size);
    return f.good();
}

std::string SectionName(const IMAGE_SECTION_HEADER& s) {
    char buf[9] = {};
    std::memcpy(buf, s.Name, 8);
    return std::string(buf);
}

// Translate an RVA to a file offset using the section table.
// Returns 0 on miss (and *ok = false). Section headers are not at RVA 0,
// so 0 is a fine sentinel.
uint32_t RvaToFileOffset(const PeImage& img, uint32_t rva, bool* ok = nullptr) {
    for (const SectionView& s : img.sections) {
        if (rva >= s.rva && rva < s.rva + std::max(s.rawSize, s.virtualSize)) {
            uint32_t delta = rva - s.rva;
            if (delta < s.rawSize) {
                if (ok) *ok = true;
                return s.rawOffset + delta;
            }
        }
    }
    if (ok) *ok = false;
    return 0;
}

void ParseExports(PeImage& img, uint32_t exportDirRva, uint32_t exportDirSize) {
    if (exportDirRva == 0 || exportDirSize < sizeof(IMAGE_EXPORT_DIRECTORY)) {
        return;
    }

    bool ok = false;
    uint32_t off = RvaToFileOffset(img, exportDirRva, &ok);
    if (!ok) return;

    const IMAGE_EXPORT_DIRECTORY* exp = nullptr;
    if (!PtrAt(img.data, off, exp)) return;

    uint32_t namesOff = RvaToFileOffset(img, exp->AddressOfNames, &ok);
    if (!ok) return;
    uint32_t funcsOff = RvaToFileOffset(img, exp->AddressOfFunctions, &ok);
    if (!ok) return;
    uint32_t ordsOff  = RvaToFileOffset(img, exp->AddressOfNameOrdinals, &ok);
    if (!ok) return;

    if (namesOff + 4 * static_cast<size_t>(exp->NumberOfNames) > img.data.size()) return;
    if (ordsOff  + 2 * static_cast<size_t>(exp->NumberOfNames) > img.data.size()) return;
    if (funcsOff + 4 * static_cast<size_t>(exp->NumberOfFunctions) > img.data.size()) return;

    const uint32_t* names = reinterpret_cast<const uint32_t*>(img.data.data() + namesOff);
    const uint16_t* ords  = reinterpret_cast<const uint16_t*>(img.data.data() + ordsOff);
    const uint32_t* funcs = reinterpret_cast<const uint32_t*>(img.data.data() + funcsOff);

    img.exports.reserve(exp->NumberOfNames);

    for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
        uint16_t ord = ords[i];
        if (ord >= exp->NumberOfFunctions) continue;

        uint32_t funcRva = funcs[ord];
        if (funcRva == 0) continue;

        uint32_t nameOff = RvaToFileOffset(img, names[i], &ok);
        if (!ok || nameOff >= img.data.size()) continue;

        const char* p = reinterpret_cast<const char*>(img.data.data() + nameOff);
        size_t maxLen = img.data.size() - nameOff;
        size_t len = ::strnlen(p, maxLen);
        if (len == maxLen) continue;

        ExportEntry e;
        e.rva = funcRva;
        e.ordinal = static_cast<uint16_t>(ord + exp->Base);
        e.name.assign(p, len);
        img.exports.push_back(std::move(e));
    }

    std::sort(img.exports.begin(), img.exports.end(),
              [](const ExportEntry& a, const ExportEntry& b) { return a.rva < b.rva; });
}

void ParsePdata(PeImage& img, uint32_t pdataRva, uint32_t pdataSize) {
    if (!img.is64) return;  // RUNTIME_FUNCTION layout we read is x64
    if (pdataRva == 0 || pdataSize < sizeof(RUNTIME_FUNCTION)) return;

    bool ok = false;
    uint32_t off = RvaToFileOffset(img, pdataRva, &ok);
    if (!ok) return;
    if (off + pdataSize > img.data.size()) return;

    uint32_t count = pdataSize / sizeof(RUNTIME_FUNCTION);
    const RUNTIME_FUNCTION* rf =
        reinterpret_cast<const RUNTIME_FUNCTION*>(img.data.data() + off);

    img.pdata.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        if (rf[i].BeginAddress == 0 && rf[i].EndAddress == 0) break;
        PdataFunction f;
        f.beginRva = rf[i].BeginAddress;
        f.endRva   = rf[i].EndAddress;
        img.pdata.push_back(f);
    }

    std::sort(img.pdata.begin(), img.pdata.end(),
              [](const PdataFunction& a, const PdataFunction& b) {
                  return a.beginRva < b.beginRva;
              });
}

void ParseCfg(PeImage& img, uint32_t lcRva, uint32_t lcSize) {
    if (lcRva == 0) return;

    bool ok = false;
    uint32_t off = RvaToFileOffset(img, lcRva, &ok);
    if (!ok) return;

    if (img.is64) {
        if (lcSize < sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64)) return;
        const IMAGE_LOAD_CONFIG_DIRECTORY64* lc = nullptr;
        if (!PtrAt(img.data, off, lc)) return;

        // GuardCFFunctionTable is a VA; subtract image base to get RVA.
        if (lc->GuardCFFunctionTable == 0 || lc->GuardCFFunctionCount == 0) return;

        uint64_t tableVa = lc->GuardCFFunctionTable;
        if (tableVa < img.imageBase) return;
        uint64_t tableRva64 = tableVa - img.imageBase;
        if (tableRva64 > 0xFFFFFFFFu) return;

        uint32_t tableRva = static_cast<uint32_t>(tableRva64);
        uint32_t tableOff = RvaToFileOffset(img, tableRva, &ok);
        if (!ok) return;

        // Stride = 4 + ((GuardFlags >> 28) & 0xF) extra metadata bytes
        uint32_t extra = (lc->GuardFlags >> 28) & 0xF;
        uint32_t stride = 4 + extra;
        uint32_t count = static_cast<uint32_t>(lc->GuardCFFunctionCount);

        if (tableOff + static_cast<size_t>(stride) * count > img.data.size()) return;

        img.cfgTargets.reserve(count);
        for (uint32_t i = 0; i < count; i++) {
            uint32_t entry =
                *reinterpret_cast<const uint32_t*>(img.data.data() + tableOff + i * stride);
            img.cfgTargets.insert(entry);
        }
        img.hasCfg = true;
    } else {
        if (lcSize < sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32)) return;
        const IMAGE_LOAD_CONFIG_DIRECTORY32* lc = nullptr;
        if (!PtrAt(img.data, off, lc)) return;
        if (lc->GuardCFFunctionTable == 0 || lc->GuardCFFunctionCount == 0) return;

        uint32_t tableVa = lc->GuardCFFunctionTable;
        if (tableVa < static_cast<uint32_t>(img.imageBase)) return;
        uint32_t tableRva = tableVa - static_cast<uint32_t>(img.imageBase);
        uint32_t tableOff = RvaToFileOffset(img, tableRva, &ok);
        if (!ok) return;

        uint32_t extra = (lc->GuardFlags >> 28) & 0xF;
        uint32_t stride = 4 + extra;
        uint32_t count = lc->GuardCFFunctionCount;
        if (tableOff + static_cast<size_t>(stride) * count > img.data.size()) return;

        img.cfgTargets.reserve(count);
        for (uint32_t i = 0; i < count; i++) {
            uint32_t entry =
                *reinterpret_cast<const uint32_t*>(img.data.data() + tableOff + i * stride);
            img.cfgTargets.insert(entry);
        }
        img.hasCfg = true;
    }
}

} // namespace

bool IsExecutable(const SectionView& s) {
    return (s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 && s.rawSize > 0;
}

uint32_t FileOffsetToRva(const PeImage& img, uint32_t fileOffset) {
    for (const SectionView& s : img.sections) {
        if (fileOffset >= s.rawOffset && fileOffset < s.rawOffset + s.rawSize) {
            return s.rva + (fileOffset - s.rawOffset);
        }
    }
    return 0;
}

bool LoadPe(const std::string& path, PeImage& img) {
    img.path = path;
    try {
        img.moduleName = std::filesystem::path(path).filename().string();
    } catch (...) {
        img.moduleName = path;
    }

    if (!ReadFileToVector(path, img.data)) {
        std::cerr << "[-] cannot read: " << path << "\n";
        return false;
    }

    const IMAGE_DOS_HEADER* dos = nullptr;
    if (!PtrAt(img.data, 0, dos) || dos->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[-] not a PE (bad MZ): " << path << "\n";
        return false;
    }

    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) >= img.data.size()) {
        std::cerr << "[-] bad e_lfanew: " << path << "\n";
        return false;
    }

    size_t ntOff = static_cast<size_t>(dos->e_lfanew);

    const DWORD* sigPtr = nullptr;
    if (!PtrAt(img.data, ntOff, sigPtr) || *sigPtr != IMAGE_NT_SIGNATURE) {
        std::cerr << "[-] bad NT signature: " << path << "\n";
        return false;
    }

    const IMAGE_FILE_HEADER* fh = nullptr;
    if (!PtrAt(img.data, ntOff + sizeof(DWORD), fh)) return false;
    img.machine = fh->Machine;

    size_t optOff = ntOff + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    const WORD* magicPtr = nullptr;
    if (!PtrAt(img.data, optOff, magicPtr)) return false;

    uint32_t numDirs = 0;
    const IMAGE_DATA_DIRECTORY* dirs = nullptr;

    if (*magicPtr == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        img.is64 = true;
        const IMAGE_OPTIONAL_HEADER64* oh = nullptr;
        if (!PtrAt(img.data, optOff, oh)) return false;
        img.imageBase   = oh->ImageBase;
        img.sizeOfImage = oh->SizeOfImage;
        numDirs         = oh->NumberOfRvaAndSizes;
        dirs            = oh->DataDirectory;
    } else if (*magicPtr == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        img.is64 = false;
        const IMAGE_OPTIONAL_HEADER32* oh = nullptr;
        if (!PtrAt(img.data, optOff, oh)) return false;
        img.imageBase   = oh->ImageBase;
        img.sizeOfImage = oh->SizeOfImage;
        numDirs         = oh->NumberOfRvaAndSizes;
        dirs            = oh->DataDirectory;
    } else {
        std::cerr << "[-] unknown optional header magic: " << path << "\n";
        return false;
    }

    // Zydis only decodes x86 / x86-64. Reject other architectures up front so
    // we don't silently return zero gadgets on ARM64 / IA64 / etc.
    switch (img.machine) {
        case IMAGE_FILE_MACHINE_I386:
        case IMAGE_FILE_MACHINE_AMD64:
            break;
        default:
            std::cerr << "[-] unsupported architecture (machine=0x"
                      << std::hex << img.machine << std::dec
                      << "); only x86/x64 PE files are supported: " << path << "\n";
            return false;
    }

    size_t secOff = optOff + fh->SizeOfOptionalHeader;
    for (WORD i = 0; i < fh->NumberOfSections; i++) {
        const IMAGE_SECTION_HEADER* sec = nullptr;
        if (!PtrAt(img.data, secOff + i * sizeof(IMAGE_SECTION_HEADER), sec)) {
            std::cerr << "[-] section header out of range: " << path << "\n";
            return false;
        }
        SectionView sv;
        sv.name            = SectionName(*sec);
        sv.rva             = sec->VirtualAddress;
        sv.rawOffset       = sec->PointerToRawData;
        sv.rawSize         = sec->SizeOfRawData;
        sv.virtualSize     = sec->Misc.VirtualSize;
        sv.characteristics = sec->Characteristics;

        if (sv.rawOffset < img.data.size()) {
            uint32_t maxRaw = static_cast<uint32_t>(
                std::min<size_t>(sv.rawSize, img.data.size() - sv.rawOffset));
            sv.rawSize = maxRaw;
            img.sections.push_back(sv);
        }
    }

    if (numDirs > IMAGE_DIRECTORY_ENTRY_EXPORT && dirs) {
        ParseExports(img,
                     dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
                     dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
    }
    if (numDirs > IMAGE_DIRECTORY_ENTRY_EXCEPTION && dirs) {
        ParsePdata(img,
                   dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress,
                   dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);
    }
    if (numDirs > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG && dirs) {
        ParseCfg(img,
                 dirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress,
                 dirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size);
    }

    return true;
}

} // namespace rop
