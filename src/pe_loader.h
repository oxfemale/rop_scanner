#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_set>

namespace rop {

struct SectionView {
    std::string name;
    uint32_t    rva = 0;
    uint32_t    rawOffset = 0;
    uint32_t    rawSize = 0;
    uint32_t    virtualSize = 0;
    uint32_t    characteristics = 0;
};

struct ExportEntry {
    uint32_t    rva = 0;
    std::string name;
    uint16_t    ordinal = 0;
};

struct PdataFunction {
    uint32_t beginRva = 0;
    uint32_t endRva = 0;
};

struct PeImage {
    std::string              path;
    std::string              moduleName;   // base file name
    std::vector<uint8_t>     data;
    bool                     is64 = false;
    uint16_t                 machine = 0;
    uint64_t                 imageBase = 0;
    uint32_t                 sizeOfImage = 0;

    std::vector<SectionView>   sections;
    std::vector<ExportEntry>   exports;       // sorted by RVA
    std::vector<PdataFunction> pdata;          // sorted by beginRva; x64 only
    std::unordered_set<uint32_t> cfgTargets;   // GuardCFFunctionTable RVAs, empty if not present
    bool                     hasCfg = false;
};

// Parse a PE file (PE32 or PE32+). Fills img and returns true on success.
// Verbose error messages go to stderr.
bool LoadPe(const std::string& path, PeImage& img);

// True if the section is executable code we want to scan.
bool IsExecutable(const SectionView& s);

// Translate a file offset inside an executable section to its RVA, or 0 if none.
uint32_t FileOffsetToRva(const PeImage& img, uint32_t fileOffset);

} // namespace rop
