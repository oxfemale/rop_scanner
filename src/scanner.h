#pragma once

#include "gadget.h"
#include "pe_loader.h"

#include <cstdint>
#include <string>
#include <vector>

namespace rop {

enum class OutputFormat {
    Text,
    Json,
    Ropper,
    Pwntools,
};

struct Options {
    std::vector<std::string> paths;          // explicit PE files
    std::string              directory;      // --dir; scan all PE in directory
    bool                     recursive = false;

    size_t                   maxBytes = 10;  // back-decode window
    size_t                   maxInsn  = 5;   // insns per gadget
    int                      minScore = 0;

    std::string              filter;         // substring over asm+section+category+semantic
    std::vector<uint8_t>     badBytes;       // reject gadgets containing any of these

    bool                     onlyCfgTargets = false;
    bool                     excludeCfgTargets = false;

    bool                     resolveSymbols = true;   // EAT + .pdata; no I/O cost
    bool                     resolvePdb = false;      // dbghelp; runtime only

    OutputFormat             format = OutputFormat::Text;
    size_t                   limit = 0;      // 0 == unlimited
};

// Scan a single loaded PE and return discovered gadgets, post-filter, sorted.
std::vector<Gadget> ScanImage(const PeImage& img, const Options& opt);

// Scan a directory of PE files and return cross-module aggregated gadgets.
// Output gadget.module == name of one representative module; the
// duplicate count and other modules are tracked in moduleHits.
struct BatchResult {
    std::vector<Gadget> gadgets;
    // gadget.asm -> sorted list of modules where it was found
    std::vector<std::vector<std::string>> moduleHits;
};

BatchResult ScanDirectory(const std::string& dir, const Options& opt);

} // namespace rop
