#pragma once

#include "pe_loader.h"
#include "gadget.h"

#include <string>

namespace rop {

// Resolve nearest exported symbol via EAT: "RtlUserThreadStart+0x4A".
// Returns empty string if no candidate within reasonable distance.
std::string ResolveExportSymbol(const PeImage& img, uint32_t rva);

// Resolve nearest function from .pdata (x64): "fn_0x1234" or "" if not in any RUNTIME_FUNCTION.
std::string ResolvePdataFunction(const PeImage& img, uint32_t rva);

// Optional: resolve via PDB through Windows dbghelp. Returns "" on any error.
// Honors _NT_SYMBOL_PATH. Safe to call repeatedly; lazily initializes a process-wide
// dbghelp context.
std::string ResolvePdbSymbol(const PeImage& img, uint32_t rva);

// Annotate a gadget in place. Always cheap (EAT + .pdata); PDB only if usePdb.
void Annotate(Gadget& g, const PeImage& img, bool usePdb);

// True if rva is in the CFG GuardCF function table.
bool IsCfgValidTarget(const PeImage& img, uint32_t rva);

} // namespace rop
