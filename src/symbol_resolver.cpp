#include "symbol_resolver.h"

#include <algorithm>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <unordered_map>

#ifdef _WIN32
#  include <Windows.h>
#  include <dbghelp.h>
#endif

namespace rop {

namespace {

#ifdef _WIN32
// ---------------------------------------------------------------------------
// Lazy dbghelp setup (Windows-only)
// ---------------------------------------------------------------------------
class PdbContext {
public:
    static PdbContext& instance() {
        static PdbContext c;
        return c;
    }

    DWORD64 LoadModule(const std::string& path) {
        std::lock_guard<std::mutex> lock(mu_);
        if (!initialized_) {
            SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS
                        | SYMOPT_LOAD_LINES | SYMOPT_FAIL_CRITICAL_ERRORS
                        | SYMOPT_NO_PROMPTS);
            if (!SymInitialize(GetCurrentProcess(), nullptr, FALSE)) {
                ok_ = false;
                initialized_ = true;
                return 0;
            }
            ok_ = true;
            initialized_ = true;
        }
        if (!ok_) return 0;

        auto it = loaded_.find(path);
        if (it != loaded_.end()) return it->second;

        DWORD64 base = SymLoadModuleEx(GetCurrentProcess(), nullptr,
                                       path.c_str(), nullptr, 0, 0, nullptr, 0);
        loaded_[path] = base;
        return base;
    }

    bool Available() {
        std::lock_guard<std::mutex> lock(mu_);
        return initialized_ && ok_;
    }

private:
    std::mutex mu_;
    bool initialized_ = false;
    bool ok_ = false;
    std::unordered_map<std::string, DWORD64> loaded_;
};
#endif // _WIN32

} // namespace

std::string ResolveExportSymbol(const PeImage& img, uint32_t rva) {
    if (img.exports.empty()) return {};

    // exports is sorted by rva ascending — upper_bound + step back.
    auto it = std::upper_bound(
        img.exports.begin(), img.exports.end(), rva,
        [](uint32_t v, const ExportEntry& e) { return v < e.rva; });

    if (it == img.exports.begin()) return {};
    --it;

    uint32_t delta = rva - it->rva;
    // Don't claim resolution for arbitrarily large deltas — practical limit
    // is ~4KB; beyond that we're probably in a different function.
    if (delta > 0x1000) return {};

    if (delta == 0) return it->name;

    std::ostringstream oss;
    oss << it->name << "+0x" << std::hex << std::uppercase << delta;
    return oss.str();
}

std::string ResolvePdataFunction(const PeImage& img, uint32_t rva) {
    if (img.pdata.empty()) return {};

    // Find the function whose [begin, end) contains rva.
    auto it = std::upper_bound(
        img.pdata.begin(), img.pdata.end(), rva,
        [](uint32_t v, const PdataFunction& f) { return v < f.beginRva; });

    if (it == img.pdata.begin()) return {};
    --it;
    if (rva >= it->endRva) return {};

    // We don't have the function name from .pdata alone; produce a stable label.
    std::ostringstream oss;
    oss << "fn_0x" << std::hex << std::uppercase << it->beginRva;
    if (rva > it->beginRva) oss << "+0x" << (rva - it->beginRva);
    return oss.str();
}

std::string ResolvePdbSymbol(const PeImage& img, uint32_t rva) {
#ifdef _WIN32
    PdbContext& ctx = PdbContext::instance();
    DWORD64 base = ctx.LoadModule(img.path);
    if (base == 0) return {};

    DWORD64 addr = base + rva;

    union {
        SYMBOL_INFO info;
        char buf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME + 1];
    } u = {};
    u.info.SizeOfStruct = sizeof(SYMBOL_INFO);
    u.info.MaxNameLen   = MAX_SYM_NAME;

    DWORD64 displacement = 0;
    if (!SymFromAddr(GetCurrentProcess(), addr, &displacement, &u.info)) return {};

    std::ostringstream oss;
    oss << u.info.Name;
    if (displacement != 0) {
        oss << "+0x" << std::hex << std::uppercase << displacement;
    }
    return oss.str();
#else
    (void)img; (void)rva;
    return {};  // PDB resolution requires dbghelp; not available on non-Windows.
#endif
}

bool IsCfgValidTarget(const PeImage& img, uint32_t rva) {
    return img.cfgTargets.find(rva) != img.cfgTargets.end();
}

void Annotate(Gadget& g, const PeImage& img, bool usePdb) {
    std::string s;
    if (usePdb) s = ResolvePdbSymbol(img, g.rva);
    if (s.empty()) s = ResolveExportSymbol(img, g.rva);
    g.nearestSymbol = std::move(s);

    g.nearestFunction = ResolvePdataFunction(img, g.rva);

    if (img.hasCfg) g.cfgValidTarget = IsCfgValidTarget(img, g.rva);
}

} // namespace rop
