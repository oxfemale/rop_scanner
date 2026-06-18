#include "output.h"

#include <iomanip>
#include <ostream>
#include <sstream>

namespace rop {

namespace {

std::string HexU64(uint64_t v, int w = 0) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << std::setfill('0');
    if (w) oss << std::setw(w);
    oss << v;
    return oss.str();
}

void PrintOne(std::ostream& os, const Gadget& g) {
    os << "[" << CategoryName(g.category) << "/" << SemanticName(g.semantic) << "] "
       << "score=" << g.score
       << " section=" << g.section
       << " rva=" << HexU64(g.rva, 8)
       << " file=" << HexU64(g.fileOffset, 8);

    if (g.cfgValidTarget) os << " cfg=valid";

    if (!g.nearestSymbol.empty())
        os << "\n  symbol: " << g.nearestSymbol;
    if (!g.nearestFunction.empty() && g.nearestFunction != g.nearestSymbol)
        os << "\n  function: " << g.nearestFunction;

    os << "\n  bytes: " << BytesHex(g.bytes)
       << "\n  asm  : " << AsmText(g)
       << "\n\n";
}

} // namespace

void PrintText(std::ostream& os, const PeImage* img,
               const std::vector<Gadget>& gs, const Options&) {
    if (img) {
        os << "[+] module: " << img->moduleName
           << " arch=" << (img->is64 ? "x64" : "x86")
           << " machine=" << HexU64(img->machine)
           << " image_base=" << HexU64(img->imageBase)
           << " sections=" << img->sections.size()
           << " exports=" << img->exports.size()
           << " pdata=" << img->pdata.size();
        if (img->hasCfg)
            os << " cfg=" << img->cfgTargets.size();
        os << "\n";
    }
    os << "[+] gadgets: " << gs.size() << "\n\n";

    for (const Gadget& g : gs) PrintOne(os, g);
}

void PrintBatchText(std::ostream& os, const BatchResult& br, const Options&) {
    os << "[+] unique gadgets across modules: " << br.gadgets.size() << "\n\n";
    for (size_t i = 0; i < br.gadgets.size(); i++) {
        const Gadget& g = br.gadgets[i];
        const auto& mods = br.moduleHits[i];

        os << "[" << CategoryName(g.category) << "/" << SemanticName(g.semantic) << "] "
           << "score=" << g.score
           << " modules=" << mods.size()
           << " rva=" << HexU64(g.rva, 8);

        if (!g.nearestSymbol.empty())
            os << "\n  symbol: " << g.nearestSymbol;

        os << "\n  modules: ";
        for (size_t j = 0; j < mods.size(); j++) {
            if (j) os << ", ";
            os << mods[j];
            if (j > 5) { os << ", ... (" << (mods.size() - j - 1) << " more)"; break; }
        }
        os << "\n  bytes: " << BytesHex(g.bytes)
           << "\n  asm  : " << AsmText(g)
           << "\n\n";
    }
}

} // namespace rop
