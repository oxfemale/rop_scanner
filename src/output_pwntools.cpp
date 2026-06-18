#include "output.h"

#include <iomanip>
#include <ostream>
#include <sstream>

namespace rop {

// pwntools-friendly output:
//   # module ntdll.dll, image_base 0x180000000
//   gadgets = {
//       0x180001234: "pop rcx; ret",         # rop, score=90
//       ...
//   }
//
// The user can paste this into Python or import it.
void PrintPwntools(std::ostream& os, const PeImage* img,
                   const std::vector<Gadget>& gs, const Options&) {
    uint64_t base = img ? img->imageBase : 0;

    if (img) {
        os << "# module: " << img->moduleName
           << "  arch: " << (img->is64 ? "x86_64" : "i386")
           << "  image_base: 0x" << std::hex << img->imageBase << "\n";
    }
    os << "gadgets = {\n";

    for (const Gadget& g : gs) {
        std::string asmText = AsmText(g);
        std::string out;
        out.reserve(asmText.size());
        for (size_t i = 0; i < asmText.size(); i++) {
            if (i + 2 < asmText.size() &&
                asmText[i] == ' ' && asmText[i+1] == ';' && asmText[i+2] == ' ') {
                out += "; ";
                i += 2;
            } else {
                out += asmText[i];
            }
        }

        os << "    0x" << std::hex << (base + g.rva)
           << ": \"" << out << "\","
           << "  # " << CategoryName(g.category)
           << "/" << SemanticName(g.semantic)
           << ", score=" << std::dec << g.score;
        if (!g.nearestSymbol.empty()) os << " @ " << g.nearestSymbol;
        os << "\n";
    }
    os << "}\n";
}

} // namespace rop
