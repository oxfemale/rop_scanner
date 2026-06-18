#include "output.h"

#include <iomanip>
#include <ostream>
#include <sstream>

namespace rop {

// ropper-style output:
//   0x00001234: pop rcx; ret;
//
// VA-style address uses ImageBase + RVA when img is available, otherwise RVA.
void PrintRopper(std::ostream& os, const PeImage* img,
                 const std::vector<Gadget>& gs, const Options&) {
    uint64_t base = img ? img->imageBase : 0;
    for (const Gadget& g : gs) {
        std::ostringstream addr;
        addr << "0x" << std::hex << std::setw(16) << std::setfill('0')
             << (base + g.rva);

        // Replace " ; " with "; " to match ropper layout.
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
        os << addr.str() << ": " << out << ";\n";
    }
}

} // namespace rop
