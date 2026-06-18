#include "output.h"

#include <iomanip>
#include <ostream>
#include <sstream>

namespace rop {

namespace {

std::string HexU64(uint64_t v) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << v;
    return oss.str();
}

std::string JsonEscape(const std::string& s) {
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

void EmitGadget(std::ostream& os, const Gadget& g, const char* indent) {
    os << indent << "{\n";
    os << indent << "  \"category\": \""  << CategoryName(g.category) << "\",\n";
    os << indent << "  \"semantic\": \""  << SemanticName(g.semantic) << "\",\n";
    os << indent << "  \"score\": "       << g.score << ",\n";
    os << indent << "  \"module\": \""    << JsonEscape(g.module)   << "\",\n";
    os << indent << "  \"section\": \""   << JsonEscape(g.section)  << "\",\n";
    os << indent << "  \"rva\": \""       << HexU64(g.rva)          << "\",\n";
    os << indent << "  \"file_offset\": \"" << HexU64(g.fileOffset) << "\",\n";
    os << indent << "  \"bytes\": \""     << JsonEscape(BytesHex(g.bytes)) << "\",\n";
    os << indent << "  \"asm\": \""       << JsonEscape(AsmText(g)) << "\",\n";
    os << indent << "  \"symbol\": \""    << JsonEscape(g.nearestSymbol)   << "\",\n";
    os << indent << "  \"function\": \""  << JsonEscape(g.nearestFunction) << "\",\n";
    os << indent << "  \"cfg_valid\": "   << (g.cfgValidTarget ? "true" : "false") << "\n";
    os << indent << "}";
}

} // namespace

void PrintJson(std::ostream& os, const PeImage* img,
               const std::vector<Gadget>& gs, const Options&) {
    os << "{\n";
    if (img) {
        os << "  \"module\": \""      << JsonEscape(img->moduleName) << "\",\n";
        os << "  \"arch\": \""        << (img->is64 ? "x64" : "x86") << "\",\n";
        os << "  \"machine\": \""     << HexU64(img->machine)        << "\",\n";
        os << "  \"image_base\": \""  << HexU64(img->imageBase)      << "\",\n";
        os << "  \"has_cfg\": "       << (img->hasCfg ? "true" : "false") << ",\n";
    }
    os << "  \"count\": " << gs.size() << ",\n";
    os << "  \"gadgets\": [";
    for (size_t i = 0; i < gs.size(); i++) {
        os << (i ? ",\n" : "\n");
        EmitGadget(os, gs[i], "    ");
    }
    os << "\n  ]\n}\n";
}

void PrintBatchJson(std::ostream& os, const BatchResult& br, const Options&) {
    os << "{\n";
    os << "  \"count\": " << br.gadgets.size() << ",\n";
    os << "  \"gadgets\": [";
    for (size_t i = 0; i < br.gadgets.size(); i++) {
        os << (i ? ",\n" : "\n");
        os << "    {\n";
        os << "      \"asm\": \""   << JsonEscape(AsmText(br.gadgets[i])) << "\",\n";
        os << "      \"bytes\": \"" << JsonEscape(BytesHex(br.gadgets[i].bytes)) << "\",\n";
        os << "      \"category\": \"" << CategoryName(br.gadgets[i].category) << "\",\n";
        os << "      \"semantic\": \"" << SemanticName(br.gadgets[i].semantic) << "\",\n";
        os << "      \"score\": "   << br.gadgets[i].score << ",\n";
        os << "      \"modules\": [";
        const auto& m = br.moduleHits[i];
        for (size_t j = 0; j < m.size(); j++) {
            os << (j ? ", " : "")
               << "\"" << JsonEscape(m[j]) << "\"";
        }
        os << "]\n";
        os << "    }";
    }
    os << "\n  ]\n}\n";
}

} // namespace rop
