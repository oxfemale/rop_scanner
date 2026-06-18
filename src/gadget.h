#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rop {

enum class Category {
    Pivot,
    Syscall,
    Jop,
    Rop,
    RetOnly,
    Misc,
};

// Semantic class — what the gadget is useful FOR, not how it ends.
enum class Semantic {
    LoadConst,      // pop reg ; ret
    MovReg,         // mov dst, src ; ret
    WriteMem,       // mov [dst], src ; ret
    ReadMem,        // mov dst, [src] ; ret
    Arith,          // add/sub/xor/inc/dec reg ; ret
    StackPivot,     // anything that moves rsp
    Syscall,
    Indirect,       // jmp/call reg
    ReturnOnly,
    Other,
};

struct GadgetInsn {
    std::string text;
    uint8_t     bytes[15] = {};
    uint8_t     length = 0;
};

struct Gadget {
    std::string             module;       // base name of source PE
    std::string             section;
    uint32_t                rva = 0;
    uint32_t                fileOffset = 0;
    std::vector<uint8_t>    bytes;
    std::vector<GadgetInsn> insns;
    Category                category = Category::Misc;
    Semantic                semantic = Semantic::Other;
    int                     score = 0;

    // Annotations layered on by later passes.
    std::string             nearestSymbol;  // e.g. "RtlUserThreadStart+0x4A"
    std::string             nearestFunction; // from .pdata (x64 only)
    bool                    cfgValidTarget = false;
};

const char* CategoryName(Category c);
const char* SemanticName(Semantic s);

// "asm" rendering: "pop rcx ; pop rdx ; ret"
std::string AsmText(const Gadget& g);

// hex bytes: "59 5A C3"
std::string BytesHex(const std::vector<uint8_t>& v);

// Score the gadget and assign a Category + Semantic based on its instructions.
void Classify(Gadget& g, bool is64);

// True if any byte in g.bytes is in `bad`.
bool HasBadByte(const Gadget& g, const std::vector<uint8_t>& bad);

} // namespace rop
