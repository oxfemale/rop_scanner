#include "gadget.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

namespace rop {

const char* CategoryName(Category c) {
    switch (c) {
        case Category::Pivot:   return "pivot";
        case Category::Syscall: return "syscall";
        case Category::Jop:     return "jop";
        case Category::Rop:     return "rop";
        case Category::RetOnly: return "ret";
        case Category::Misc:    return "misc";
    }
    return "?";
}

const char* SemanticName(Semantic s) {
    switch (s) {
        case Semantic::LoadConst:  return "load-const";
        case Semantic::MovReg:     return "mov-reg";
        case Semantic::WriteMem:   return "write-mem";
        case Semantic::ReadMem:    return "read-mem";
        case Semantic::Arith:      return "arith";
        case Semantic::StackPivot: return "stack-pivot";
        case Semantic::Syscall:    return "syscall";
        case Semantic::Indirect:   return "indirect";
        case Semantic::ReturnOnly: return "return-only";
        case Semantic::Other:      return "other";
    }
    return "?";
}

std::string AsmText(const Gadget& g) {
    std::ostringstream oss;
    for (size_t i = 0; i < g.insns.size(); i++) {
        if (i) oss << " ; ";
        oss << g.insns[i].text;
    }
    return oss.str();
}

std::string BytesHex(const std::vector<uint8_t>& v) {
    std::ostringstream oss;
    for (size_t i = 0; i < v.size(); i++) {
        if (i) oss << ' ';
        oss << std::hex << std::uppercase << std::setfill('0')
            << std::setw(2) << static_cast<int>(v[i]);
    }
    return oss.str();
}

static std::string ToLower(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

static bool Contains(const std::string& s, const char* needle) {
    return s.find(needle) != std::string::npos;
}

void Classify(Gadget& g, bool is64) {
    std::string text = ToLower(AsmText(g));
    if (g.insns.empty()) {
        g.category = Category::Misc;
        g.semantic = Semantic::Other;
        return;
    }

    const std::string& last = g.insns.back().text;
    std::string lastLower = ToLower(last);

    bool isRet     = lastLower == "ret" || lastLower.rfind("ret ", 0) == 0;
    bool isSyscall = lastLower == "syscall" || lastLower == "sysenter";
    bool isJmpReg  = lastLower.rfind("jmp ", 0) == 0 && !Contains(lastLower, "[");
    bool isCallReg = lastLower.rfind("call ", 0) == 0 && !Contains(lastLower, "[");

    // Stack-pivot indicators anywhere in the gadget body.
    bool pivot =
        (Contains(text, "xchg") && Contains(text, is64 ? "rsp" : "esp")) ||
         Contains(text, "leave") ||
         Contains(text, is64 ? "pop rsp" : "pop esp") ||
         Contains(text, is64 ? "add rsp" : "add esp") ||
         Contains(text, is64 ? "sub rsp" : "sub esp") ||
         Contains(text, is64 ? "mov rsp" : "mov esp");

    // ---- Category --------------------------------------------------------
    if (pivot && (isRet || isSyscall || isJmpReg || isCallReg)) {
        g.category = Category::Pivot;
    } else if (isSyscall) {
        g.category = Category::Syscall;
    } else if (isJmpReg || isCallReg) {
        g.category = Category::Jop;
    } else if (isRet && g.insns.size() > 1) {
        g.category = Category::Rop;
    } else if (isRet) {
        g.category = Category::RetOnly;
    } else {
        g.category = Category::Misc;
    }

    // ---- Semantic --------------------------------------------------------
    // Look at the non-terminator body.
    Semantic sem = Semantic::Other;

    auto bodyHas = [&](const char* needle) {
        for (size_t i = 0; i + 1 < g.insns.size(); i++) {
            if (ToLower(g.insns[i].text).find(needle) != std::string::npos)
                return true;
        }
        return false;
    };

    if (pivot) {
        sem = Semantic::StackPivot;
    } else if (isSyscall) {
        sem = Semantic::Syscall;
    } else if (isJmpReg || isCallReg) {
        sem = Semantic::Indirect;
    } else if (g.insns.size() == 1 && isRet) {
        sem = Semantic::ReturnOnly;
    } else {
        // Classify based on body
        bool onlyPops = true;
        for (size_t i = 0; i + 1 < g.insns.size(); i++) {
            if (ToLower(g.insns[i].text).rfind("pop ", 0) != 0) {
                onlyPops = false;
                break;
            }
        }

        if (onlyPops && g.insns.size() > 1) {
            sem = Semantic::LoadConst;
        } else if (bodyHas("mov ") && bodyHas("[")) {
            // crude: distinguish [dst], src vs dst, [src]
            bool writeMem = false, readMem = false;
            for (size_t i = 0; i + 1 < g.insns.size(); i++) {
                std::string t = ToLower(g.insns[i].text);
                if (t.rfind("mov ", 0) != 0) continue;
                auto comma = t.find(',');
                if (comma == std::string::npos) continue;
                std::string lhs = t.substr(0, comma);
                std::string rhs = t.substr(comma + 1);
                if (lhs.find('[') != std::string::npos) writeMem = true;
                if (rhs.find('[') != std::string::npos) readMem = true;
            }
            if (writeMem) sem = Semantic::WriteMem;
            else if (readMem) sem = Semantic::ReadMem;
            else sem = Semantic::MovReg;
        } else if (bodyHas("mov ")) {
            sem = Semantic::MovReg;
        } else if (bodyHas("add ") || bodyHas("sub ") || bodyHas("xor ") ||
                   bodyHas("inc ") || bodyHas("dec ") || bodyHas("and ") ||
                   bodyHas("or ")  || bodyHas("shl ") || bodyHas("shr ") ||
                   bodyHas("neg ") || bodyHas("not ")) {
            sem = Semantic::Arith;
        }
    }
    g.semantic = sem;

    // ---- Score -----------------------------------------------------------
    int score = 0;
    switch (g.category) {
        case Category::Pivot:   score = 95; break;
        case Category::Syscall: score = 90; break;
        case Category::Jop:     score = 75; break;
        case Category::Rop:     score = 70; break;
        case Category::RetOnly: score = 40; break;
        case Category::Misc:    score = 20; break;
    }

    // Windows x64 calling-convention helpers
    if (Contains(text, "pop rcx")) score += 10;
    if (Contains(text, "pop rdx")) score += 10;
    if (Contains(text, "pop r8"))  score += 10;
    if (Contains(text, "pop r9"))  score += 10;
    if (Contains(text, "add rsp")) score += 10;
    if (Contains(text, "xchg rax, rsp")) score += 15;
    if (Contains(text, "xchg rsp, rax")) score += 15;
    if (Contains(text, "leave"))   score += 15;

    // Penalize huge gadgets — every extra insn beyond 3 costs 3.
    if (g.insns.size() > 3) score -= 3 * static_cast<int>(g.insns.size() - 3);

    if (score < 0)   score = 0;
    if (score > 100) score = 100;
    g.score = score;
}

bool HasBadByte(const Gadget& g, const std::vector<uint8_t>& bad) {
    if (bad.empty()) return false;
    for (uint8_t b : g.bytes) {
        for (uint8_t bb : bad) {
            if (b == bb) return true;
        }
    }
    return false;
}

} // namespace rop
