#include "scanner.h"
#include "symbol_resolver.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace rop {

namespace {

bool IsControlFlowDisallowedInBody(ZydisMnemonic m) {
    switch (m) {
        case ZYDIS_MNEMONIC_JMP: case ZYDIS_MNEMONIC_CALL:
        case ZYDIS_MNEMONIC_RET: case ZYDIS_MNEMONIC_IRET:
        case ZYDIS_MNEMONIC_IRETD: case ZYDIS_MNEMONIC_IRETQ:
        case ZYDIS_MNEMONIC_INT: case ZYDIS_MNEMONIC_INT3:
        case ZYDIS_MNEMONIC_INTO: case ZYDIS_MNEMONIC_INT1:
        case ZYDIS_MNEMONIC_SYSCALL: case ZYDIS_MNEMONIC_SYSENTER:
        case ZYDIS_MNEMONIC_SYSEXIT: case ZYDIS_MNEMONIC_SYSRET:
        case ZYDIS_MNEMONIC_HLT:
        case ZYDIS_MNEMONIC_UD0: case ZYDIS_MNEMONIC_UD1: case ZYDIS_MNEMONIC_UD2:
        case ZYDIS_MNEMONIC_JB:  case ZYDIS_MNEMONIC_JBE: case ZYDIS_MNEMONIC_JCXZ:
        case ZYDIS_MNEMONIC_JECXZ: case ZYDIS_MNEMONIC_JL: case ZYDIS_MNEMONIC_JLE:
        case ZYDIS_MNEMONIC_JNB: case ZYDIS_MNEMONIC_JNBE: case ZYDIS_MNEMONIC_JNL:
        case ZYDIS_MNEMONIC_JNLE: case ZYDIS_MNEMONIC_JNO: case ZYDIS_MNEMONIC_JNP:
        case ZYDIS_MNEMONIC_JNS: case ZYDIS_MNEMONIC_JNZ: case ZYDIS_MNEMONIC_JO:
        case ZYDIS_MNEMONIC_JP:  case ZYDIS_MNEMONIC_JRCXZ: case ZYDIS_MNEMONIC_JS:
        case ZYDIS_MNEMONIC_JZ:
        case ZYDIS_MNEMONIC_LOOP: case ZYDIS_MNEMONIC_LOOPE: case ZYDIS_MNEMONIC_LOOPNE:
            return true;
        default:
            return false;
    }
}

bool IsAcceptableEnding(const ZydisDecodedInstruction& insn,
                        const ZydisDecodedOperand* ops) {
    switch (insn.mnemonic) {
        case ZYDIS_MNEMONIC_RET:
        case ZYDIS_MNEMONIC_SYSCALL:
        case ZYDIS_MNEMONIC_SYSENTER:
            return true;
        case ZYDIS_MNEMONIC_JMP:
        case ZYDIS_MNEMONIC_CALL:
            return insn.operand_count_visible >= 1
                && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER;
        default:
            return false;
    }
}

std::string FormatInsn(const ZydisFormatter& fmt,
                       const ZydisDecodedInstruction& insn,
                       const ZydisDecodedOperand* ops,
                       uint64_t runtimeAddr) {
    char buf[256];
    if (ZYAN_FAILED(ZydisFormatterFormatInstruction(
            &fmt, &insn, ops, insn.operand_count_visible,
            buf, sizeof(buf), runtimeAddr, nullptr))) {
        return "?";
    }
    return std::string(buf);
}

std::string ToLower(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

} // namespace

std::vector<Gadget> ScanImage(const PeImage& img, const Options& opt) {
    std::vector<Gadget> found;
    std::set<std::string> dedup;

    ZydisDecoder decoder;
    ZydisStackWidth sw = img.is64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;
    ZydisMachineMode mm = img.is64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
    ZydisDecoderInit(&decoder, mm, sw);

    ZydisFormatter fmt;
    ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);

    for (const SectionView& sec : img.sections) {
        if (!IsExecutable(sec)) continue;

        const uint8_t* base = img.data.data() + sec.rawOffset;
        size_t size = sec.rawSize;

        for (size_t endPos = 0; endPos < size; endPos++) {
            ZydisDecodedInstruction probe;
            ZydisDecodedOperand probeOps[ZYDIS_MAX_OPERAND_COUNT];
            if (ZYAN_FAILED(ZydisDecoderDecodeFull(
                    &decoder, base + endPos, size - endPos, &probe, probeOps))) {
                continue;
            }
            if (!IsAcceptableEnding(probe, probeOps)) continue;

            size_t endLen = probe.length;
            size_t startMin = (endPos > opt.maxBytes) ? endPos - opt.maxBytes : 0;

            for (size_t start = startMin; start <= endPos; start++) {
                std::vector<GadgetInsn> body;
                size_t pos = start;
                bool valid = true;
                bool reachedEnding = false;

                while (pos <= endPos && body.size() < opt.maxInsn) {
                    ZydisDecodedInstruction d;
                    ZydisDecodedOperand dOps[ZYDIS_MAX_OPERAND_COUNT];
                    if (ZYAN_FAILED(ZydisDecoderDecodeFull(
                            &decoder, base + pos, size - pos, &d, dOps))) {
                        valid = false; break;
                    }

                    if (pos == endPos) {
                        if (d.length != endLen) { valid = false; break; }
                        GadgetInsn gi;
                        gi.text = FormatInsn(fmt, d, dOps, sec.rva + pos);
                        gi.length = static_cast<uint8_t>(d.length);
                        std::memcpy(gi.bytes, base + pos, d.length);
                        body.push_back(std::move(gi));
                        reachedEnding = true;
                        break;
                    }

                    if (pos + d.length > endPos) { valid = false; break; }
                    if (IsControlFlowDisallowedInBody(d.mnemonic)) { valid = false; break; }

                    GadgetInsn gi;
                    gi.text = FormatInsn(fmt, d, dOps, sec.rva + pos);
                    gi.length = static_cast<uint8_t>(d.length);
                    std::memcpy(gi.bytes, base + pos, d.length);
                    body.push_back(std::move(gi));
                    pos += d.length;
                }

                if (!valid || !reachedEnding) continue;
                if (body.empty() || body.size() > opt.maxInsn) continue;

                // Drop the trivial bare-ret (1-byte 0xC3) gadget — but keep
                // `ret imm16`, which is genuinely useful for stack pivoting.
                if (body.size() == 1 &&
                    probe.mnemonic == ZYDIS_MNEMONIC_RET &&
                    body.front().text == "ret") continue;

                Gadget g;
                g.module     = img.moduleName;
                g.section    = sec.name;
                g.fileOffset = sec.rawOffset + static_cast<uint32_t>(start);
                g.rva        = sec.rva + static_cast<uint32_t>(start);
                g.bytes.assign(base + start, base + endPos + endLen);
                g.insns      = std::move(body);

                Classify(g, img.is64);

                if (HasBadByte(g, opt.badBytes)) continue;
                if (g.score < opt.minScore) continue;

                if (opt.resolveSymbols) Annotate(g, img, opt.resolvePdb);

                if (img.hasCfg) {
                    if (opt.onlyCfgTargets && !g.cfgValidTarget) continue;
                    if (opt.excludeCfgTargets && g.cfgValidTarget) continue;
                }

                std::string asmText = AsmText(g);
                std::string key = std::to_string(g.rva) + ":" + asmText;
                if (dedup.count(key)) continue;
                dedup.insert(key);

                if (!opt.filter.empty()) {
                    std::string f = ToLower(opt.filter);
                    std::string hay = ToLower(
                        asmText + " " + g.section + " " +
                        CategoryName(g.category) + " " +
                        SemanticName(g.semantic) + " " +
                        g.nearestSymbol + " " + g.nearestFunction);
                    if (hay.find(f) == std::string::npos) continue;
                }

                found.push_back(std::move(g));
            }
        }
    }

    std::sort(found.begin(), found.end(), [](const Gadget& a, const Gadget& b) {
        if (a.score != b.score) return a.score > b.score;
        return a.rva < b.rva;
    });

    if (opt.limit > 0 && found.size() > opt.limit) found.resize(opt.limit);
    return found;
}

BatchResult ScanDirectory(const std::string& dir, const Options& opt) {
    namespace fs = std::filesystem;
    BatchResult out;

    auto isPe = [](const fs::path& p) {
        auto ext = p.extension().string();
        for (auto& c : ext)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return ext == ".dll" || ext == ".exe" || ext == ".sys"
            || ext == ".cpl" || ext == ".ocx" || ext == ".drv" || ext == ".efi";
    };

    std::vector<fs::path> peFiles;
    try {
        if (opt.recursive) {
            for (auto& e : fs::recursive_directory_iterator(dir))
                if (e.is_regular_file() && isPe(e.path()))
                    peFiles.push_back(e.path());
        } else {
            for (auto& e : fs::directory_iterator(dir))
                if (e.is_regular_file() && isPe(e.path()))
                    peFiles.push_back(e.path());
        }
    } catch (const std::exception& ex) {
        std::cerr << "[-] directory scan failed: " << ex.what() << "\n";
        return out;
    }

    std::sort(peFiles.begin(), peFiles.end());

    std::unordered_map<std::string, size_t> seen;

    Options local = opt;
    local.paths.clear();
    local.directory.clear();
    local.limit = 0; // no per-file limit; we'll trim at the end

    for (const fs::path& p : peFiles) {
        PeImage img;
        if (!LoadPe(p.string(), img)) continue;
        std::cerr << "[+] scanning " << img.moduleName
                  << " (" << img.sections.size() << " sections, "
                  << (img.is64 ? "x64" : "x86") << ")\n";

        std::vector<Gadget> gs = ScanImage(img, local);

        // Within a single PE the same asm sequence can appear at many RVAs
        // (e.g. `syscall` lives in every Nt-stub). For batch ranking we want
        // "how many distinct modules expose this gadget", so dedup per file.
        std::unordered_set<std::string> seenInThisFile;
        for (Gadget& g : gs) {
            std::string key = AsmText(g);
            if (!seenInThisFile.insert(key).second) continue;

            auto it = seen.find(key);
            if (it == seen.end()) {
                seen[key] = out.gadgets.size();
                out.moduleHits.push_back({img.moduleName});
                out.gadgets.push_back(std::move(g));
            } else {
                out.moduleHits[it->second].push_back(img.moduleName);
            }
        }
    }

    std::vector<size_t> idx(out.gadgets.size());
    for (size_t i = 0; i < idx.size(); i++) idx[i] = i;
    std::sort(idx.begin(), idx.end(), [&](size_t a, size_t b) {
        size_t ha = out.moduleHits[a].size();
        size_t hb = out.moduleHits[b].size();
        if (ha != hb) return ha > hb;
        return out.gadgets[a].score > out.gadgets[b].score;
    });

    BatchResult sorted;
    sorted.gadgets.reserve(out.gadgets.size());
    sorted.moduleHits.reserve(out.gadgets.size());
    for (size_t i : idx) {
        sorted.gadgets.push_back(std::move(out.gadgets[i]));
        sorted.moduleHits.push_back(std::move(out.moduleHits[i]));
    }

    if (opt.limit > 0 && sorted.gadgets.size() > opt.limit) {
        sorted.gadgets.resize(opt.limit);
        sorted.moduleHits.resize(opt.limit);
    }

    return sorted;
}

} // namespace rop
