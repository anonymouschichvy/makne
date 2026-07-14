#include "CodeReorderer.h"
#include <algorithm>
#include <cstring>
#include <numeric>
#include <map>
#include <set>
#include <random>
#include <iostream>

namespace Polymorphic {

CodeReorderer::CodeReorderer(CryptoRandom& rng) : m_rng(rng), m_strategy("random") {}

void CodeReorderer::SetStrategy(const std::string& strategy) {
    m_strategy = strategy;
}

void CodeReorderer::Run(InstructionBlock& block, ArchContext& ctx) {
    if (block.empty()) return;
    if (ctx.functionBoundaries.empty()) {
        std::cout << "[DEBUG] CodeReorderer: No function boundaries available, skipping." << std::endl;
        return;
    }

    uint64_t sectionBase = block.empty() ? 0 : block[0].rva;
    uint64_t sectionEnd  = block.empty() ? 0 : block.back().rva + block.back().original_bytes.size();

    // Build sorted, merged function boundaries within our section
    std::vector<std::pair<uint64_t, uint64_t>> mergedFuncs;
    {
        std::vector<std::pair<uint64_t, uint64_t>> funcs;
        for (auto& [beg, end] : ctx.functionBoundaries) {
            uint64_t b = beg, e = end;
            if (b >= sectionBase && e <= sectionEnd && e > b) {
                funcs.push_back({b, e});
            }
        }
        std::sort(funcs.begin(), funcs.end());
        for (auto& f : funcs) {
            if (!mergedFuncs.empty() && f.first < mergedFuncs.back().second) {
                mergedFuncs.back().second = std::max(mergedFuncs.back().second, f.second);
            } else {
                mergedFuncs.push_back(f);
            }
        }
    }

    if (mergedFuncs.size() < 2) {
        std::cout << "[DEBUG] CodeReorderer: Less than 2 functions in section, skipping." << std::endl;
        return;
    }

    // Fast function index lookup: binary search into mergedFuncs
    auto funcIndexForRVA = [&](uint64_t rva) -> int {
        int lo = 0, hi = static_cast<int>(mergedFuncs.size()) - 1;
        while (lo <= hi) {
            int mid = (lo + hi) / 2;
            if (rva < mergedFuncs[mid].first) hi = mid - 1;
            else if (rva >= mergedFuncs[mid].second) lo = mid + 1;
            else return mid;
        }
        return -1;
    };

    // Partition instructions into groups (functions and gaps)
    struct FunctionGroup {
        uint64_t originalBegin, originalEnd;
        std::vector<IRInstruction> instructions;
        bool isGap = false;
        bool canShuffle = true;
        int funcIdx = -1;
    };

    std::vector<FunctionGroup> groups;
    size_t instIdx = 0;

    for (size_t fi = 0; fi <= mergedFuncs.size(); ++fi) {
        if (fi < mergedFuncs.size()) {
            // Gap before function fi
            uint64_t gapEnd = mergedFuncs[fi].first;
            if (instIdx < block.size() && block[instIdx].rva < gapEnd) {
                FunctionGroup gap;
                gap.originalBegin = block[instIdx].rva;
                gap.isGap = true;
                gap.canShuffle = false;
                while (instIdx < block.size() && block[instIdx].rva < gapEnd)
                    gap.instructions.push_back(block[instIdx++]);
                gap.originalEnd = gap.instructions.empty() ? gap.originalBegin :
                    gap.instructions.back().rva + gap.instructions.back().original_bytes.size();
                if (!gap.instructions.empty()) groups.push_back(gap);
            }
            // Function fi
            uint64_t funcEnd = mergedFuncs[fi].second;
            if (instIdx < block.size() && block[instIdx].rva < funcEnd) {
                FunctionGroup fg;
                fg.originalBegin = block[instIdx].rva;
                fg.funcIdx = static_cast<int>(fi);
                while (instIdx < block.size() && block[instIdx].rva < funcEnd)
                    fg.instructions.push_back(block[instIdx++]);
                fg.originalEnd = fg.instructions.empty() ? fg.originalBegin :
                    fg.instructions.back().rva + fg.instructions.back().original_bytes.size();
                if (!fg.instructions.empty()) groups.push_back(fg);
            }
        } else {
            // Tail gap
            if (instIdx < block.size()) {
                FunctionGroup gap;
                gap.originalBegin = block[instIdx].rva;
                gap.isGap = true;
                gap.canShuffle = false;
                while (instIdx < block.size())
                    gap.instructions.push_back(block[instIdx++]);
                gap.originalEnd = gap.instructions.empty() ? gap.originalBegin :
                    gap.instructions.back().rva + gap.instructions.back().original_bytes.size();
                if (!gap.instructions.empty()) groups.push_back(gap);
            }
        }
    }

    // Build groupIndex: funcIdx -> group index (for function groups)
    std::map<int, size_t> funcIdxToGroupIdx;
    for (size_t gi = 0; gi < groups.size(); ++gi) {
        if (!groups[gi].isGap && groups[gi].funcIdx >= 0) {
            funcIdxToGroupIdx[groups[gi].funcIdx] = gi;
        }
    }

    // Mark entry group, gaps, functions with exception handlers, functions with indirect jumps, and functions with size mismatches (gaps) as fixed
    for (auto& g : groups) {
        bool hasIndirectJmp = false;
        bool hasSizeMismatch = false;
        if (!g.isGap) {
            size_t instsSize = 0;
            for (const auto& inst : g.instructions) {
                instsSize += inst.original_bytes.size();
                if (inst.raw.mnemonic == ZYDIS_MNEMONIC_JMP) {
                    if (inst.raw.operand_count > 0) {
                        auto opType = inst.operands[0].type;
                        if (opType == ZYDIS_OPERAND_TYPE_REGISTER || opType == ZYDIS_OPERAND_TYPE_MEMORY) {
                            hasIndirectJmp = true;
                        }
                    }
                }
            }
            if (g.funcIdx >= 0 && g.funcIdx < static_cast<int>(mergedFuncs.size())) {
                uint64_t originalSize = mergedFuncs[g.funcIdx].second - mergedFuncs[g.funcIdx].first;
                if (instsSize != originalSize) {
                    hasSizeMismatch = true;
                }
            }
        }

        if (g.isGap || g.originalBegin == sectionBase || 
            ctx.exceptionHandlerFuncRVAs.count(g.originalBegin) > 0 || 
            hasIndirectJmp || hasSizeMismatch) {
            g.canShuffle = false;
        }
    }

    // Phase 1: fixpoint propagation for cross-function and unresolvable short branches
    {
        bool changed = true;
        while (changed) {
            changed = false;
            for (size_t gi = 0; gi < groups.size(); ++gi) {
                if (groups[gi].isGap) continue;
                for (const auto& inst : groups[gi].instructions) {
                    if (inst.branch_size != 1 || inst.branch_target_rva == 0) continue;

                    bool targetValid = ctx.validInstructionRVAs.count(inst.branch_target_rva) > 0;
                    if (!targetValid) {
                        if (groups[gi].canShuffle) { groups[gi].canShuffle = false; changed = true; }
                        continue;
                    }

                    int targetFuncIdx = funcIndexForRVA(inst.branch_target_rva);
                    if (targetFuncIdx != groups[gi].funcIdx) {
                        if (groups[gi].canShuffle) { groups[gi].canShuffle = false; changed = true; }
                        auto it = funcIdxToGroupIdx.find(targetFuncIdx);
                        if (it != funcIdxToGroupIdx.end() && groups[it->second].canShuffle) {
                            groups[it->second].canShuffle = false; changed = true;
                        }
                    }
                }
            }
        }
    }

    // Phase 2: Range interval marking.
    // For every fixed group G with a short-branch target T, ALL groups in the original
    // position range [min(G.begin,T), max(G.end,T)] must be fixed. Otherwise a shuffled
    // group between G and T would change the relative distance and corrupt the branch.
    // We mark groups in range and repeat until stable.
    {
        bool changed = true;
        while (changed) {
            changed = false;
            for (size_t gi = 0; gi < groups.size(); ++gi) {
                if (groups[gi].canShuffle) continue; // only process fixed groups
                for (const auto& inst : groups[gi].instructions) {
                    if (inst.branch_size != 1 || inst.branch_target_rva == 0) continue;

                    uint64_t tgt = inst.branch_target_rva;
                    uint64_t lo = std::min(groups[gi].originalBegin, tgt);
                    uint64_t hi = std::max(groups[gi].originalEnd, tgt);

                    // Mark all groups whose range overlaps [lo, hi] as fixed
                    for (size_t hj = 0; hj < groups.size(); ++hj) {
                        if (!groups[hj].canShuffle) continue;
                        // Check overlap: [groups[hj].begin, groups[hj].end) overlaps [lo, hi]
                        if (groups[hj].originalBegin <= hi && groups[hj].originalEnd > lo) {
                            groups[hj].canShuffle = false;
                            changed = true;
                        }
                    }
                }
            }
        }
    }

    // Collect shuffleable and fixed
    std::vector<size_t> shuffleableIdx, fixedIdx;
    for (size_t gi = 0; gi < groups.size(); ++gi) {
        if (groups[gi].canShuffle) shuffleableIdx.push_back(gi);
        else fixedIdx.push_back(gi);
    }

    if (shuffleableIdx.size() < 2) {
        std::cout << "[DEBUG] CodeReorderer: Not enough shuffleable functions (<2), skipping." << std::endl;
        return;
    }

    // Group shuffleable indices by group size
    std::map<size_t, std::vector<size_t>> sizeToShuffleableIdx;
    for (size_t idx : shuffleableIdx) {
        size_t gSize = 0;
        for (const auto& inst : groups[idx].instructions) {
            gSize += inst.original_bytes.size();
        }
        sizeToShuffleableIdx[gSize].push_back(idx);
    }

    // Overwrite groups array
    std::vector<FunctionGroup> newGroups = groups;
    std::mt19937 g_mt(m_rng.Next());
    
    size_t totalShuffled = 0;
    for (auto& [gSize, idxList] : sizeToShuffleableIdx) {
        if (idxList.size() < 2) continue;
        
        std::vector<size_t> shuffledList = idxList;
        std::shuffle(shuffledList.begin(), shuffledList.end(), g_mt);
        
        for (size_t i = 0; i < idxList.size(); ++i) {
            newGroups[idxList[i]] = groups[shuffledList[i]];
        }
        totalShuffled += idxList.size();
    }
    
    std::cout << "[DEBUG] CodeReorderer: " << totalShuffled
              << " functions shuffled in size-matched slots, " 
              << (groups.size() - totalShuffled) << " fixed/unshuffled." << std::endl;

    InstructionBlock newBlock;
    newBlock.reserve(block.size());
    for (const auto& g : newGroups) {
        newBlock.insert(newBlock.end(), g.instructions.begin(), g.instructions.end());
    }

    if (newBlock.size() != block.size()) {
        std::cout << "[WARN] CodeReorderer: Instruction count mismatch (" << newBlock.size()
                  << " vs " << block.size() << "). Reverting." << std::endl;
        return;
    }

    block = std::move(newBlock);
}

bool CodeReorderer::ValidateOutput(const InstructionBlock& block) const {
    return !block.empty();
}

} // namespace Polymorphic
