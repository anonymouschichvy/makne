// src/CodeReorderer.h
#pragma once
#include <vector>
#include <cstdint>
#include <memory>
#include "Utils.h"

namespace Polymorphic {

class CodeReorderer {
public:
    struct BasicBlock {
        uint32_t startAddress;
        uint32_t endAddress;
        std::vector<uint8_t> code;
        std::vector<uint32_t> predecessors;
        std::vector<uint32_t> successors;
        bool isEntry;
        bool isExit;
        size_t originalIndex;
    };

    CodeReorderer(CryptoRandom& rng);
    
    // Analyze and reorder code blocks
    std::vector<uint8_t> Reorder(const std::vector<uint8_t>& code,
        uint32_t baseAddress);
    
    // Set reordering strategy
    void SetStrategy(const std::string& strategy); // "random", "size", "frequency"
    
private:
    CryptoRandom& m_rng;
    std::string m_strategy;
    
    // Block identification
    std::vector<BasicBlock> IdentifyBlocks(const std::vector<uint8_t>& code,
        uint32_t baseAddress);
    
    // Disassemble to find block boundaries
    size_t GetInstructionLength(const std::vector<uint8_t>& code, size_t pos);
    
    // Check if instruction is a branch
    bool IsBranch(const std::vector<uint8_t>& code, size_t pos, 
        uint32_t& target, bool& isConditional);
    
    // Reorder blocks
    std::vector<BasicBlock> ShuffleBlocks(
        const std::vector<BasicBlock>& blocks);
    
    // Rebuild code with reordered blocks
    std::vector<uint8_t> RebuildCode(const std::vector<BasicBlock>& blocks,
        uint32_t baseAddress);
    
    // Fix jump targets after reordering
    void FixJumpTargets(std::vector<uint8_t>& code, 
        const std::vector<BasicBlock>& oldBlocks,
        const std::vector<BasicBlock>& newBlocks,
        uint32_t baseAddress);
};

} // namespace Polymorphic