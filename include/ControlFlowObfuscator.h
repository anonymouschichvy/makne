// src/ControlFlowObfuscator.h
#pragma once
#include <vector>
#include <cstdint>
#include <map>
#include "Utils.h"

namespace Polymorphic {

class ControlFlowObfuscator {
public:
    struct OpaquePredicate {
        std::vector<uint8_t> code;
        bool alwaysTrue;
        uint32_t fallThroughAddr;
        uint32_t branchAddr;
    };

    ControlFlowObfuscator(CryptoRandom& rng);
    
    // Apply control flow obfuscation
    std::vector<uint8_t> Obfuscate(const std::vector<uint8_t>& code,
        uint32_t baseAddress);
    
    // Set obfuscation level (1-5)
    void SetLevel(int level);
    
    // Enable specific techniques
    void EnableIndirectJumps(bool enable);
    void EnableOpaquePredicates(bool enable);
    void EnableCallStackSpaghetti(bool enable);
    void EnableExceptionBased(bool enable);
    
private:
    CryptoRandom& m_rng;
    int m_level;
    bool m_indirectJumps;
    bool m_opaquePredicates;
    bool m_callStackSpaghetti;
    bool m_exceptionBased;
    
    struct BasicBlock {
        uint32_t id;
        uint32_t startAddr;
        uint32_t endAddr;
        std::vector<uint8_t> code;
        std::vector<uint32_t> successors;
        bool isEntry;
        bool isExit;
    };

    // Jump table for indirect jumps
    std::map<uint32_t, uint32_t> m_jumpTable;
    
    // Generate opaque predicate
    OpaquePredicate GenerateOpaquePredicate(uint32_t fallThrough,
        uint32_t branch);
    
    // Transform direct jumps to indirect
    std::vector<uint8_t> MakeIndirectJump(uint32_t target);
    
    // Create jump table
    std::vector<uint8_t> CreateJumpTable();
    
    // Flatten control flow
    std::vector<uint8_t> FlattenFlow(const std::vector<uint8_t>& code,
        uint32_t baseAddress);
    
    // Add dispatcher
    std::vector<uint8_t> AddDispatcher(const std::vector<BasicBlock>& blocks);
    
    std::vector<BasicBlock> IdentifyBlocks(const std::vector<uint8_t>& code,
        uint32_t baseAddress);
};

} // namespace Polymorphic