// src/ControlFlowObfuscator.cpp
#include "ControlFlowObfuscator.h"
#include <algorithm>

namespace Polymorphic {

ControlFlowObfuscator::ControlFlowObfuscator(CryptoRandom& rng)
    : m_rng(rng), m_level(3), m_indirectJumps(true),
      m_opaquePredicates(true), m_callStackSpaghetti(false),
      m_exceptionBased(false) {}

void ControlFlowObfuscator::SetLevel(int level) {
    m_level = std::max(1, std::min(5, level));
}

void ControlFlowObfuscator::EnableIndirectJumps(bool enable) {
    m_indirectJumps = enable;
}

void ControlFlowObfuscator::EnableOpaquePredicates(bool enable) {
    m_opaquePredicates = enable;
}

ControlFlowObfuscator::OpaquePredicate 
ControlFlowObfuscator::GenerateOpaquePredicate(uint32_t fallThrough,
    uint32_t branch) {
    
    OpaquePredicate pred;
    pred.fallThroughAddr = fallThrough;
    pred.branchAddr = branch;
    
    // Multiple opaque predicate patterns
    uint32_t choice = m_rng.Next(5);
    
    switch (choice) {
        case 0: {
            // x*x >= 0 (always true for real x)
            pred.alwaysTrue = true;
            pred.code = {
                0x31, 0xC0,        // XOR EAX, EAX
                0x0F, 0xAF, 0xC0,  // IMUL EAX, EAX
                0x85, 0xC0,        // TEST EAX, EAX
                0x79                // JNS (jump if not signed - always taken)
            };
            break;
        }
        case 1: {
            // (x & 1) == 0 || (x & 1) == 1 (always true)
            pred.alwaysTrue = true;
            pred.code = {
                0x31, 0xC0,        // XOR EAX, EAX
                0xA8, 0x01,        // TEST AL, 1
                0x74                // JZ (always taken for even numbers, but we control x)
            };
            break;
        }
        case 2: {
            // x*2 == x+x (always true)
            pred.alwaysTrue = true;
            pred.code = {
                0xB8, 0x10, 0x00, 0x00, 0x00,  // MOV EAX, 0x10
                0x8D, 0x14, 0x00,              // LEA EDX, [EAX+EAX]
                0xD1, 0xE0,                    // SHL EAX, 1
                0x39, 0xD0,                    // CMP EAX, EDX
                0x74                           // JE (always equal)
            };
            break;
        }
        case 3: {
            // x^y^y == x (always true)
            pred.alwaysTrue = true;
            pred.code = {
                0xB8, 0x42, 0x00, 0x00, 0x00,  // MOV EAX, 0x42
                0xB9, 0x13, 0x37, 0x00, 0x00,  // MOV ECX, 0x3713
                0x31, 0xC8,                    // XOR EAX, ECX
                0x31, 0xC8,                    // XOR EAX, ECX
                0x3D, 0x42, 0x00, 0x00, 0x00,  // CMP EAX, 0x42
                0x74                           // JE (always equal)
            };
            break;
        }
        case 4: {
            // Complex arithmetic identity
            pred.alwaysTrue = true;
            pred.code = {
                0xB8, 0x05, 0x00, 0x00, 0x00,  // MOV EAX, 5
                0x6B, 0xC0, 0x03,              // IMUL EAX, EAX, 3
                0x83, 0xE8, 0x0F,              // SUB EAX, 15
                0x85, 0xC0,                    // TEST EAX, EAX
                0x74                           // JE (always zero)
            };
            break;
        }
    }
    
    // Add displacement byte for conditional jump
    pred.code.push_back(0x00);  // Placeholder
    
    return pred;
}

std::vector<uint8_t> ControlFlowObfuscator::MakeIndirectJump(uint32_t target) {
    std::vector<uint8_t> code;
    
    // Method 1: Push target; RET
    code.push_back(0x68);  // PUSH imm32
    code.push_back(static_cast<uint8_t>(target & 0xFF));
    code.push_back(static_cast<uint8_t>((target >> 8) & 0xFF));
    code.push_back(static_cast<uint8_t>((target >> 16) & 0xFF));
    code.push_back(static_cast<uint8_t>((target >> 24) & 0xFF));
    code.push_back(0xC3);  // RET
    
    return code;
}

std::vector<ControlFlowObfuscator::BasicBlock> 
ControlFlowObfuscator::IdentifyBlocks(const std::vector<uint8_t>& /*code*/,
    uint32_t /*baseAddress*/) {
    
    std::vector<BasicBlock> blocks;
    // Similar to CodeReorderer implementation
    // Simplified for brevity
    
    return blocks;
}

std::vector<uint8_t> ControlFlowObfuscator::FlattenFlow(
    const std::vector<uint8_t>& code, uint32_t baseAddress) {
    
    // Control flow flattening implementation
    // Transforms structured code into switch-based dispatcher
    
    auto blocks = IdentifyBlocks(code, baseAddress);
    if (blocks.size() < 3) return code;
    
    std::vector<uint8_t> result;
    
    // Add state variable initialization
    result.push_back(0xB8);  // MOV EAX, entry_block_id
    result.push_back(0x00);
    result.push_back(0x00);
    result.push_back(0x00);
    result.push_back(0x00);
    
    // Dispatcher loop
    result.push_back(0x50);  // PUSH EAX (save state)
    
    // Switch on state
    result.push_back(0x58);  // POP EAX
    result.push_back(0xFF);  // JMP [EAX*4 + dispatch_table]
    result.push_back(0x24);
    result.push_back(0x85);
    // ... dispatch table address
    
    return result;
}

std::vector<uint8_t> ControlFlowObfuscator::Obfuscate(const std::vector<uint8_t>& code,
    uint32_t baseAddress) {
    
    std::vector<uint8_t> result = code;
    
    if (m_level >= 4) {
        result = FlattenFlow(result, baseAddress);
    }
    
    // Transform direct jumps
    if (m_indirectJumps) {
        for (size_t i = 0; i < result.size() - 4; ++i) {
            if (result[i] == 0xE9) {  // JMP rel32
                int32_t offset = *reinterpret_cast<int32_t*>(&result[i + 1]);
                uint32_t target = static_cast<uint32_t>(i + 5 + offset);
                
                // Replace with indirect jump
                auto indirect = MakeIndirectJump(baseAddress + target);
                
                // Simple replacement (real implementation needs relocation)
                for (size_t j = 0; j < 5 && j < indirect.size(); ++j) {
                    if (i + j < result.size()) {
                        result[i + j] = indirect[j];
                    }
                }
            }
        }
    }
    
    // Insert opaque predicates
    if (m_opaquePredicates && m_level >= 2) {
        // Find locations for opaque predicates
        for (size_t i = 0; i < result.size(); ++i) {
            if (result[i] == 0xEB && i + 1 < result.size()) {  // JMP short
                // Replace with opaque predicate
                int8_t offset = static_cast<int8_t>(result[i + 1]);
                uint32_t target = static_cast<uint32_t>(i + 2 + offset);
                
                auto pred = GenerateOpaquePredicate(target, target);
                
                // Insert predicate code
                // (Simplified - real implementation needs proper integration)
            }
        }
    }
    
    return result;
}

} // namespace Polymorphic