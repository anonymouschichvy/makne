// src/JunkCodeInserter.cpp
#include "JunkCodeInserter.h"
#include <algorithm>

namespace Polymorphic {

JunkCodeInserter::JunkCodeInserter(CryptoRandom& rng) 
    : m_rng(rng), m_density(0.15f) {
    InitializePatterns();
}

void JunkCodeInserter::SetDensity(float density) {
    m_density = std::max(0.0f, std::min(1.0f, density));
}

void JunkCodeInserter::SetPreservedRegisters(const std::vector<X86Register>& regs) {
    m_preservedRegs = regs;
}

void JunkCodeInserter::InitializePatterns() {
    // NOP equivalents (preserve everything)
    m_patterns.push_back({{0x90}, true, false, {}, 1, 5});  // NOP
    m_patterns.push_back({{0x50, 0x58}, true, true, {X86Register::EAX}, 1, 3});  // PUSH EAX; POP EAX
    m_patterns.push_back({{0x53, 0x5B}, true, true, {X86Register::EBX}, 1, 3});  // PUSH EBX; POP EBX
    m_patterns.push_back({{0x51, 0x59}, true, true, {X86Register::ECX}, 1, 3});  // PUSH ECX; POP ECX
    m_patterns.push_back({{0x52, 0x5A}, true, true, {X86Register::EDX}, 1, 3});  // PUSH EDX; POP EDX
    m_patterns.push_back({{0x56, 0x5E}, true, true, {X86Register::ESI}, 1, 3});  // PUSH ESI; POP ESI
    m_patterns.push_back({{0x57, 0x5F}, true, true, {X86Register::EDI}, 1, 3});  // PUSH EDI; POP EDI
    
    // XCHG with self
    m_patterns.push_back({{0x87, 0xC0}, true, false, {}, 1, 3});  // XCHG EAX, EAX
    m_patterns.push_back({{0x87, 0xDB}, true, false, {}, 1, 3});  // XCHG EBX, EBX
    m_patterns.push_back({{0x87, 0xC9}, true, false, {}, 1, 3});  // XCHG ECX, ECX
    m_patterns.push_back({{0x87, 0xD2}, true, false, {}, 1, 3});  // XCHG EDX, EDX
    
    // LEA with zero offset
    m_patterns.push_back({{0x8D, 0x40, 0x00}, true, false, {}, 1, 3});  // LEA EAX, [EAX+0]
    m_patterns.push_back({{0x8D, 0x43, 0x00}, true, false, {}, 1, 3});  // LEA EAX, [EBX+0]
    m_patterns.push_back({{0x8D, 0x64, 0x24, 0x00}, true, false, {}, 1, 3});  // LEA ESP, [ESP+0]
    
    // MOV to same register
    m_patterns.push_back({{0x8B, 0xC0}, true, false, {}, 1, 3});  // MOV EAX, EAX
    m_patterns.push_back({{0x8B, 0xDB}, true, false, {}, 1, 3});  // MOV EBX, EBX
    m_patterns.push_back({{0x89, 0xC0}, true, false, {}, 1, 3});  // MOV EAX, EAX (alt)
    
    // Flag manipulations that cancel out
    m_patterns.push_back({{0xF8, 0xF9, 0xF8}, true, false, {}, 1, 2});  // CLC; STC; CLC
    m_patterns.push_back({{0xF9, 0xF8, 0xF9}, true, false, {}, 1, 2});  // STC; CLC; STC
    m_patterns.push_back({{0xFC, 0xFD, 0xFC}, true, false, {}, 1, 2});  // CLD; STD; CLD
    
    // Complex NOPs
    m_patterns.push_back({{0x40, 0x48}, true, false, {}, 1, 3});  // INC EAX; DEC EAX
    m_patterns.push_back({{0x43, 0x4B}, true, false, {}, 1, 3});  // INC EBX; DEC EBX
    m_patterns.push_back({{0x01, 0xC0, 0x29, 0xC0}, true, false, {X86Register::EAX}, 1, 2});  // ADD EAX, EAX; SUB EAX, EAX
    
    // Multi-byte NOPs
    m_patterns.push_back({{0x66, 0x90}, true, false, {}, 1, 5});  // 2-byte NOP
    m_patterns.push_back({{0x0F, 0x1F, 0x00}, true, false, {}, 1, 4});  // 3-byte NOP
    m_patterns.push_back({{0x0F, 0x1F, 0x40, 0x00}, true, false, {}, 1, 3});  // 4-byte NOP
    m_patterns.push_back({{0x0F, 0x1F, 0x44, 0x00, 0x00}, true, false, {}, 1, 3});  // 5-byte NOP
    m_patterns.push_back({{0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}, true, false, {}, 1, 2});  // 6-byte NOP
    m_patterns.push_back({{0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00}, true, false, {}, 1, 2});  // 7-byte NOP
    
    // Push/Pop flags
    m_patterns.push_back({{0x9C, 0x9D}, true, true, {}, 1, 2});  // PUSHFD; POPFD
    
    // Fake conditional jumps (always taken or never taken)
    m_patterns.push_back({{0xEB, 0x00}, true, false, {}, 1, 2});  // JMP +0
    m_patterns.push_back({{0x74, 0x00, 0xEB, 0x01, 0x90}, true, false, {}, 1, 2});  // JZ +0; JMP +1; NOP
    
    // Opaque predicates (always true/false conditions)
    m_patterns.push_back({{0x31, 0xC0, 0x40, 0x74, 0x00}, true, false, {X86Register::EAX}, 1, 2});  // XOR EAX,EAX; INC EAX; JZ +0 (never taken)
    m_patterns.push_back({{0x31, 0xC0, 0x75, 0x00}, true, false, {X86Register::EAX}, 1, 2});  // XOR EAX,EAX; JNZ +0 (never taken)
    
    // Fake function calls (to next instruction)
    m_patterns.push_back({{0xE8, 0x00, 0x00, 0x00, 0x00}, true, true, {}, 1, 2});  // CALL $+5
    
    // Junk math operations that result in no change
    m_patterns.push_back({{0x83, 0xE0, 0xFF}, true, false, {X86Register::EAX}, 1, 2});  // AND EAX, 0xFFFFFFFF (no change)
    m_patterns.push_back({{0x83, 0xC8, 0x00}, true, false, {X86Register::EAX}, 1, 2});  // OR EAX, 0 (no change)
}

JunkCodeInserter::JunkPattern JunkCodeInserter::SelectJunk(bool /*afterBranch*/, 
    bool /*beforeBranch*/) {
    
    std::vector<size_t> candidates;
    
    for (size_t i = 0; i < m_patterns.size(); ++i) {
        const auto& pattern = m_patterns[i];
        
        // Skip patterns that clobber preserved registers
        bool safe = true;
        for (auto reg : pattern.clobberedRegs) {
            if (std::find(m_preservedRegs.begin(), m_preservedRegs.end(), reg) 
                != m_preservedRegs.end()) {
                safe = false;
                break;
            }
        }
        
        if (safe) {
            candidates.push_back(i);
        }
    }
    
    if (candidates.empty()) {
        return m_patterns[0];  // Return NOP
    }
    
    size_t choice = m_rng.Next(static_cast<uint32_t>(candidates.size()));
    return m_patterns[candidates[choice]];
}

std::vector<uint8_t> JunkCodeInserter::GenerateRandomJunk() {
    std::vector<uint8_t> junk;
    
    // Generate random instruction sequences
    int length = m_rng.Next(2, 8);
    
    for (int i = 0; i < length; ++i) {
        uint8_t choice = m_rng.Next(10);
        
        switch (choice) {
            case 0: junk.push_back(0x90); break;  // NOP
            case 1: junk.push_back(0x50); junk.push_back(0x58); break;  // PUSH/POP EAX
            case 2: junk.push_back(0x87); junk.push_back(0xC0); break;  // XCHG EAX, EAX
            case 3: junk.push_back(0x40); junk.push_back(0x48); break;  // INC/DEC EAX
            case 4: junk.push_back(0xF8); break;  // CLC
            case 5: junk.push_back(0xF9); break;  // STC
            case 6: junk.push_back(0xFC); break;  // CLD
            case 7: junk.push_back(0xFD); break;  // STD
            case 8: junk.push_back(0x66); junk.push_back(0x90); break;  // 2-byte NOP
            case 9: junk.push_back(0xEB); junk.push_back(0x00); break;  // JMP +0
        }
    }
    
    return junk;
}

std::vector<uint8_t> JunkCodeInserter::Insert(const std::vector<uint8_t>& code) {
    std::vector<uint8_t> result;
    result.reserve(code.size() * 2);
    
    size_t i = 0;
    while (i < code.size()) {
        // Copy original byte
        result.push_back(code[i]);
        
        // Decide whether to insert junk
        if (m_rng.Next(100) < static_cast<uint32_t>(m_density * 100)) {
            auto pattern = SelectJunk(false, false);
            
            // Multiple insertions
            int count = m_rng.Next(pattern.minInsertions, pattern.maxInsertions + 1);
            for (int j = 0; j < count; ++j) {
                result.insert(result.end(), pattern.code.begin(), pattern.code.end());
            }
        }
        
        // Insert junk after specific instructions
        if (code[i] == 0xC3 || code[i] == 0xC2) {  // RET
            auto pattern = SelectJunk(true, false);
            result.insert(result.end(), pattern.code.begin(), pattern.code.end());
        }
        
        ++i;
    }
    
    return result;
}

void JunkCodeInserter::AddPattern(const JunkPattern& pattern) {
    m_patterns.push_back(pattern);
}

} // namespace Polymorphic