// src/InstructionSubstitutor.cpp
#include "InstructionSubstitutor.h"
#include <algorithm>

namespace Polymorphic {

InstructionSubstitutor::InstructionSubstitutor(CryptoRandom& rng) : m_rng(rng) {
    LoadDefaultRules();
}

void InstructionSubstitutor::LoadDefaultRules() {
    AddArithmeticRules();
    AddLogicalRules();
    AddMoveRules();
    AddStackRules();
    AddNOPRules();
}

void InstructionSubstitutor::AddArithmeticRules() {
    // ADD EAX, imm32 -> LEA EAX, [EAX + imm32]
    m_rules.push_back({
        {0x05},  // ADD EAX, imm32
        {
            {0x8D, 0x80},  // LEA EAX, [EAX + imm32] (needs displacement)
            {0x83, 0xC0},  // ADD EAX, imm8
            {0x81, 0xC0}   // ADD EAX, imm32 (alternative encoding)
        },
        1, true, 0xF8, nullptr
    });
    
    // INC reg -> ADD reg, 1 / SUB reg, -1
    m_rules.push_back({
        {0x40},  // INC r32
        {
            {0x83, 0xC0, 0x01},  // ADD r32, 1
            {0x05, 0x01, 0x00, 0x00, 0x00},  // ADD EAX, 1
            {0x8D, 0x40, 0x01},  // LEA EAX, [EAX+1]
            {0x8D, 0x41, 0x01},  // LEA EAX, [ECX+1]
            {0x8D, 0x42, 0x01}   // LEA EAX, [EDX+1]
        },
        1, false, 0, nullptr
    });
    
    // DEC reg -> SUB reg, 1
    m_rules.push_back({
        {0x48},  // DEC r32
        {
            {0x83, 0xE8, 0x01},  // SUB r32, 1
            {0x2D, 0x01, 0x00, 0x00, 0x00},  // SUB EAX, 1
            {0x8D, 0x40, 0xFF}   // LEA EAX, [EAX-1]
        },
        1, false, 0, nullptr
    });
    
    // NEG reg -> NOT reg; INC reg
    m_rules.push_back({
        {0xF7, 0xD8},  // NEG EAX
        {
            {0xF7, 0xD0, 0x40},  // NOT EAX; INC EAX
            {0x83, 0xE8, 0x00, 0x48, 0x40},  // Complex variant
            {0x2B, 0xC0, 0xF7, 0xD8}  // SUB EAX, EAX; NEG EAX
        },
        2, false, 0, nullptr
    });
    
    // XOR reg, reg -> SUB reg, reg / MOV reg, 0 / AND reg, 0
    m_rules.push_back({
        {0x31, 0xC0},  // XOR EAX, EAX
        {
            {0x29, 0xC0},  // SUB EAX, EAX
            {0x2B, 0xC0},  // SUB EAX, EAX (alternative)
            {0xB8, 0x00, 0x00, 0x00, 0x00},  // MOV EAX, 0
            {0x83, 0xE0, 0x00},  // AND EAX, 0
            {0x25, 0x00, 0x00, 0x00, 0x00}   // AND EAX, imm32
        },
        2, false, 0, nullptr
    });
}

void InstructionSubstitutor::AddLogicalRules() {
    // TEST reg, reg -> OR reg, reg / AND reg, reg
    m_rules.push_back({
        {0x85, 0xC0},  // TEST EAX, EAX
        {
            {0x09, 0xC0},  // OR EAX, EAX
            {0x0B, 0xC0},  // OR EAX, EAX (alternative)
            {0x21, 0xC0},  // AND EAX, EAX
            {0x23, 0xC0}   // AND EAX, EAX (alternative)
        },
        2, false, 0, nullptr
    });
    
    // CMP reg, 0 -> TEST reg, reg
    m_rules.push_back({
        {0x83, 0xF8, 0x00},  // CMP EAX, 0 (imm8)
        {
            {0x85, 0xC0},  // TEST EAX, EAX
            {0x3D, 0x00, 0x00, 0x00, 0x00},  // CMP EAX, imm32
            {0xF7, 0xC0, 0x00, 0x00, 0x00, 0x00}  // TEST EAX, imm32
        },
        3, false, 0, nullptr
    });
}

void InstructionSubstitutor::AddMoveRules() {
    // MOV reg, imm32 -> PUSH imm32; POP reg
    m_rules.push_back({
        {0xB8},  // MOV r32, imm32
        {
            {0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0x58},  // PUSH imm32; POP EAX
            {0x6A, 0x00, 0x58},  // PUSH 0; POP EAX (for zero)
            {0x31, 0xC0, 0x05},  // XOR EAX, EAX; ADD EAX, imm32
            {0x29, 0xC0, 0x05}   // SUB EAX, EAX; ADD EAX, imm32
        },
        1, true, 0xF8, nullptr
    });
    
    // MOV reg, reg -> PUSH reg; POP reg / XCHG reg, reg; XCHG reg, reg
    m_rules.push_back({
        {0x89, 0xC0},  // MOV EAX, EAX (NOP)
        {
            {0x50, 0x58},  // PUSH EAX; POP EAX
            {0x87, 0xC0, 0x87, 0xC0},  // XCHG EAX, EAX; XCHG EAX, EAX
            {0x8B, 0xC0},  // MOV EAX, EAX (alternative)
            {0x8D, 0x00, 0x00, 0x00, 0x00, 0x00}  // LEA EAX, [EAX]
        },
        2, false, 0, nullptr
    });
    
    // LEA reg, [reg] -> MOV reg, reg
    m_rules.push_back({
        {0x8D, 0x00},  // LEA EAX, [EAX]
        {
            {0x8B, 0xC0},  // MOV EAX, EAX
            {0x89, 0xC0},  // MOV EAX, EAX (alternative)
            {0x87, 0xC0}   // XCHG EAX, EAX
        },
        2, false, 0, nullptr
    });
}

void InstructionSubstitutor::AddStackRules() {
    // PUSH reg -> SUB ESP, 4; MOV [ESP], reg
    m_rules.push_back({
        {0x50},  // PUSH EAX
        {
            {0x83, 0xEC, 0x04, 0x89, 0x04, 0x24},  // SUB ESP, 4; MOV [ESP], EAX
            {0x83, 0xEC, 0x04, 0x50, 0x8F, 0x00},  // Alternative
            {0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00, 0x83, 0xEC, 0x04}  // Complex
        },
        1, false, 0, nullptr
    });
    
    // POP reg -> MOV reg, [ESP]; ADD ESP, 4
    m_rules.push_back({
        {0x58},  // POP EAX
        {
            {0x8B, 0x04, 0x24, 0x83, 0xC4, 0x04},  // MOV EAX, [ESP]; ADD ESP, 4
            {0x87, 0x04, 0x24, 0x83, 0xC4, 0x04}   // XCHG EAX, [ESP]; ADD ESP, 4
        },
        1, false, 0, nullptr
    });
}

void InstructionSubstitutor::AddNOPRules() {
    // NOP (0x90) -> equivalent sequences
    m_rules.push_back({
        {0x90},
        {
            {0x50, 0x58},  // PUSH EAX; POP EAX
            {0x53, 0x5B},  // PUSH EBX; POP EBX
            {0x51, 0x59},  // PUSH ECX; POP ECX
            {0x52, 0x5A},  // PUSH EDX; POP EDX
            {0x56, 0x5E},  // PUSH ESI; POP ESI
            {0x57, 0x5F},  // PUSH EDI; POP EDI
            {0x87, 0xC0},  // XCHG EAX, EAX
            {0x87, 0xDB},  // XCHG EBX, EBX
            {0x8D, 0x40, 0x00},  // LEA EAX, [EAX+0]
            {0x8D, 0x64, 0x24, 0x00},  // LEA ESP, [ESP+0]
            {0x8B, 0xC0},  // MOV EAX, EAX
            {0x8B, 0xDB},  // MOV EBX, EBX
            {0x01, 0xC0, 0x29, 0xC0},  // ADD EAX, EAX; SUB EAX, EAX
            {0x40, 0x48},  // INC EAX; DEC EAX
            {0xF8, 0xF9, 0xF8},  // CLC; STC; CLC
            {0x9C, 0x9D},  // PUSHFD; POPFD
            {0x66, 0x90},  // 2-byte NOP
            {0x0F, 0x1F, 0x00},  // 3-byte NOP
            {0x0F, 0x1F, 0x40, 0x00},  // 4-byte NOP
            {0x0F, 0x1F, 0x44, 0x00, 0x00},  // 5-byte NOP
            {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00},  // 6-byte NOP
            {0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00},  // 7-byte NOP
            {0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},  // 8-byte NOP
            {0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},  // 9-byte NOP
            {0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}  // 10-byte NOP
        },
        1, false, 0, nullptr
    });
}

bool InstructionSubstitutor::MatchPattern(const std::vector<uint8_t>& code, 
    size_t pos, const SubstitutionRule& rule) {
    if (pos + rule.patternLength > code.size()) return false;
    
    for (size_t i = 0; i < rule.pattern.size(); ++i) {
        if (code[pos + i] != rule.pattern[i]) return false;
    }
    
    if (rule.requiresModRM && rule.pattern.size() < rule.patternLength) {
        uint8_t modRM = code[pos + rule.pattern.size()];
        if ((modRM & rule.modRMMask) != (rule.pattern.back() & rule.modRMMask)) {
            return false;
        }
    }
    
    if (rule.validator && !rule.validator(code, pos)) return false;
    
    return true;
}

void InstructionSubstitutor::ApplySubstitution(std::vector<uint8_t>& code, 
    size_t pos, const std::vector<uint8_t>& replacement) {
    // Replace instruction with alternative
    size_t originalLen = 1;  // Simplified - real implementation needs full decoder
    
    // Find matching rule to get original length
    for (const auto& rule : m_rules) {
        if (MatchPattern(code, pos, rule)) {
            originalLen = rule.patternLength;
            break;
        }
    }
    
    // Replace bytes
    for (size_t i = 0; i < replacement.size() && (pos + i) < code.size(); ++i) {
        if (replacement[i] != 0xFF) {  // 0xFF means keep original
            code[pos + i] = replacement[i];
        }
    }
    
    // Pad with NOPs if replacement is shorter
    if (replacement.size() < originalLen) {
        for (size_t i = replacement.size(); i < originalLen; ++i) {
            if (pos + i < code.size()) {
                code[pos + i] = 0x90;
            }
        }
    }
}

std::vector<uint8_t> InstructionSubstitutor::Substitute(
    const std::vector<uint8_t>& code) {
    std::vector<uint8_t> result = code;
    
    for (size_t i = 0; i < result.size(); ) {
        bool matched = false;
        
        for (const auto& rule : m_rules) {
            if (MatchPattern(result, i, rule)) {
                if (!rule.replacements.empty()) {
                    size_t choice = m_rng.Next(static_cast<uint32_t>(rule.replacements.size()));
                    ApplySubstitution(result, i, rule.replacements[choice]);
                    matched = true;
                    break;
                }
            }
        }
        
        if (!matched) {
            ++i;
        } else {
            // Advance by replaced instruction length
            i += 1;  // Simplified - should use actual decoded length
        }
    }
    
    return result;
}

void InstructionSubstitutor::AddRule(const SubstitutionRule& rule) {
    m_rules.push_back(rule);
}

} // namespace Polymorphic