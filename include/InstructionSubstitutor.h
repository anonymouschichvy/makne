// src/InstructionSubstitutor.h
#pragma once
#include <vector>
#include <cstdint>
#include <functional>
#include "Utils.h"

namespace Polymorphic {

class InstructionSubstitutor {
public:
    struct SubstitutionRule {
        std::vector<uint8_t> pattern;
        std::vector<std::vector<uint8_t>> replacements;
        size_t patternLength;
        bool requiresModRM;
        uint8_t modRMMask;
        std::function<bool(const std::vector<uint8_t>&, size_t)> validator;
    };

    InstructionSubstitutor(CryptoRandom& rng);
    
    void LoadDefaultRules();
    void AddRule(const SubstitutionRule& rule);
    
    std::vector<uint8_t> Substitute(const std::vector<uint8_t>& code);
    
    // Specific substitution methods
    std::vector<uint8_t> SubstituteArithmetic(const std::vector<uint8_t>& code);
    std::vector<uint8_t> SubstituteLogical(const std::vector<uint8_t>& code);
    std::vector<uint8_t> SubstituteMove(const std::vector<uint8_t>& code);
    std::vector<uint8_t> SubstituteStack(const std::vector<uint8_t>& code);
    
private:
    CryptoRandom& m_rng;
    std::vector<SubstitutionRule> m_rules;
    
    bool MatchPattern(const std::vector<uint8_t>& code, size_t pos, 
        const SubstitutionRule& rule);
    void ApplySubstitution(std::vector<uint8_t>& code, size_t pos,
        const std::vector<uint8_t>& replacement);
    
    // Built-in rule generators
    void AddArithmeticRules();
    void AddLogicalRules();
    void AddMoveRules();
    void AddStackRules();
    void AddNOPRules();
};

} // namespace Polymorphic