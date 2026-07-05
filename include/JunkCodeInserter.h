// src/JunkCodeInserter.h
#pragma once
#include <vector>
#include <cstdint>
#include "Utils.h"

namespace Polymorphic {

class JunkCodeInserter {
public:
    struct JunkPattern {
        std::vector<uint8_t> code;
        bool safeAfterBranch;
        bool safeBeforeBranch;
        std::vector<X86Register> clobberedRegs;
        int minInsertions;
        int maxInsertions;
    };

    JunkCodeInserter(CryptoRandom& rng);
    void SetDensity(float density);
    void SetPreservedRegisters(const std::vector<X86Register>& regs);
    std::vector<uint8_t> Insert(const std::vector<uint8_t>& code);
    void AddPattern(const JunkPattern& pattern);

private:
    void InitializePatterns();
    JunkPattern SelectJunk(bool afterBranch, bool beforeBranch);
    std::vector<uint8_t> GenerateRandomJunk();

    CryptoRandom& m_rng;
    float m_density;
    std::vector<JunkPattern> m_patterns;
    std::vector<X86Register> m_preservedRegs;
};

} // namespace Polymorphic
