// include/RegisterRandomizer.h
#pragma once
#include <vector>
#include <cstdint>
#include <map>
#include "Utils.h"

namespace Polymorphic {

class RegisterRandomizer {
public:
    RegisterRandomizer(CryptoRandom& rng);
    
    // Randomize register usage in code
    std::vector<uint8_t> Randomize(const std::vector<uint8_t>& code);
    
    // Set which registers can be used for substitution
    void SetAllowedRegisters(const std::vector<X86Register>& regs);
    
    // Preserve specific registers (e.g., ESP, EBP for stack frame)
    void PreserveRegisters(const std::vector<X86Register>& regs);
    
    // Enable or disable 64-bit mode
    void Set64Bit(bool enable);
    
private:
    CryptoRandom& m_rng;
    std::vector<uint8_t> m_allowedIds;
    std::vector<uint8_t> m_preservedIds;
    bool m_is64Bit;
    
    // Generate register ID mapping
    std::map<uint8_t, uint8_t> GenerateIdMapping();
};

} // namespace Polymorphic