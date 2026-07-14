// include/RegisterRandomizer.h
#pragma once
#include <vector>
#include <cstdint>
#include <map>
#include "Utils.h"
#include "ObfuscationPass.h"

namespace Polymorphic {

// RegisterRandomizerCore does the raw-byte register substitution (same logic as before)
class RegisterRandomizerCore {
public:
    explicit RegisterRandomizerCore(CryptoRandom& rng);

    // Set 64-bit / 32-bit mode
    void Set64Bit(bool enable);

    // Randomize register usage in raw code bytes
    std::vector<uint8_t> Randomize(const std::vector<uint8_t>& code);

    // Set which registers can be used for substitution
    void SetAllowedRegisters(const std::vector<X86Register>& regs);

    // Preserve specific registers (e.g., RSP, RBP for stack frame)
    void PreserveRegisters(const std::vector<X86Register>& regs);

private:
    CryptoRandom& m_rng;
    std::vector<uint8_t> m_allowedIds;
    std::vector<uint8_t> m_preservedIds;
    bool m_is64Bit;

    // Generate register ID mapping
    std::map<uint8_t, uint8_t> GenerateIdMapping();
};

// IObfuscationPass wrapper — operates on the shared InstructionBlock IR
class RegisterRandomizer : public IObfuscationPass {
public:
    explicit RegisterRandomizer(CryptoRandom& rng) : m_rng(rng) {}

    void Run(InstructionBlock& block, ArchContext& ctx) override;
    std::string Name() const override { return "RegisterRandomizer"; }
    bool ValidateOutput(const InstructionBlock& block) const override { return !block.empty(); }

private:
    CryptoRandom& m_rng;
};

} // namespace Polymorphic