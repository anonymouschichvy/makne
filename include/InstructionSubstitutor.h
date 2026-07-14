#pragma once
#include "ObfuscationPass.h"
#include "Utils.h"

namespace Polymorphic {

class InstructionSubstitutor : public IObfuscationPass {
public:
    InstructionSubstitutor(CryptoRandom& rng);
    
    std::string Name() const override { return "InstructionSubstitutor"; }
    void Run(InstructionBlock& block, ArchContext& ctx) override;
    bool ValidateOutput(const InstructionBlock& block) const override;
    
private:
    CryptoRandom& m_rng;
};

} // namespace Polymorphic