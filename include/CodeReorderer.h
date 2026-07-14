#pragma once
#include "ObfuscationPass.h"
#include "Utils.h"

namespace Polymorphic {

class CodeReorderer : public IObfuscationPass {
public:
    CodeReorderer(CryptoRandom& rng);
    
    std::string Name() const override { return "CodeReorderer"; }
    void Run(InstructionBlock& block, ArchContext& ctx) override;
    bool ValidateOutput(const InstructionBlock& block) const override;
    
    void SetStrategy(const std::string& strategy);
    
private:
    CryptoRandom& m_rng;
    std::string m_strategy;
};

} // namespace Polymorphic