#pragma once
#include "ObfuscationPass.h"
#include "Utils.h"

namespace Polymorphic {

class ControlFlowObfuscator : public IObfuscationPass {
public:
    ControlFlowObfuscator(CryptoRandom& rng);
    
    std::string Name() const override { return "ControlFlowObfuscator"; }
    void Run(InstructionBlock& block, ArchContext& ctx) override;
    bool ValidateOutput(const InstructionBlock& block) const override;
    
    void SetLevel(int level);
    
private:
    CryptoRandom& m_rng;
    int m_level;
};

} // namespace Polymorphic