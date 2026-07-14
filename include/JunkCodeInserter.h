#pragma once
#include "ObfuscationPass.h"
#include "Utils.h"

namespace Polymorphic {

class JunkCodeInserter : public IObfuscationPass {
public:
    JunkCodeInserter(CryptoRandom& rng);
    
    std::string Name() const override { return "JunkCodeInserter"; }
    void Run(InstructionBlock& block, ArchContext& ctx) override;
    bool ValidateOutput(const InstructionBlock& block) const override;
    
    void SetDensity(float density);
    
private:
    CryptoRandom& m_rng;
    float m_density;
};

} // namespace Polymorphic
