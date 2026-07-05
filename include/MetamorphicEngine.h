// src/MetamorphicEngine.h
#pragma once
#include "PolymorphicEngine.h"
#include <memory>

namespace Polymorphic {

// Metamorphic engine - rewrites code completely while preserving semantics
class MetamorphicEngine {
public:
    MetamorphicEngine(CryptoRandom& rng);
    ~MetamorphicEngine();
    
    // Full code metamorphosis
    bool Transform(std::vector<uint8_t>& code, uint32_t baseAddress);
    
    // Set transformation levels
    void Set64Bit(bool enable);               // Architecture configuration
    void SetPermutationLevel(int level);      // Instruction reordering
    void SetExpansionLevel(int level);       // Code expansion
    void setGarbageLevel(int level);          // Garbage code insertion
    void SetRegisterPressure(int level);      // Register allocation complexity
    
    // Enable specific transformations
    void EnableLoopUnrolling(bool enable);
    void EnableFunctionInlining(bool enable);
    void EnableOpaquePredicates(bool enable);
    void EnableBranchPrediction(bool enable);
    
private:
    CryptoRandom& m_rng;
    bool m_is64Bit;
    
    int m_permLevel;
    int m_expandLevel;
    int m_garbageLevel;
    int m_regPressure;
    
    bool m_loopUnroll;
    bool m_funcInline;
    bool m_opaquePredicates;
    bool m_branchPrediction;
    
    // Intermediate representation
    class IR;
    std::unique_ptr<IR> m_ir;
    
    // Transformation passes
    void DisassembleToIR(const std::vector<uint8_t>& code, uint32_t baseAddress);
    std::vector<uint8_t> AssembleFromIR();
    
    void ApplyPermutation();
    void ApplyExpansion();
    void ApplyGarbageInsertion();
    void ApplyRegisterAllocation();
    void ApplyLoopUnrolling();
    void ApplyFunctionInlining();
    void ApplyOpaquePredicates();
    void ApplyBranchPrediction();
};

} // namespace Polymorphic