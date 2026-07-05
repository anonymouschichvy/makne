// src/DecryptorGenerator.h
#pragma once
#include <vector>
#include <cstdint>
#include "Utils.h"
#include "PayloadEncryptor.h"

namespace Polymorphic {

class DecryptorGenerator {
public:
    DecryptorGenerator(CryptoRandom& rng);
    
    // Generate polymorphic decryptor stub
    std::vector<uint8_t> Generate(const std::vector<uint8_t>& key,
        PayloadEncryptor::Algorithm algo,
        uint32_t encryptedSectionRva,
        uint32_t encryptedSectionSize,
        uint32_t originalEntryPoint);
    
    // Set polymorphism level
    void SetPolymorphismLevel(int level); // 1-5
    
    // Enable anti-debugging in decryptor
    void EnableAntiDebug(bool enable);
    
    // Enable anti-emulation
    void EnableAntiEmulation(bool enable);
    
    // Set architecture compatibility mode
    void SetIs64Bit(bool is64);
    
private:
    CryptoRandom& m_rng;
    int m_level;
    bool m_antiDebug;
    bool m_antiEmulation;
    bool m_is64Bit;
    
    // Decryptor generation methods
    std::vector<uint8_t> GenerateXORDecryptor(const std::vector<uint8_t>& key,
        uint32_t rva, uint32_t size);
    std::vector<uint8_t> GenerateRC4Decryptor(const std::vector<uint8_t>& key,
        uint32_t rva, uint32_t size);
    std::vector<uint8_t> GenerateAESDecryptor(const std::vector<uint8_t>& key,
        uint32_t rva, uint32_t size);
    
    // Polymorphic instruction generators
    std::vector<uint8_t> GenerateMovRegImm(X86Register reg, uint32_t value);
    std::vector<uint8_t> GenerateAddRegImm(X86Register reg, uint32_t value);
    std::vector<uint8_t> GenerateXorRegReg(X86Register reg1, X86Register reg2);
    std::vector<uint8_t> GeneratePushReg(X86Register reg);
    std::vector<uint8_t> GeneratePopReg(X86Register reg);
    
    // Anti-debugging code
    std::vector<uint8_t> GenerateAntiDebugCode();
    
    // Anti-emulation code
    std::vector<uint8_t> GenerateAntiEmulationCode();
    
    // Junk code insertion
    void InsertPolymorphicJunk(std::vector<uint8_t>& code);
    
    // Register allocation
    std::vector<X86Register> AllocateRegisters(int count);
    
    // Instruction permutations
    std::vector<std::vector<uint8_t>> PermuteInstructions(
        const std::vector<std::vector<uint8_t>>& instructions);
};

} // namespace Polymorphic