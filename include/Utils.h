// src/Utils.h
#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include <random>
#include <functional>

namespace Polymorphic {

// Cryptographically secure random number generator
class CryptoRandom {
public:
    CryptoRandom();
    
    uint32_t Next();
    uint32_t Next(uint32_t max);
    uint32_t Next(uint32_t min, uint32_t max);
    void GetBytes(std::vector<uint8_t>& buffer);
    uint8_t NextByte();
    bool NextBool();
    
private:
    std::random_device m_rd;
    std::mt19937_64 m_generator;
};

// Utility functions
class Utils {
public:
    // CRC32 calculation
    static uint32_t CalculateCRC32(const std::vector<uint8_t>& data);
    
    // PE checksum calculation
    static uint32_t CalculatePEChecksum(const std::vector<uint8_t>& data);
    
    // Align value
    static uint32_t AlignUp(uint32_t value, uint32_t alignment);
    
    // RVA to file offset conversion
    static uint32_t RvaToOffset(uint32_t rva, const std::vector<class SectionInfo>& sections);
    static uint32_t OffsetToRva(uint32_t offset, const std::vector<class SectionInfo>& sections);
    
    // String hashing
    static uint32_t HashString(const std::string& str);
    static uint32_t HashStringW(const std::wstring& str);
    
    // XOR encryption
    static std::vector<uint8_t> XorEncrypt(const std::vector<uint8_t>& data, 
        const std::vector<uint8_t>& key);
    
    // RC4 encryption
    static std::vector<uint8_t> RC4Crypt(const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& key);
    
    // AES encryption (simplified)
    static std::vector<uint8_t> AESEncrypt(const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& key);
    
    // Compression
    static std::vector<uint8_t> Compress(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> Decompress(const std::vector<uint8_t>& data);
};

// Section information helper
class SectionInfo {
public:
    std::string name;
    uint32_t virtualAddress;
    uint32_t virtualSize;
    uint32_t rawAddress;
    uint32_t rawSize;
    uint32_t characteristics;
    
    bool ContainsRva(uint32_t rva) const;
    bool ContainsOffset(uint32_t offset) const;
};

// Instruction representation
struct Instruction {
    uint8_t opcode;
    std::vector<uint8_t> operands;
    size_t length;
    uint32_t virtualAddress;
    bool isJump;
    bool isCall;
    bool isReturn;
    bool isConditional;
    int32_t jumpOffset;
    uint32_t targetAddress;
    
    Instruction() : opcode(0), length(0), virtualAddress(0),
        isJump(false), isCall(false), isReturn(false),
        isConditional(false), jumpOffset(0), targetAddress(0) {}
};

// x86 register definitions
enum class X86Register {
    EAX = 0, ECX = 1, EDX = 2, EBX = 3,
    ESP = 4, EBP = 5, ESI = 6, EDI = 7,
    NONE = 8
};

// Register mapping for substitution
struct RegisterMapping {
    X86Register from;
    X86Register to;
};

} // namespace Polymorphic