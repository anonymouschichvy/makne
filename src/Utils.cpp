// src/Utils.cpp
#include "Utils.h"
#include <fstream>
#include <algorithm>
#include <cstring>
#include <numeric>

namespace Polymorphic {

// CRC32 table
static const uint32_t CRC32_TABLE[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
    0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    // ... (truncated for brevity - full table would be here)
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

CryptoRandom::CryptoRandom() : m_generator(m_rd()) {}

uint32_t CryptoRandom::Next() {
    return static_cast<uint32_t>(m_generator());
}

uint32_t CryptoRandom::Next(uint32_t max) {
    return Next() % max;
}

uint32_t CryptoRandom::Next(uint32_t min, uint32_t max) {
    return min + (Next() % (max - min));
}

void CryptoRandom::GetBytes(std::vector<uint8_t>& buffer) {
    for (auto& byte : buffer) {
        byte = static_cast<uint8_t>(Next() & 0xFF);
    }
}

uint8_t CryptoRandom::NextByte() {
    return static_cast<uint8_t>(Next() & 0xFF);
}

bool CryptoRandom::NextBool() {
    return (Next() & 1) == 1;
}

uint32_t Utils::CalculateCRC32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t byte : data) {
        crc = CRC32_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

uint32_t Utils::AlignUp(uint32_t value, uint32_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

uint32_t Utils::HashString(const std::string& str) {
    uint32_t hash = 0;
    for (char c : str) {
        hash = ((hash << 5) + hash) + static_cast<uint8_t>(c);
    }
    return hash;
}

std::vector<uint8_t> Utils::XorEncrypt(const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& key) {
    std::vector<uint8_t> result = data;
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] ^= key[i % key.size()];
    }
    return result;
}

std::vector<uint8_t> Utils::RC4Crypt(const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& key) {
    std::vector<uint8_t> S(256);
    std::iota(S.begin(), S.end(), 0);
    
    size_t j = 0;
    for (size_t i = 0; i < 256; ++i) {
        j = (j + S[i] + key[i % key.size()]) % 256;
        std::swap(S[i], S[j]);
    }
    
    std::vector<uint8_t> result = data;
    size_t i = 0;
    j = 0;
    for (size_t k = 0; k < result.size(); ++k) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        result[k] ^= S[(S[i] + S[j]) % 256];
    }
    
    return result;
}

bool SectionInfo::ContainsRva(uint32_t rva) const {
    return rva >= virtualAddress && rva < virtualAddress + virtualSize;
}

bool SectionInfo::ContainsOffset(uint32_t offset) const {
    return offset >= rawAddress && offset < rawAddress + rawSize;
}

} // namespace Polymorphic