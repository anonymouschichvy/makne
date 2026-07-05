// src/DataEncoder.h
#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include "Utils.h"

namespace Polymorphic {

class DataEncoder {
public:
    enum class Encoding {
        XOR,
        Base64,
        Custom,
        StringSplit,
        UnicodeTransform
    };

    DataEncoder(CryptoRandom& rng);
    
    // Encode data section
    std::vector<uint8_t> Encode(const std::vector<uint8_t>& data,
        Encoding method);
    
    // Encode specific strings
    std::vector<uint8_t> EncodeString(const std::string& str,
        Encoding method);
    
    // Generate decoder stub for encoded data
    std::vector<uint8_t> GenerateDecoder(const std::vector<uint8_t>& encoded,
        Encoding method, uint32_t dataRva);
    
    // Set custom encoding function
    void SetCustomEncoding(std::function<std::vector<uint8_t>(
        const std::vector<uint8_t>&)> encoder,
        std::function<std::vector<uint8_t>(
        const std::vector<uint8_t>&)> decoder);
        
    void SetIs64Bit(bool is64);
    
private:
    CryptoRandom& m_rng;
    bool m_is64Bit;
    std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)> m_customEncoder;
    std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)> m_customDecoder;
    
    // Encoding implementations
    std::vector<uint8_t> XorEncode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> Base64Encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> CustomEncode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> StringSplitEncode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> UnicodeTransformEncode(const std::vector<uint8_t>& data);
    
    // Decoder generators
    std::vector<uint8_t> GenerateXORDecoder(uint32_t dataRva, size_t size);
    std::vector<uint8_t> GenerateBase64Decoder(uint32_t dataRva, size_t size);
};

} // namespace Polymorphic