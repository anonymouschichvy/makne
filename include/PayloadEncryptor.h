// src/PayloadEncryptor.h
#pragma once
#include <vector>
#include <cstdint>
#include <functional>
#include "Utils.h"

namespace Polymorphic {

class PayloadEncryptor {
public:
    enum class Algorithm {
        XOR,
        RC4,
        AES,
        CUSTOM
    };

    struct EncryptionResult {
        std::vector<uint8_t> encryptedData;
        std::vector<uint8_t> key;
        Algorithm algorithm;
        uint32_t originalEntryPoint;
        uint32_t newEntryPoint;
    };

    PayloadEncryptor(CryptoRandom& rng);
    
    // Encrypt code section
    EncryptionResult Encrypt(const std::vector<uint8_t>& code,
        uint32_t baseAddress);
    
    // Set encryption algorithm
    void SetAlgorithm(Algorithm algo);
    
    // Set key size
    void SetKeySize(size_t size);
    
    // Custom encryption callback
    void SetCustomEncrypt(std::function<std::vector<uint8_t>(
        const std::vector<uint8_t>&, const std::vector<uint8_t>&)> func);
    
    // Generate random key
    std::vector<uint8_t> GenerateKey(size_t length);
    
private:
    CryptoRandom& m_rng;
    Algorithm m_algorithm;
    size_t m_keySize;
    std::function<std::vector<uint8_t>(const std::vector<uint8_t>&,
        const std::vector<uint8_t>&)> m_customEncrypt;
    
    // Encryption implementations
    std::vector<uint8_t> XorEncrypt(const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& key);
    std::vector<uint8_t> RC4Encrypt(const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& key);
    std::vector<uint8_t> AESEncrypt(const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& key);
};

} // namespace Polymorphic