// src/PayloadEncryptor.cpp
#include "PayloadEncryptor.h"
#include <algorithm>
#include <numeric>

namespace Polymorphic {

PayloadEncryptor::PayloadEncryptor(CryptoRandom& rng)
    : m_rng(rng), m_algorithm(Algorithm::XOR), m_keySize(16) {}

void PayloadEncryptor::SetAlgorithm(Algorithm algo) {
    m_algorithm = algo;
}

void PayloadEncryptor::SetKeySize(size_t size) {
    m_keySize = size;
}

void PayloadEncryptor::SetCustomEncrypt(
    std::function<std::vector<uint8_t>(const std::vector<uint8_t>&,
        const std::vector<uint8_t>&)> func) {
    m_customEncrypt = func;
}

std::vector<uint8_t> PayloadEncryptor::GenerateKey(size_t length) {
    std::vector<uint8_t> key(length);
    m_rng.GetBytes(key);
    return key;
}

std::vector<uint8_t> PayloadEncryptor::XorEncrypt(const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& key) {
    std::vector<uint8_t> result = data;
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] ^= key[i % key.size()];
    }
    return result;
}

std::vector<uint8_t> PayloadEncryptor::RC4Encrypt(const std::vector<uint8_t>& data,
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

std::vector<uint8_t> PayloadEncryptor::AESEncrypt(const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& key) {
    // Simplified AES - real implementation would use proper AES
    // This is a placeholder that does multiple rounds of XOR
    std::vector<uint8_t> result = data;
    
    for (int round = 0; round < 10; ++round) {
        for (size_t i = 0; i < result.size(); ++i) {
            result[i] ^= key[(i + round) % key.size()];
            result[i] = ((result[i] << 1) | (result[i] >> 7)) & 0xFF;  // Rotate
        }
    }
    
    return result;
}

PayloadEncryptor::EncryptionResult PayloadEncryptor::Encrypt(
    const std::vector<uint8_t>& code, uint32_t baseAddress) {
    
    EncryptionResult result;
    result.key = GenerateKey(m_keySize);
    result.originalEntryPoint = baseAddress;
    
    switch (m_algorithm) {
        case Algorithm::XOR:
            result.encryptedData = XorEncrypt(code, result.key);
            result.algorithm = Algorithm::XOR;
            break;
        case Algorithm::RC4:
            result.encryptedData = RC4Encrypt(code, result.key);
            result.algorithm = Algorithm::RC4;
            break;
        case Algorithm::AES:
            result.encryptedData = AESEncrypt(code, result.key);
            result.algorithm = Algorithm::AES;
            break;
        case Algorithm::CUSTOM:
            if (m_customEncrypt) {
                result.encryptedData = m_customEncrypt(code, result.key);
            } else {
                result.encryptedData = XorEncrypt(code, result.key);
            }
            result.algorithm = Algorithm::CUSTOM;
            break;
    }
    
    // New entry point will be the decryptor stub
    result.newEntryPoint = baseAddress;  // Will be adjusted later
    
    return result;
}

} // namespace Polymorphic