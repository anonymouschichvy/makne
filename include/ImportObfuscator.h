// src/ImportObfuscator.h
#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include <map>
#include "Utils.h"
#include "PEStructs.h"

namespace Polymorphic {

class ImportObfuscator {
public:
    struct ImportInfo {
        std::string dllName;
        std::string functionName;
        uint16_t ordinal;
        bool byOrdinal;
        uint32_t rva;  // IAT entry RVA
    };

    struct ObfuscatedImport {
        std::string encodedDll;
        std::string encodedFunction;
        uint32_t hash;
        bool byOrdinal;
        uint16_t ordinal;
        std::vector<uint8_t> resolverStub;
    };

    ImportObfuscator(CryptoRandom& rng);
    
    // Obfuscate import table
    bool Obfuscate(std::vector<uint8_t>& peData);
    
    // Set obfuscation methods
    void SetHashImports(bool enable);
    void SetEncryptStrings(bool enable);
    void SetDynamicLoad(bool enable);
    void SetStolenImports(bool enable);  // Use alternative APIs
    void EnableAntiDebug(bool enable);
    
    // Add custom import resolver
    void SetCustomResolver(std::function<uint32_t(const std::string&, 
        const std::string&)> resolver);
    
    // Generate import resolver stub
    std::vector<uint8_t> GenerateResolverStub(
        const std::vector<ObfuscatedImport>& imports);
    
private:
    CryptoRandom& m_rng;
    bool m_hashImports;
    bool m_encryptStrings;
    bool m_dynamicLoad;
    bool m_stolenImports;
    bool m_antiDebug;
    
    std::function<uint32_t(const std::string&, const std::string&)> m_customResolver;
    
    // Import parsing
    bool ParseImports(const std::vector<uint8_t>& data,
        std::vector<ImportInfo>& imports,
        uint32_t& iatRva, uint32_t& iatSize);
    
    // Obfuscation methods
    std::string EncodeString(const std::string& str);
    uint32_t HashFunction(const std::string& dll, const std::string& func);
    
    // Generate hash-based resolver
    std::vector<uint8_t> GenerateHashResolver();
    
    // Generate LoadLibrary/GetProcAddress based resolver
    std::vector<uint8_t> GenerateDynamicResolver(
        const std::vector<ObfuscatedImport>& imports);
    
    // Generate stolen import resolver (uses alternative APIs)
    std::vector<uint8_t> GenerateStolenResolver();
    
    // String encryption
    std::vector<uint8_t> EncryptStringData(const std::string& str);
    
    // API hashes database
    static std::map<std::string, uint32_t> s_apiHashes;
};

} // namespace Polymorphic