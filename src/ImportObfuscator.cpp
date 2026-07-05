// src/ImportObfuscator.cpp
#include "ImportObfuscator.h"
#include <algorithm>
#include <cstring>

namespace Polymorphic {

// Common API hashes (for hash-based resolution)
std::map<std::string, uint32_t> ImportObfuscator::s_apiHashes = {
    {"LoadLibraryA", 0x8A8B4036},
    {"LoadLibraryW", 0x9C8B3D5F},
    {"GetProcAddress", 0x7C0DFCA8},
    {"GetModuleHandleA", 0xD3324904},
    {"GetModuleHandleW", 0xE5B35D7D},
    {"VirtualAlloc", 0xE553A458},
    {"VirtualProtect", 0xc929e63b},
    {"VirtualFree", 0x306D7E1C},
    {"CreateFileA", 0x8F8F114},
    {"ReadFile", 0xF8C5E536},
    {"WriteFile", 0xF1F1D8E9},
    {"CloseHandle", 0xD4D5E2C1},
    {"MessageBoxA", 0xA9D0F2B4},
    {"ExitProcess", 0x251097C4},
    {"GetLastError", 0xC25D8E3A}
};

ImportObfuscator::ImportObfuscator(CryptoRandom& rng)
    : m_rng(rng), m_hashImports(false), m_encryptStrings(true),
      m_dynamicLoad(true), m_stolenImports(false), m_antiDebug(false) {}

void ImportObfuscator::SetHashImports(bool enable) {
    m_hashImports = enable;
}

void ImportObfuscator::SetEncryptStrings(bool enable) {
    m_encryptStrings = enable;
}

void ImportObfuscator::SetDynamicLoad(bool enable) {
    m_dynamicLoad = enable;
}

void ImportObfuscator::SetStolenImports(bool enable) {
    m_stolenImports = enable;
}

void ImportObfuscator::EnableAntiDebug(bool enable) {
    m_antiDebug = enable;
}

void ImportObfuscator::SetCustomResolver(
    std::function<uint32_t(const std::string&, const std::string&)> resolver) {
    m_customResolver = resolver;
}

std::string ImportObfuscator::EncodeString(const std::string& str) {
    // XOR encode with random key
    std::string encoded = str;
    uint8_t key = m_rng.NextByte();
    
    for (char& c : encoded) {
        c ^= key;
    }
    
    // Prepend key
    encoded.insert(encoded.begin(), key);
    return encoded;
}

uint32_t ImportObfuscator::HashFunction(const std::string& dll, 
    const std::string& func) {
    
    // ROR13 hash (common in malware)
    uint32_t hash = 0;
    
    // Hash DLL name (uppercase)
    for (char c : dll) {
        hash = ((hash >> 13) | (hash << 19)) + toupper(c);
    }
    
    // Hash function name
    for (char c : func) {
        hash = ((hash >> 13) | (hash << 19)) + c;
    }
    
    return hash;
}

std::vector<uint8_t> ImportObfuscator::EncryptStringData(const std::string& str) {
    std::vector<uint8_t> result(str.begin(), str.end());
    uint8_t key = m_rng.NextByte();
    
    for (auto& c : result) {
        c ^= key;
    }
    
    result.push_back(0);  // Null terminator
    result.insert(result.begin(), key);  // Key at start
    
    return result;
}

bool ImportObfuscator::ParseImports(const std::vector<uint8_t>& data,
    std::vector<ImportInfo>& imports, uint32_t& iatRva, uint32_t& iatSize) {
    
    if (data.size() < sizeof(PE::IMAGE_DOS_HEADER)) return false;
    
    const PE::IMAGE_DOS_HEADER* dosHeader = 
        reinterpret_cast<const PE::IMAGE_DOS_HEADER*>(data.data());
    if (dosHeader->e_magic != 0x5A4D) return false;
    
    uint32_t peOffset = dosHeader->e_lfanew;
    if (peOffset + sizeof(uint32_t) + sizeof(PE::IMAGE_FILE_HEADER) > data.size()) {
        return false;
    }
    
    const PE::IMAGE_FILE_HEADER* fileHeader = 
        reinterpret_cast<const PE::IMAGE_FILE_HEADER*>(data.data() + peOffset + 4);
        
    const uint8_t* optionalHeaderPtr = reinterpret_cast<const uint8_t*>(fileHeader) + sizeof(PE::IMAGE_FILE_HEADER);
    if (peOffset + sizeof(uint32_t) + sizeof(PE::IMAGE_FILE_HEADER) + sizeof(uint16_t) > data.size()) {
        return false;
    }
    
    uint16_t magic = *reinterpret_cast<const uint16_t*>(optionalHeaderPtr);
    bool is64Bit = (magic == 0x20B);
    
    uint32_t importRva = 0;
    uint32_t importSize = 0;
    
    if (is64Bit) {
        const PE::IMAGE_OPTIONAL_HEADER64* opt64 = 
            reinterpret_cast<const PE::IMAGE_OPTIONAL_HEADER64*>(optionalHeaderPtr);
        importRva = opt64->DataDirectory[1].VirtualAddress;
        importSize = opt64->DataDirectory[1].Size;
        iatRva = opt64->DataDirectory[12].VirtualAddress;
        iatSize = opt64->DataDirectory[12].Size;
    } else {
        const PE::IMAGE_OPTIONAL_HEADER32* opt32 = 
            reinterpret_cast<const PE::IMAGE_OPTIONAL_HEADER32*>(optionalHeaderPtr);
        importRva = opt32->DataDirectory[1].VirtualAddress;
        importSize = opt32->DataDirectory[1].Size;
        iatRva = opt32->DataDirectory[12].VirtualAddress;
        iatSize = opt32->DataDirectory[12].Size;
    }
    
    if (importRva == 0 || importSize == 0) return false;
    
    // Find section containing imports
    const PE::IMAGE_SECTION_HEADER* sections = 
        reinterpret_cast<const PE::IMAGE_SECTION_HEADER*>(
            optionalHeaderPtr + fileHeader->SizeOfOptionalHeader);
    
    for (int i = 0; i < fileHeader->NumberOfSections; ++i) {
        if (importRva >= sections[i].VirtualAddress &&
            importRva < sections[i].VirtualAddress + sections[i].VirtualSize) {
            
            uint32_t fileOffset = sections[i].PointerToRawData + 
                (importRva - sections[i].VirtualAddress);
            
            if (fileOffset + sizeof(PE::IMAGE_IMPORT_DESCRIPTOR) > data.size()) {
                return false;
            }
            
            // Parse import descriptors
            const PE::IMAGE_IMPORT_DESCRIPTOR* importDesc = 
                reinterpret_cast<const PE::IMAGE_IMPORT_DESCRIPTOR*>(
                    data.data() + fileOffset);
            
            while (importDesc->Name != 0) {
                uint32_t dllNameOffset = sections[i].PointerToRawData + 
                    (importDesc->Name - sections[i].VirtualAddress);
                if (dllNameOffset >= data.size()) return false;
                const char* dllName = 
                    reinterpret_cast<const char*>(data.data() + dllNameOffset);
                
                // Parse import lookup table
                uint32_t iltRva = importDesc->OriginalFirstThunk;
                if (iltRva == 0) iltRva = importDesc->FirstThunk;
                
                uint32_t iltOffset = sections[i].PointerToRawData + 
                    (iltRva - sections[i].VirtualAddress);
                
                if (iltOffset >= data.size()) return false;
                
                int idx = 0;
                if (is64Bit) {
                    const PE::IMAGE_THUNK_DATA64* thunk = 
                        reinterpret_cast<const PE::IMAGE_THUNK_DATA64*>(
                            data.data() + iltOffset);
                            
                    while (thunk->u1.AddressOfData != 0) {
                        ImportInfo info;
                        info.dllName = dllName;
                        info.rva = importDesc->FirstThunk + (idx * 8);
                        
                        if (thunk->u1.Ordinal & 0x8000000000000000ULL) {
                            // Import by ordinal
                            info.byOrdinal = true;
                            info.ordinal = static_cast<uint16_t>(
                                thunk->u1.Ordinal & 0xFFFF);
                        } else {
                            // Import by name
                            info.byOrdinal = false;
                            uint32_t nameOffset = sections[i].PointerToRawData + 
                                (static_cast<uint32_t>(thunk->u1.AddressOfData) - sections[i].VirtualAddress);
                            if (nameOffset + 2 >= data.size()) return false;
                            const char* funcName = 
                                reinterpret_cast<const char*>(data.data() + nameOffset + 2);
                            info.functionName = funcName;
                        }
                        
                        imports.push_back(info);
                        ++thunk;
                        ++idx;
                    }
                } else {
                    const PE::IMAGE_THUNK_DATA32* thunk = 
                        reinterpret_cast<const PE::IMAGE_THUNK_DATA32*>(
                            data.data() + iltOffset);
                            
                    while (thunk->u1.AddressOfData != 0) {
                        ImportInfo info;
                        info.dllName = dllName;
                        info.rva = importDesc->FirstThunk + (idx * 4);
                        
                        if (thunk->u1.Ordinal & 0x80000000) {
                            // Import by ordinal
                            info.byOrdinal = true;
                            info.ordinal = static_cast<uint16_t>(
                                thunk->u1.Ordinal & 0xFFFF);
                        } else {
                            // Import by name
                            info.byOrdinal = false;
                            uint32_t nameOffset = sections[i].PointerToRawData + 
                                (thunk->u1.AddressOfData - sections[i].VirtualAddress);
                            if (nameOffset + 2 >= data.size()) return false;
                            const char* funcName = 
                                reinterpret_cast<const char*>(data.data() + nameOffset + 2);
                            info.functionName = funcName;
                        }
                        
                        imports.push_back(info);
                        ++thunk;
                        ++idx;
                    }
                }
                
                ++importDesc;
            }
            
            return true;
        }
    }
    
    return false;
}

std::vector<uint8_t> ImportObfuscator::GenerateHashResolver() {
    std::vector<uint8_t> code;
    
    // Hash-based API resolver
    // Input: EAX = hash, ECX = module base
    // Output: EAX = function address
    
    // push ebx
    code.push_back(0x53);
    // push esi
    code.push_back(0x56);
    // push edi
    code.push_back(0x57);
    
    // mov ebx, [ecx + 0x3C]  ; PE header offset
    code.push_back(0x8B); code.push_back(0x59); code.push_back(0x3C);
    // mov ebx, [ecx + ebx + 0x78]  ; export directory RVA
    code.push_back(0x8B); code.push_back(0x9C); code.push_back(0x19);
    code.push_back(0x78); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00);
    // add ebx, ecx  ; export directory VA
    code.push_back(0x03); code.push_back(0xD9);
    
    // mov esi, [ebx + 0x20]  ; name table RVA
    code.push_back(0x8B); code.push_back(0x73); code.push_back(0x20);
    // add esi, ecx  ; name table VA
    code.push_back(0x03); code.push_back(0xF1);
    
    // mov edx, [ebx + 0x14]  ; number of names
    code.push_back(0x8B); code.push_back(0x53); code.push_back(0x14);
    // xor edi, edi  ; counter
    code.push_back(0x33); code.push_back(0xFF);
    
    // hash_loop:
    // push edx
    code.push_back(0x52);
    // mov edx, [esi + edi * 4]  ; name RVA
    code.push_back(0x8B); code.push_back(0x14); code.push_back(0xBE);
    // add edx, ecx  ; name VA
    code.push_back(0x03); code.push_back(0xD1);
    
    // push eax  ; save target hash
    code.push_back(0x50);
    // xor eax, eax  ; hash accumulator
    code.push_back(0x33); code.push_back(0xC0);
    
    // hash_char:
    // lodsb (using manual implementation)
    code.push_back(0x8A); code.push_back(0x02);
    // test al, al
    code.push_back(0x84); code.push_back(0xC0);
    // jz hash_done
    code.push_back(0x74); code.push_back(0x08);
    // ror eax, 0x0D
    code.push_back(0xC1); code.push_back(0xC8); code.push_back(0x0D);
    // add eax, [esp]  ; add char
    code.push_back(0x03); code.push_back(0x04); code.push_back(0x24);
    // inc edx
    code.push_back(0x42);
    // jmp hash_char
    code.push_back(0xEB); code.push_back(0xF1);
    
    // hash_done:
    // cmp eax, [esp+4]  ; compare with target
    code.push_back(0x3B); code.push_back(0x44); code.push_back(0x24); code.push_back(0x04);
    // pop edx  ; discard
    code.push_back(0x5A);
    // je found
    code.push_back(0x74); code.push_back(0x05);
    
    // inc edi
    code.push_back(0x47);
    // pop edx
    code.push_back(0x5A);
    // cmp edi, edx
    code.push_back(0x3B); code.push_back(0xFA);
    // jb hash_loop
    code.push_back(0x72); code.push_back(0xD9);
    
    // not found - return NULL
    code.push_back(0x33); code.push_back(0xC0);
    code.push_back(0xEB); code.push_back(0x15);
    
    // found:
    // mov edx, [ebx + 0x24]  ; ordinal table RVA
    code.push_back(0x8B); code.push_back(0x53); code.push_back(0x24);
    // add edx, ecx
    code.push_back(0x03); code.push_back(0xD1);
    // movzx eax, word ptr [edx + edi * 2]  ; ordinal
    code.push_back(0x0F); code.push_back(0xB7); code.push_back(0x04); code.push_back(0x5A);
    
    // mov edx, [ebx + 0x1C]  ; function table RVA
    code.push_back(0x8B); code.push_back(0x53); code.push_back(0x1C);
    // add edx, ecx
    code.push_back(0x03); code.push_back(0xD1);
    // mov eax, [edx + eax * 4]  ; function RVA
    code.push_back(0x8B); code.push_back(0x04); code.push_back(0x82);
    // add eax, ecx  ; function VA
    code.push_back(0x03); code.push_back(0xC1);
    
    // pop edi
    code.push_back(0x5F);
    // pop esi
    code.push_back(0x5E);
    // pop ebx
    code.push_back(0x5B);
    // ret
    code.push_back(0xC3);
    
    return code;
}

std::vector<uint8_t> ImportObfuscator::GenerateDynamicResolver(
    const std::vector<ObfuscatedImport>& imports) {
    
    std::vector<uint8_t> code;
    
    // Build encrypted string table
    std::vector<uint8_t> stringTable;
    std::vector<uint32_t> stringOffsets;
    
    for (const auto& imp : imports) {
        stringOffsets.push_back(static_cast<uint32_t>(stringTable.size()));
        
        auto encodedDll = EncryptStringData(imp.encodedDll);
        stringTable.insert(stringTable.end(), encodedDll.begin(), encodedDll.end());
        
        auto encodedFunc = EncryptStringData(imp.encodedFunction);
        stringTable.insert(stringTable.end(), encodedFunc.begin(), encodedFunc.end());
    }
    
    // Generate resolver that:
    // 1. Decrypts DLL name
    // 2. Calls LoadLibrary
    // 3. Decrypts function name
    // 4. Calls GetProcAddress
    // 5. Stores result in IAT slot
    
    // First, find LoadLibrary and GetProcAddress using hash resolver
    
    // pushad
    code.push_back(0x60);
    
    // Get kernel32 base (from PEB)
    // mov eax, fs:[0x30]  ; PEB
    code.push_back(0x64); code.push_back(0xA1); code.push_back(0x30); 
    code.push_back(0x00); code.push_back(0x00); code.push_back(0x00);
    // mov eax, [eax + 0x0C]  ; PEB_LDR_DATA
    code.push_back(0x8B); code.push_back(0x40); code.push_back(0x0C);
    // mov eax, [eax + 0x1C]  ; InInitializationOrderModuleList
    code.push_back(0x8B); code.push_back(0x40); code.push_back(0x1C);
    // mov ebp, [eax + 0x08]  ; kernel32 base
    code.push_back(0x8B); code.push_back(0x68); code.push_back(0x08);
    
    // Resolve LoadLibraryA by hash
    // mov eax, 0x8A8B4036  ; LoadLibraryA hash
    code.push_back(0xB8); code.push_back(0x36); code.push_back(0x40);
    code.push_back(0x8B); code.push_back(0x8A);
    // mov ecx, ebp  ; kernel32 base
    code.push_back(0x8B); code.push_back(0xCD);
    // call hash_resolver
    code.push_back(0xE8);
    // ... offset to hash resolver
    
    // mov esi, eax  ; LoadLibraryA address
    
    // Resolve GetProcAddress by hash
    // mov eax, 0x7C0DFCA8  ; GetProcAddress hash
    // mov ecx, ebp
    // call hash_resolver
    // mov edi, eax  ; GetProcAddress address
    
    // Process each import
    for (size_t i = 0; i < imports.size(); ++i) {
        // Decrypt DLL name
        // lea eax, [string_table + offset]
        // call decrypt_string
        
        // push eax  ; DLL name
        // call esi  ; LoadLibraryA
        
        // Decrypt function name
        // lea eax, [string_table + offset]
        // call decrypt_string
        
        // push eax  ; function name
        // push edx  ; module handle
        // call edi  ; GetProcAddress
        
        // Store in IAT
        // mov [iat_address], eax
    }
    
    // popad
    code.push_back(0x61);
    // ret
    code.push_back(0xC3);
    
    // Append string table
    code.insert(code.end(), stringTable.begin(), stringTable.end());
    
    // Append hash resolver
    auto hashResolver = GenerateHashResolver();
    code.insert(code.end(), hashResolver.begin(), hashResolver.end());
    
    return code;
}

std::vector<uint8_t> ImportObfuscator::GenerateStolenResolver() {
    // Use alternative APIs to resolve imports
    // e.g., using NTDLL functions instead of KERNEL32
    std::vector<uint8_t> code;
    
    // Implementation would use LdrLoadDll, LdrGetProcedureAddress, etc.
    
    return code;
}

std::vector<uint8_t> ImportObfuscator::GenerateResolverStub(
    const std::vector<ObfuscatedImport>& imports) {
    
    if (m_hashImports) {
        return GenerateHashResolver();
    } else if (m_dynamicLoad) {
        return GenerateDynamicResolver(imports);
    } else if (m_stolenImports) {
        return GenerateStolenResolver();
    }
    
    return {};
}

bool ImportObfuscator::Obfuscate(std::vector<uint8_t>& peData) {
    std::vector<ImportInfo> imports;
    uint32_t iatRva, iatSize;
    
    if (!ParseImports(peData, imports, iatRva, iatSize)) {
        return false;
    }
    
    // Create obfuscated import table
    std::vector<ObfuscatedImport> obfuscated;
    
    for (const auto& imp : imports) {
        ObfuscatedImport obf;
        obf.encodedDll = m_encryptStrings ? EncodeString(imp.dllName) : imp.dllName;
        
        if (imp.byOrdinal) {
            obf.byOrdinal = true;
            obf.ordinal = imp.ordinal;
        } else {
            obf.byOrdinal = false;
            obf.encodedFunction = m_encryptStrings ? 
                EncodeString(imp.functionName) : imp.functionName;
            obf.hash = HashFunction(imp.dllName, imp.functionName);
        }
        
        obfuscated.push_back(obf);
    }
    
    // Generate resolver stub
    auto resolver = GenerateResolverStub(obfuscated);
    
    // Inject resolver into PE
    // (Simplified - real implementation would add new section or use cave)
    
    // Clear original import table
    // Set new entry point to resolver
    // Resolver fixes IAT then jumps to original entry
    
    return true;
}

} // namespace Polymorphic