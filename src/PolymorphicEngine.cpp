// PolymorphicEngine.cpp
#include "PolymorphicEngine.h"
#include "RegisterRandomizer.h"
#include "DataEncoder.h"
#include "SectionRandomizer.h"
#include "ImportObfuscator.h"
#include "PayloadEncryptor.h"
#include "DecryptorGenerator.h"
#include "InstructionSubstitutor.h"
#include "JunkCodeInserter.h"
#include "ControlFlowObfuscator.h"
#include "CodeReorderer.h"
#include "MetamorphicEngine.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <numeric>
#include <map>
#include <set>
#include <Zydis/Decoder.h>
#include <Zydis/Register.h>

namespace Polymorphic {

    namespace {
        struct PolyInstruction {
            uint64_t originalAddress = 0;
            std::vector<uint8_t> bytes;
            bool isBranch = false;
            uint64_t branchTarget = 0;
            size_t branchOffset = 0;
            size_t branchSize = 0;
            bool isRipRelative = false;
            uint64_t ripTarget = 0;
            size_t ripOffset = 0;
            size_t ripSize = 0;
        };

        std::vector<PolyInstruction> DisassembleToPolyIR(const std::vector<uint8_t>& code, uint64_t baseAddress, bool is64Bit) {
            std::vector<PolyInstruction> ir;
            ZydisDecoder decoder;
            ZydisMachineMode mode = is64Bit ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
            ZydisStackWidth stackWidth = is64Bit ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;

            if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, mode, stackWidth))) {
                return ir;
            }

            size_t offset = 0;
            ZydisDecodedInstruction ins;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

            while (offset < code.size()) {
                ZyanStatus status = ZydisDecoderDecodeFull(&decoder, &code[offset], code.size() - offset, &ins, operands);
                PolyInstruction inst;
                inst.originalAddress = baseAddress + offset;

                if (!ZYAN_SUCCESS(status)) {
                    inst.bytes.push_back(code[offset]);
                    ir.push_back(inst);
                    offset++;
                    continue;
                }

                inst.bytes.assign(code.begin() + offset, code.begin() + offset + ins.length);

                // Extract relative branches
                for (int i = 0; i < 2; ++i) {
                    if (ins.raw.imm[i].size > 0 && ins.raw.imm[i].is_relative) {
                        inst.isBranch = true;
                        inst.branchTarget = inst.originalAddress + ins.length + ins.raw.imm[i].value.s;
                        inst.branchOffset = ins.raw.imm[i].offset;
                        inst.branchSize = ins.raw.imm[i].size / 8;
                        break;
                    }
                }

                // Extract RIP-relative memory references
                if (is64Bit && !inst.isBranch) {
                    for (int i = 0; i < ins.operand_count; ++i) {
                        if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY && 
                            operands[i].mem.base == ZYDIS_REGISTER_RIP) {
                            inst.isRipRelative = true;
                            inst.ripTarget = inst.originalAddress + ins.length + ins.raw.disp.value;
                            inst.ripOffset = ins.raw.disp.offset;
                            inst.ripSize = ins.raw.disp.size / 8;
                            break;
                        }
                    }
                }

                ir.push_back(inst);
                offset += ins.length;
            }
            return ir;
        }

        std::vector<uint8_t> AssembleFromPolyIR(std::vector<PolyInstruction>& ir, uint64_t baseAddress, bool is64Bit) {
            (void)is64Bit;
            std::vector<uint8_t> code;
            if (ir.empty()) return code;

            std::vector<size_t> newOffsets(ir.size());
            size_t currentOffset = 0;

            for (size_t i = 0; i < ir.size(); ++i) {
                newOffsets[i] = currentOffset;
                currentOffset += ir[i].bytes.size();
            }

            std::map<uint64_t, uint64_t> addressMap;
            for (size_t i = 0; i < ir.size(); ++i) {
                if (ir[i].originalAddress != 0) {
                    addressMap[ir[i].originalAddress] = baseAddress + newOffsets[i];
                }
            }

            for (size_t i = 0; i < ir.size(); ++i) {
                auto& inst = ir[i];
                uint64_t newInstVA = baseAddress + newOffsets[i];
                uint64_t nextInstVA = newInstVA + inst.bytes.size();

                if (inst.isBranch && inst.branchTarget != 0) {
                    uint64_t targetVA = inst.branchTarget;
                    if (addressMap.count(inst.branchTarget)) {
                        targetVA = addressMap[inst.branchTarget];
                    }
                    int64_t disp = static_cast<int64_t>(targetVA) - static_cast<int64_t>(nextInstVA);
                    
                    if (inst.branchSize == 1) {
                        if (disp >= -128 && disp <= 127) {
                            inst.bytes[inst.branchOffset] = static_cast<uint8_t>(disp & 0xFF);
                        }
                    } else if (inst.branchSize == 4) {
                        inst.bytes[inst.branchOffset] = static_cast<uint8_t>(disp & 0xFF);
                        inst.bytes[inst.branchOffset + 1] = static_cast<uint8_t>((disp >> 8) & 0xFF);
                        inst.bytes[inst.branchOffset + 2] = static_cast<uint8_t>((disp >> 16) & 0xFF);
                        inst.bytes[inst.branchOffset + 3] = static_cast<uint8_t>((disp >> 24) & 0xFF);
                    }
                }

                if (inst.isRipRelative && inst.ripTarget != 0) {
                    uint64_t targetVA = inst.ripTarget;
                    if (addressMap.count(inst.ripTarget)) {
                        targetVA = addressMap[inst.ripTarget];
                    }
                    int64_t disp = static_cast<int64_t>(targetVA) - static_cast<int64_t>(nextInstVA);
                    
                    if (inst.ripSize == 4) {
                        inst.bytes[inst.ripOffset] = static_cast<uint8_t>(disp & 0xFF);
                        inst.bytes[inst.ripOffset + 1] = static_cast<uint8_t>((disp >> 8) & 0xFF);
                        inst.bytes[inst.ripOffset + 2] = static_cast<uint8_t>((disp >> 16) & 0xFF);
                        inst.bytes[inst.ripOffset + 3] = static_cast<uint8_t>((disp >> 24) & 0xFF);
                    }
                }

                code.insert(code.end(), inst.bytes.begin(), inst.bytes.end());
            }

            return code;
        }
    }

    // ============ PolymorphicEngine Implementation ============

    class PolymorphicEngine::Impl {
    public:
        Impl(PolymorphicEngine* engine) : m_engine(engine), m_rng(&engine->m_rng) {}

        // Junk code templates
        std::vector<std::vector<uint8_t>> m_junkTemplates = {
            {0x50, 0x58},                    // push eax; pop eax
            {0x53, 0x5B},                    // push ebx; pop ebx
            {0x51, 0x59},                    // push ecx; pop ecx
            {0x52, 0x5A},                    // push edx; pop edx
            {0x87, 0xC0},                    // xchg eax, eax (nop)
            {0x87, 0xDB},                    // xchg ebx, ebx
            {0x8D, 0x40, 0x00},              // lea eax, [eax+0]
            {0x8D, 0x64, 0x24, 0x00},        // lea esp, [esp+0]
            {0x8B, 0xC0},                    // mov eax, eax
            {0x8B, 0xDB},                    // mov ebx, ebx
            {0x01, 0xC0, 0x29, 0xC0},        // add eax, eax; sub eax, eax
            {0x40, 0x48},                    // inc eax; dec eax
            {0xF8, 0xF9, 0xF8},              // clc; stc; clc
            {0x9C, 0x9D},                    // pushfd; popfd
            {0x60, 0x61},                    // pusha; popa
            {0x66, 0x0F, 0x1F, 0xC0},        // nop eax (multi-byte)
            {0x0F, 0x1F, 0xC0},              // nop eax
            {0x0F, 0x1F, 0x40, 0x00},        // nop dword ptr [eax]
            {0xEB, 0x00},                    // jmp +0
            {0x74, 0x00, 0xEB, 0x01, 0x90}   // jz +0; jmp +1; nop
        };

        // Encryption/decryption primitives
        struct EncryptionEngine {
            std::function<std::vector<uint8_t>(const std::vector<uint8_t>&, const std::vector<uint8_t>&)> encrypt;
            std::function<std::vector<uint8_t>(const std::vector<uint8_t>&, const std::vector<uint8_t>&)> decrypt;
            std::vector<uint8_t> generateKey(size_t length);
        };

        void ApplyInstructionSubstitution(std::vector<uint8_t>& code);
        void ApplyRegisterRandomization(std::vector<uint8_t>& code);
        void ApplyCodeReordering(std::vector<uint8_t>& code, const std::vector<size_t>& boundaries, uint64_t baseAddress);
        void InsertJunkCode(std::vector<uint8_t>& code, uint64_t baseAddress);
        void ApplyControlFlowObfuscation(std::vector<uint8_t>& code, uint64_t baseAddress);
        std::vector<uint8_t> GenerateDecryptor(const std::vector<uint8_t>& encrypted, const std::vector<uint8_t>& key);
        void EncodeDataSections(std::vector<uint8_t>& data);
        void RandomizeSectionLayout();
        void ObfuscateImports();
        bool EncryptPayload();

    private:
        PolymorphicEngine* m_engine;
        CryptoRandom* m_rng;
    };

    // ============ Transformation Implementations ============

    void PolymorphicEngine::Impl::ApplyInstructionSubstitution(std::vector<uint8_t>& code) {
        ZydisDecoder decoder;
        ZydisMachineMode mode = m_engine->Is64Bit() ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
        ZydisStackWidth stackWidth = m_engine->Is64Bit() ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;

        if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, mode, stackWidth))) {
            return;
        }

        size_t offset = 0;
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        while (offset < code.size()) {
            ZyanStatus status = ZydisDecoderDecodeFull(&decoder, &code[offset], code.size() - offset, &ins, operands);
            if (!ZYAN_SUCCESS(status)) {
                offset++;
                continue;
            }

            // Perform in-place same-size substitution to avoid binary corruption.
            if (ins.attributes & ZYDIS_ATTRIB_HAS_MODRM) {
                uint8_t& modrmByte = code[offset + ins.raw.modrm.offset];
                uint8_t mod = (modrmByte >> 6) & 0x3;
                uint8_t reg = (modrmByte >> 3) & 0x7;
                uint8_t rm = modrmByte & 0x7;

                size_t opcodeOffset = ins.raw.prefix_count;
                if (ins.attributes & ZYDIS_ATTRIB_HAS_REX) {
                    opcodeOffset++;
                }

                if (opcodeOffset < ins.length) {
                    uint8_t& opcodeByte = code[offset + opcodeOffset];

                    // XOR r/m, r -> SUB r/m, r (opcode 0x31 -> 0x29 or 0x2B or 0x33)
                    if (opcodeByte == 0x31 && mod == 0x3 && reg == rm) {
                        uint32_t choice = m_rng->Next(3);
                        if (choice == 0) {
                            opcodeByte = 0x29; // SUB r/m, r
                        } else if (choice == 1) {
                            opcodeByte = 0x2B; // SUB r, r/m
                        }
                    }
                    // TEST r/m, r -> OR r/m, r (opcode 0x85 -> 0x09 or 0x0B or 0x21 or 0x23)
                    else if (opcodeByte == 0x85 && mod == 0x3 && reg == rm) {
                        uint32_t choice = m_rng->Next(5);
                        if (choice == 0) {
                            opcodeByte = 0x09; // OR r/m, r
                        } else if (choice == 1) {
                            opcodeByte = 0x0B; // OR r, r/m
                        } else if (choice == 2) {
                            opcodeByte = 0x21; // AND r/m, r
                        } else if (choice == 3) {
                            opcodeByte = 0x23; // AND r, r/m
                        }
                    }
                    // LEA r, [r] -> MOV r, r (opcode 0x8D -> 0x8B or 0x89)
                    else if (opcodeByte == 0x8D && mod == 0x0 && reg == rm) {
                        uint32_t choice = m_rng->Next(3);
                        if (choice == 0) {
                            opcodeByte = 0x8B; // MOV r, r/m
                            modrmByte |= 0xC0; // set mod to 3
                        } else if (choice == 1) {
                            opcodeByte = 0x89; // MOV r/m, r
                            modrmByte |= 0xC0; // set mod to 3
                        }
                    }
                }
            }

            offset += ins.length;
        }
    }

    void PolymorphicEngine::Impl::ApplyRegisterRandomization(std::vector<uint8_t>& code) {
        RegisterRandomizerCore randomizer(*m_rng);
        randomizer.Set64Bit(m_engine->Is64Bit());
        code = randomizer.Randomize(code);
    }

    void PolymorphicEngine::Impl::ApplyCodeReordering(std::vector<uint8_t>& code,
        const std::vector<size_t>& /*boundaries*/, uint64_t baseAddress) {
        bool is64Bit = m_engine->Is64Bit();
        auto ir = DisassembleToPolyIR(code, baseAddress, is64Bit);
        if (ir.empty()) return;

        // Basic block identification and reordering
        struct BasicBlock {
            std::vector<PolyInstruction> instructions;
            size_t originalIndex = 0;
            bool endsWithUnconditional = false;
        };

        std::vector<BasicBlock> blocks;
        BasicBlock currentBlock;

        for (auto& inst : ir) {
            currentBlock.instructions.push_back(inst);
            
            bool isTerminator = false;
            bool isUnconditional = false;
            
            if (inst.bytes.size() > 0) {
                uint8_t op = inst.bytes[0];
                if (op == 0xC3 || op == 0xC2) { // RET
                    isTerminator = true;
                    isUnconditional = true;
                }
                else if (op == 0xEB || op == 0xE9) { // JMP
                    isTerminator = true;
                    isUnconditional = true;
                }
                else if ((op >= 0x70 && op <= 0x7F) || 
                         (op == 0x0F && inst.bytes.size() > 1 && inst.bytes[1] >= 0x80 && inst.bytes[1] <= 0x8F)) { // Jcc
                    isTerminator = true;
                }
            }
            
            if (isTerminator) {
                currentBlock.originalIndex = blocks.size();
                currentBlock.endsWithUnconditional = isUnconditional;
                blocks.push_back(std::move(currentBlock));
                currentBlock = BasicBlock();
            }
        }
        
        if (!currentBlock.instructions.empty()) {
            currentBlock.originalIndex = blocks.size();
            currentBlock.endsWithUnconditional = false;
            blocks.push_back(std::move(currentBlock));
        }

        if (blocks.size() >= 2) {
            std::vector<BasicBlock> shuffledBlocks;
            shuffledBlocks.push_back(std::move(blocks[0]));
            
            std::vector<size_t> indices(blocks.size() - 1);
            std::iota(indices.begin(), indices.end(), 1);
            std::shuffle(indices.begin(), indices.end(), std::mt19937(m_rng->Next()));

            for (size_t idx : indices) {
                shuffledBlocks.push_back(std::move(blocks[idx]));
            }

            std::vector<PolyInstruction> newIr;
            for (size_t i = 0; i < shuffledBlocks.size(); ++i) {
                auto& block = shuffledBlocks[i];
                newIr.insert(newIr.end(), block.instructions.begin(), block.instructions.end());

                if (!block.endsWithUnconditional && block.originalIndex + 1 < blocks.size()) {
                    uint64_t successorVA = 0;
                    for (const auto& originalBlock : blocks) {
                        if (originalBlock.originalIndex == block.originalIndex + 1 && !originalBlock.instructions.empty()) {
                            successorVA = originalBlock.instructions[0].originalAddress;
                            break;
                        }
                    }
                    
                    if (successorVA != 0) {
                        PolyInstruction jmpInst;
                        jmpInst.originalAddress = 0;
                        jmpInst.isBranch = true;
                        jmpInst.branchTarget = successorVA;
                        jmpInst.bytes = {0xE9, 0x00, 0x00, 0x00, 0x00};
                        jmpInst.branchOffset = 1;
                        jmpInst.branchSize = 4;
                        newIr.push_back(jmpInst);
                    }
                }
            }
            ir = std::move(newIr);
        }

        code = AssembleFromPolyIR(ir, baseAddress, is64Bit);
    }

    void PolymorphicEngine::Impl::InsertJunkCode(std::vector<uint8_t>& code, uint64_t baseAddress) {
        bool is64Bit = m_engine->Is64Bit();
        auto ir = DisassembleToPolyIR(code, baseAddress, is64Bit);
        if (ir.empty()) return;

        std::vector<PolyInstruction> newIr;
        newIr.reserve(ir.size() * 2);

        std::vector<std::vector<uint8_t>> x64Junk = {
            {0x90},                          // nop
            {0x50, 0x58},                    // push rax; pop rax
            {0x53, 0x5B},                    // push rbx; pop rbx
            {0x51, 0x59},                    // push rcx; pop rcx
            {0x52, 0x5A},                    // push rdx; pop rdx
            {0x48, 0x87, 0xC0},              // xchg rax, rax
            {0x48, 0x87, 0xDB},              // xchg rbx, rbx
            {0x48, 0x8D, 0x40, 0x00},        // lea rax, [rax+0]
            {0x48, 0x89, 0xC0},              // mov rax, rax
            {0x48, 0x89, 0xDB},              // mov rbx, rbx
            {0x48, 0xFF, 0xC0, 0x48, 0xFF, 0xC8}, // inc rax; dec rax
            {0xF8, 0xF9, 0xF8},              // clc; stc; clc
            {0x9C, 0x9D},                    // pushfq; popfq
            {0xEB, 0x00}                     // jmp +0
        };

        std::vector<std::vector<uint8_t>> x86Junk = {
            {0x90},                          // nop
            {0x50, 0x58},                    // push eax; pop eax
            {0x53, 0x5B},                    // push ebx; pop ebx
            {0x51, 0x59},                    // push ecx; pop ecx
            {0x52, 0x5A},                    // push edx; pop edx
            {0x87, 0xC0},                    // xchg eax, eax
            {0x87, 0xDB},                    // xchg ebx, ebx
            {0x8D, 0x40, 0x00},              // lea eax, [eax+0]
            {0x8B, 0xC0},                    // mov eax, eax
            {0x8B, 0xDB},                    // mov ebx, ebx
            {0x40, 0x48},                    // inc eax; dec eax
            {0xF8, 0xF9, 0xF8},              // clc; stc; clc
            {0x9C, 0x9D},                    // pushfd; popfd
            {0x60, 0x61},                    // pusha; popa
            {0xEB, 0x00}                     // jmp +0
        };

        const auto& templates = is64Bit ? x64Junk : x86Junk;

        for (auto& inst : ir) {
            newIr.push_back(inst);

            if (m_rng->Next(100) < 15) {
                size_t templateIdx = m_rng->Next(static_cast<uint32_t>(templates.size()));
                PolyInstruction junkInst;
                junkInst.originalAddress = 0;
                junkInst.bytes = templates[templateIdx];
                newIr.push_back(junkInst);
            }

            if (inst.bytes.size() == 1 && (inst.bytes[0] == 0xC3 || inst.bytes[0] == 0xC2)) {
                size_t nopCount = m_rng->Next(1, 8);
                for (size_t n = 0; n < nopCount; ++n) {
                    PolyInstruction nopInst;
                    nopInst.originalAddress = 0;
                    nopInst.bytes = {0x90};
                    newIr.push_back(nopInst);
                }
            }
        }
        ir = std::move(newIr);
        code = AssembleFromPolyIR(ir, baseAddress, is64Bit);
    }

    void PolymorphicEngine::Impl::ApplyControlFlowObfuscation(std::vector<uint8_t>& code, uint64_t baseAddress) {
        bool is64Bit = m_engine->Is64Bit();
        auto ir = DisassembleToPolyIR(code, baseAddress, is64Bit);
        if (ir.empty()) return;

        std::vector<PolyInstruction> newIr;
        newIr.reserve(ir.size() * 1.2);

        for (auto& inst : ir) {
            if (inst.isBranch && inst.bytes.size() >= 2 && (inst.bytes[0] == 0xEB || inst.bytes[0] == 0xE9)) {
                // JO Target
                PolyInstruction joInst;
                joInst.originalAddress = 0;
                joInst.isBranch = true;
                joInst.branchTarget = inst.branchTarget;
                
                // JNO Target
                PolyInstruction jnoInst;
                jnoInst.originalAddress = 0;
                jnoInst.isBranch = true;
                jnoInst.branchTarget = inst.branchTarget;

                if (inst.bytes[0] == 0xEB) {
                    joInst.bytes = {0x70, 0x00};
                    joInst.branchOffset = 1;
                    joInst.branchSize = 1;

                    jnoInst.bytes = {0x71, 0x00};
                    jnoInst.branchOffset = 1;
                    jnoInst.branchSize = 1;
                } else {
                    joInst.bytes = {0x0F, 0x80, 0x00, 0x00, 0x00, 0x00};
                    joInst.branchOffset = 2;
                    joInst.branchSize = 4;

                    jnoInst.bytes = {0x0F, 0x81, 0x00, 0x00, 0x00, 0x00};
                    jnoInst.branchOffset = 2;
                    jnoInst.branchSize = 4;
                }
                newIr.push_back(joInst);
                newIr.push_back(jnoInst);
            }
            else if (inst.isBranch && inst.bytes.size() == 2 && inst.bytes[0] >= 0x70 && inst.bytes[0] <= 0x7F) {
                uint8_t originalOpcode = inst.bytes[0];
                uint8_t oppositeOpcode = 0x70 + ((originalOpcode - 0x70) ^ 1);

                PolyInstruction jccInst;
                jccInst.originalAddress = 0;
                jccInst.bytes = {oppositeOpcode, 0x05};

                PolyInstruction jmpInst;
                jmpInst.originalAddress = 0;
                jmpInst.isBranch = true;
                jmpInst.branchTarget = inst.branchTarget;
                jmpInst.bytes = {0xE9, 0x00, 0x00, 0x00, 0x00};
                jmpInst.branchOffset = 1;
                jmpInst.branchSize = 4;

                newIr.push_back(jccInst);
                newIr.push_back(jmpInst);
            }
            else {
                newIr.push_back(inst);
            }
        }
        ir = std::move(newIr);
        code = AssembleFromPolyIR(ir, baseAddress, is64Bit);
    }

    std::vector<uint8_t> PolymorphicEngine::Impl::GenerateDecryptor(
        const std::vector<uint8_t>& encrypted, const std::vector<uint8_t>& key) {

        std::vector<uint8_t> decryptor;

        // Generate random XOR-based decryptor
        // Each generation produces different instruction sequences

        uint32_t keyValue = 0;
        for (size_t i = 0; i < key.size() && i < 4; ++i) {
            keyValue |= (static_cast<uint32_t>(key[i]) << (i * 8));
        }

        if (m_engine->m_is64Bit) {
            // Method 1: Direct XOR loop (x64)
            if (m_rng->Next(2) == 0) {
                // push rsi; push rcx; push rax
                decryptor.push_back(0x56);
                decryptor.push_back(0x51);
                decryptor.push_back(0x50);
                
                // mov rsi, encrypted_data (64-bit immediate placeholder)
                decryptor.push_back(0x48); decryptor.push_back(0xBE);
                decryptor.push_back(0x00); decryptor.push_back(0x00);
                decryptor.push_back(0x00); decryptor.push_back(0x00);
                decryptor.push_back(0x00); decryptor.push_back(0x00);
                decryptor.push_back(0x00); decryptor.push_back(0x00);
                
                // mov ecx, size
                decryptor.push_back(0xB9);
                decryptor.push_back(static_cast<uint8_t>(encrypted.size() & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((encrypted.size() >> 8) & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((encrypted.size() >> 16) & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((encrypted.size() >> 24) & 0xFF));
                
                // mov eax, key
                decryptor.push_back(0xB8);
                decryptor.push_back(static_cast<uint8_t>(keyValue & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((keyValue >> 8) & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((keyValue >> 16) & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((keyValue >> 24) & 0xFF));
                
                // decrypt_loop:
                // xor [rsi], eax
                decryptor.push_back(0x31); decryptor.push_back(0x06);
                // add rsi, 4
                decryptor.push_back(0x48); decryptor.push_back(0x83); decryptor.push_back(0xC6); decryptor.push_back(0x04);
                // dec rcx
                decryptor.push_back(0x48); decryptor.push_back(0xFF); decryptor.push_back(0xC9);
                // jnz decrypt_loop
                decryptor.push_back(0x75); decryptor.push_back(0xF5);
                
                // pop rax; pop rcx; pop rsi
                decryptor.push_back(0x58);
                decryptor.push_back(0x59);
                decryptor.push_back(0x5E);
            }
            // Method 2: Rolling XOR (x64)
            else {
                // push rsi; push rcx; push rax
                decryptor.push_back(0x56);
                decryptor.push_back(0x51);
                decryptor.push_back(0x50);
                
                // mov rsi, encrypted_data (64-bit immediate placeholder)
                decryptor.push_back(0x48); decryptor.push_back(0xBE);
                decryptor.push_back(0x00); decryptor.push_back(0x00);
                decryptor.push_back(0x00); decryptor.push_back(0x00);
                decryptor.push_back(0x00); decryptor.push_back(0x00);
                decryptor.push_back(0x00); decryptor.push_back(0x00);
                
                // mov ecx, size
                decryptor.push_back(0xB9);
                decryptor.push_back(static_cast<uint8_t>(encrypted.size() & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((encrypted.size() >> 8) & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((encrypted.size() >> 16) & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((encrypted.size() >> 24) & 0xFF));
                
                // mov al, key_byte
                decryptor.push_back(0xB0);
                decryptor.push_back(static_cast<uint8_t>(keyValue & 0xFF));
                
                // decrypt_loop:
                // xor [rsi], al
                decryptor.push_back(0x30); decryptor.push_back(0x06);
                // rol al, 1
                decryptor.push_back(0xD0); decryptor.push_back(0xC0);
                // inc rsi
                decryptor.push_back(0x48); decryptor.push_back(0xFF); decryptor.push_back(0xC6);
                // dec rcx
                decryptor.push_back(0x48); decryptor.push_back(0xFF); decryptor.push_back(0xC9);
                // jnz decrypt_loop
                decryptor.push_back(0x75); decryptor.push_back(0xF4);
                
                // pop rax; pop rcx; pop rsi
                decryptor.push_back(0x58);
                decryptor.push_back(0x59);
                decryptor.push_back(0x5E);
            }
        } else {
            // Method 1: Direct XOR loop (x86)
            if (m_rng->Next(2) == 0) {
                // pushad
                decryptor.push_back(0x60);
                // mov esi, encrypted_data
                decryptor.push_back(0xBE);
                decryptor.push_back(0x00); decryptor.push_back(0x00);
                decryptor.push_back(0x00); decryptor.push_back(0x00); // placeholder
                // mov ecx, size
                decryptor.push_back(0xB9);
                decryptor.push_back(static_cast<uint8_t>(encrypted.size() & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((encrypted.size() >> 8) & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((encrypted.size() >> 16) & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((encrypted.size() >> 24) & 0xFF));
                // mov eax, key
                decryptor.push_back(0xB8);
                decryptor.push_back(static_cast<uint8_t>(keyValue & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((keyValue >> 8) & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((keyValue >> 16) & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((keyValue >> 24) & 0xFF));
                // decrypt_loop:
                // xor [esi], eax
                decryptor.push_back(0x31); decryptor.push_back(0x06);
                // add esi, 4
                decryptor.push_back(0x83); decryptor.push_back(0xC6); decryptor.push_back(0x04);
                // dec ecx
                decryptor.push_back(0x49);
                // jnz decrypt_loop
                decryptor.push_back(0x75); decryptor.push_back(0xF7);
                // popad
                decryptor.push_back(0x61);
            }
            // Method 2: Rolling XOR (x86)
            else {
                // pushad
                decryptor.push_back(0x60);
                // mov esi, encrypted_data
                decryptor.push_back(0xBE);
                decryptor.push_back(0x00); decryptor.push_back(0x00);
                decryptor.push_back(0x00); decryptor.push_back(0x00);
                // mov ecx, size
                decryptor.push_back(0xB9);
                decryptor.push_back(static_cast<uint8_t>(encrypted.size() & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((encrypted.size() >> 8) & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((encrypted.size() >> 16) & 0xFF));
                decryptor.push_back(static_cast<uint8_t>((encrypted.size() >> 24) & 0xFF));
                // mov al, key_byte
                decryptor.push_back(0xB0);
                decryptor.push_back(static_cast<uint8_t>(keyValue & 0xFF));
                // decrypt_loop:
                // xor [esi], al
                decryptor.push_back(0x30); decryptor.push_back(0x06);
                // rol al, 1
                decryptor.push_back(0xD0); decryptor.push_back(0xC0);
                // inc esi
                decryptor.push_back(0x46);
                // dec ecx
                decryptor.push_back(0x49);
                // jnz decrypt_loop
                decryptor.push_back(0x75); decryptor.push_back(0xF7);
                // popad
                decryptor.push_back(0x61);
            }
        }

        return decryptor;
    }

    void PolymorphicEngine::Impl::EncodeDataSections(std::vector<uint8_t>& data) {
        DataEncoder encoder(*m_rng);
        encoder.SetIs64Bit(m_engine->Is64Bit());
        data = encoder.Encode(data, DataEncoder::Encoding::XOR);
    }

    void PolymorphicEngine::Impl::RandomizeSectionLayout() {
        SectionRandomizer randomizer(*m_rng);
        randomizer.Randomize(m_engine->m_rawBinary);
    }

    void PolymorphicEngine::Impl::ObfuscateImports() {
        ImportObfuscator obfuscator(*m_rng);
        obfuscator.EnableAntiDebug(m_engine->m_antiDebug);
        obfuscator.Obfuscate(m_engine->m_rawBinary);
    }

    bool PolymorphicEngine::Impl::EncryptPayload() {
        if (!m_engine->m_encryptPayload) return true;
        
        IMAGE_SECTION_HEADER* targetSec = nullptr;
        for (auto* sec : m_engine->m_sections) {
            if (sec->Characteristics & 0x20000000) {
                targetSec = sec;
                break;
            }
        }
        if (!targetSec) return true;
        
        PayloadEncryptor encryptor(*m_rng);
        encryptor.SetAlgorithm(PayloadEncryptor::Algorithm::XOR);
        encryptor.SetKeySize(16);
        
        std::vector<uint8_t> originalCode(
            m_engine->m_rawBinary.begin() + targetSec->PointerToRawData,
            m_engine->m_rawBinary.begin() + targetSec->PointerToRawData + targetSec->SizeOfRawData
        );
        
        auto encResult = encryptor.Encrypt(originalCode, targetSec->VirtualAddress);
        
        std::copy(encResult.encryptedData.begin(), encResult.encryptedData.end(),
            m_engine->m_rawBinary.begin() + targetSec->PointerToRawData);
            
        targetSec->Characteristics |= 0x80000000;
        
        DecryptorGenerator generator(*m_rng);
        generator.SetIs64Bit(m_engine->m_is64Bit);
        
        uint32_t originalEntryPoint = m_engine->m_is64Bit ?
            (m_engine->m_optionalHeader64 ? m_engine->m_optionalHeader64->AddressOfEntryPoint : 0) :
            (m_engine->m_optionalHeader32 ? m_engine->m_optionalHeader32->AddressOfEntryPoint : 0);
            
        IMAGE_SECTION_HEADER* lastSec = m_engine->m_sections.back();
        uint32_t secAlign = m_engine->m_is64Bit ? 
            m_engine->m_optionalHeader64->SectionAlignment : m_engine->m_optionalHeader32->SectionAlignment;
        uint32_t fileAlign = m_engine->m_is64Bit ? 
            m_engine->m_optionalHeader64->FileAlignment : m_engine->m_optionalHeader32->FileAlignment;
        // Cache section fields NOW before any resize that could reallocate the vector
        // and invalidate targetSec / lastSec pointers.
        uint32_t targetSecRva       = targetSec->VirtualAddress;
        uint32_t targetSecRawSize   = targetSec->SizeOfRawData;
        uint32_t lastSecVA          = lastSec->VirtualAddress;
        uint32_t lastSecVSize       = lastSec->VirtualSize;
        uint32_t lastSecRawPtr      = lastSec->PointerToRawData;
        uint32_t lastSecRawSize     = lastSec->SizeOfRawData;

        // Place stub IMMEDIATELY after the last section's existing raw data.
        // This keeps the file-to-virtual mapping consistent within the section:
        //   file[PointerToRawData + X]  <-->  VA[VirtualAddress + X]
        uint32_t lastSecRawEnd   = lastSecRawPtr + lastSecRawSize;
        uint32_t stubFileOffset  = (lastSecRawEnd + fileAlign - 1) & ~(fileAlign - 1);
        // stubRva must satisfy: stubRva - lastSecVA == stubFileOffset - lastSecRawPtr
        uint32_t stubRva = lastSecVA + (stubFileOffset - lastSecRawPtr);

        // Pad raw binary up to stubFileOffset (may reallocate the vector)
        m_engine->m_rawBinary.resize(stubFileOffset, 0x00);

        auto stub = generator.Generate(
            encResult.key,
            PayloadEncryptor::Algorithm::XOR,
            targetSecRva,
            targetSecRawSize,
            originalEntryPoint,
            stubRva
        );

        // Append stub
        m_engine->m_rawBinary.insert(m_engine->m_rawBinary.end(), stub.begin(), stub.end());

        // Align file end
        uint32_t stubRawSize = static_cast<uint32_t>((stub.size() + fileAlign - 1) & ~(fileAlign - 1));
        m_engine->m_rawBinary.resize(stubFileOffset + stubRawSize, 0x00);

        // Refresh all pointers after reallocation
        m_engine->ParsePE();
        lastSec = m_engine->m_sections.back();

        // Expand the last section to cover stub bytes
        uint32_t newRawSize = stubFileOffset - lastSecRawPtr + stubRawSize;
        uint32_t newVSize   = stubRva - lastSecVA + static_cast<uint32_t>(stub.size());
        lastSec->VirtualSize    = newVSize;
        lastSec->SizeOfRawData  = newRawSize;
        lastSec->Characteristics |= 0xE0000020; // CODE | EXECUTE | READ | WRITE

        // Update Optional Header
        m_engine->ParsePE();
        lastSec = m_engine->m_sections.back();

        uint32_t newSizeOfImage = (lastSec->VirtualAddress + lastSec->VirtualSize + secAlign - 1) & ~(secAlign - 1);

        if (m_engine->m_is64Bit) {
            m_engine->m_optionalHeader64->SizeOfImage = newSizeOfImage;
            m_engine->m_optionalHeader64->AddressOfEntryPoint = stubRva;
            m_engine->m_optionalHeader64->DllCharacteristics &= ~0x0040u; // Clear DYNAMIC_BASE
            m_engine->m_optionalHeader64->DataDirectory[9].VirtualAddress = 0; // Clear TLS
            m_engine->m_optionalHeader64->DataDirectory[9].Size = 0;
        } else {
            m_engine->m_optionalHeader32->SizeOfImage = newSizeOfImage;
            m_engine->m_optionalHeader32->AddressOfEntryPoint = stubRva;
            m_engine->m_optionalHeader32->DllCharacteristics &= ~0x0040u; // Clear DYNAMIC_BASE
            m_engine->m_optionalHeader32->DataDirectory[9].VirtualAddress = 0; // Clear TLS
            m_engine->m_optionalHeader32->DataDirectory[9].Size = 0;
        }

        std::cout << "[DEBUG] EncryptPayload: stubRva=0x" << std::hex << stubRva
                  << " fileOff=0x" << stubFileOffset
                  << " stubSize=" << std::dec << stub.size()
                  << " origEP=0x" << std::hex << originalEntryPoint << std::dec << std::endl;

        return true;
    }

    // (Pattern matching and manual substitution helpers removed in favor of Zydis disassembler backend)

    // ============ Main Engine Methods ============

    PolymorphicEngine::PolymorphicEngine()
        : m_dosHeader(nullptr)
        , m_fileHeader(nullptr)
        , m_is64Bit(false)
        , m_optionalHeader32(nullptr)
        , m_optionalHeader64(nullptr)
        , m_substituteInstructions(true)
        , m_randomizeRegisters(true)
        , m_reorderCode(true)
        , m_insertJunkCode(true)
        , m_obfuscateControlFlow(true)
        , m_encryptPayload(true)
        , m_encodeData(true)
        , m_randomizeSections(true)
        , m_obfuscateImports(true)
        , m_antiDebug(false)
        , m_isMetamorphic(false)
        , m_permuteLevel(3)
        , m_expandLevel(2)
        , m_garbageLevel(2)
        , m_unrollLoops(false)
        , m_inlineFunctions(false)
        , m_impl(std::make_unique<Impl>(this)) {
    }

    PolymorphicEngine::~PolymorphicEngine() = default;

    bool PolymorphicEngine::LoadExecutable(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file) return false;

        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);

        m_rawBinary.resize(size);
        file.read(reinterpret_cast<char*>(m_rawBinary.data()), size);

        return ParsePE();
    }

    bool PolymorphicEngine::ParsePE() {
        if (m_rawBinary.size() < sizeof(IMAGE_DOS_HEADER)) return false;

        m_dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(m_rawBinary.data());
        if (m_dosHeader->e_magic != 0x5A4D) return false; // "MZ"

        uint32_t peOffset = m_dosHeader->e_lfanew;
        if (peOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) > m_rawBinary.size()) {
            return false;
        }

        uint32_t* peSignature = reinterpret_cast<uint32_t*>(m_rawBinary.data() + peOffset);
        if (*peSignature != 0x00004550) return false; // "PE\0\0"

        m_fileHeader = reinterpret_cast<IMAGE_FILE_HEADER*>(
            m_rawBinary.data() + peOffset + 4);

        uint16_t* magicPtr = reinterpret_cast<uint16_t*>(
            reinterpret_cast<uint8_t*>(m_fileHeader) + sizeof(IMAGE_FILE_HEADER));
        if (peOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + sizeof(uint16_t) > m_rawBinary.size()) {
            return false;
        }

        uint16_t magic = *magicPtr;
        if (magic == 0x20B) { // IMAGE_NT_OPTIONAL_HDR64_MAGIC
            m_is64Bit = true;
            m_optionalHeader64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(magicPtr);
            m_optionalHeader32 = nullptr;
        } else if (magic == 0x10B) { // IMAGE_NT_OPTIONAL_HDR32_MAGIC
            m_is64Bit = false;
            m_optionalHeader32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(magicPtr);
            m_optionalHeader64 = nullptr;
        } else {
            return false; // Unknown magic
        }

        // Parse section headers
        IMAGE_SECTION_HEADER* section = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            reinterpret_cast<uint8_t*>(magicPtr) + m_fileHeader->SizeOfOptionalHeader);

        m_sections.clear();
        m_sections.reserve(m_fileHeader->NumberOfSections);
        for (int i = 0; i < m_fileHeader->NumberOfSections; ++i) {
            m_sections.push_back(section + i);
        }

        return true;
    }

    uint32_t PolymorphicEngine::GetFileAlignment() const {
        if (m_is64Bit) {
            return m_optionalHeader64 ? m_optionalHeader64->FileAlignment : 512;
        } else {
            return m_optionalHeader32 ? m_optionalHeader32->FileAlignment : 512;
        }
    }

    bool PolymorphicEngine::Process() {
        if (!AnalyzeCode()) return false;
        return ApplyTransformations();
    }

    bool PolymorphicEngine::AnalyzeCode() {
        // Find code section
        for (auto* section : m_sections) {
            if (section->Characteristics & 0x20000000) { // IMAGE_SCN_MEM_EXECUTE
                size_t codeStart = section->PointerToRawData;
                size_t codeSize = section->SizeOfRawData;

                // Disassemble and analyze
                // Simplified - real implementation needs full disassembler
                m_functionBoundaries.push_back(codeStart);
                m_functionBoundaries.push_back(codeStart + codeSize);
            }
        }
        return true;
    }

    bool PolymorphicEngine::ApplyTransformations() {
        // Use index-based iteration because m_sections pointers can be invalidated on m_rawBinary reallocation.
        for (size_t i = 0; i < m_sections.size(); ++i) {
            auto* section = m_sections[i];
            if (!(section->Characteristics & 0x20000000)) continue; // Skip non-executable

            size_t start = section->PointerToRawData;
            size_t size = section->SizeOfRawData;

            std::vector<uint8_t> code(m_rawBinary.begin() + start,
                m_rawBinary.begin() + start + size);

            // Use pure RVA (no ImageBase) for instruction addresses so that rvaMap,
            // branch_target_rva, and MapRVA callers (entryPoint, pdata, reloc) are all
            // in the same RVA coordinate space.
            uint64_t baseAddress = section->VirtualAddress;
            uint64_t imageBase = m_is64Bit ?
                (m_optionalHeader64 ? m_optionalHeader64->ImageBase : 0x140000000ULL) :
                (m_optionalHeader32 ? m_optionalHeader32->ImageBase : 0x400000ULL);

            // Initialize ArchContext early
            ArchContext ctx;
            ctx.is64Bit = m_is64Bit;
            ctx.imageBase = imageBase;
            ctx.sectionAlignment = m_is64Bit ? 
                (m_optionalHeader64 ? m_optionalHeader64->SectionAlignment : 0x1000) :
                (m_optionalHeader32 ? m_optionalHeader32->SectionAlignment : 0x1000);
            ctx.fileAlignment = GetFileAlignment();
            ctx.maxRawSize = size;
            if (m_isMetamorphic) {
                if (size > 0x2000) {
                    ctx.maxRawSize = size - 0x2000;
                } else {
                    ctx.maxRawSize = size * 3 / 4;
                }
            }
            
            // Populate function boundaries from .pdata before disassembling
            if (m_is64Bit && m_optionalHeader64) {
                uint32_t pdataRva = m_optionalHeader64->DataDirectory[3].VirtualAddress;
                uint32_t pdataSize = m_optionalHeader64->DataDirectory[3].Size;
                if (pdataRva != 0 && pdataSize != 0) {
                    for (auto* sec : m_sections) {
                        if (pdataRva >= sec->VirtualAddress && 
                            pdataRva < sec->VirtualAddress + sec->VirtualSize) {
                            uint32_t fileOff = sec->PointerToRawData + (pdataRva - sec->VirtualAddress);
                            if (fileOff + pdataSize <= m_rawBinary.size()) {
                                struct RF { uint32_t Begin, End, Unwind; };
                                uint32_t pos = fileOff;
                                while (pos + sizeof(RF) <= fileOff + pdataSize) {
                                    auto* rf = reinterpret_cast<const RF*>(&m_rawBinary[pos]);
                                    if (rf->Begin != 0 && rf->End > rf->Begin) {
                                        ctx.functionBoundaries.push_back({rf->Begin, rf->End});
                                        
                                        // Check if this function has exception handlers or chained unwind info
                                        if (rf->Unwind != 0) {
                                            uint32_t unwRva = rf->Unwind;
                                            for (auto* sec2 : m_sections) {
                                                if (unwRva >= sec2->VirtualAddress && 
                                                    unwRva < sec2->VirtualAddress + sec2->VirtualSize) {
                                                    uint32_t unwFileOffset = sec2->PointerToRawData + (unwRva - sec2->VirtualAddress);
                                                    if (unwFileOffset + 4 <= m_rawBinary.size()) {
                                                        uint8_t verFlags = m_rawBinary[unwFileOffset];
                                                        uint8_t flags = verFlags >> 3;
                                                         if (flags != 0) {
                                                             ctx.exceptionHandlerFuncRVAs.insert(rf->Begin);
                                                         }
                                                    }
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    pos += sizeof(RF);
                                }
                            }
                            break;
                        }
                    }
                }
            }
            std::cout << "[DEBUG] Loaded " << ctx.functionBoundaries.size() << " function boundaries from .pdata." << std::endl;
            std::cout << "[DEBUG] Found " << ctx.exceptionHandlerFuncRVAs.size() << " functions with exception handlers." << std::endl;

            // 1. Disassemble the raw section bytes into the unified InstructionBlock once!
            // Guide disassembly by function boundaries to keep decoder synchronized and skip padding/data!
            InstructionBlock irBlock;
            ZydisDecoder decoder;
            ZydisMachineMode mode = m_is64Bit ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
            ZydisStackWidth stackWidth = m_is64Bit ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;
            if (ZYAN_SUCCESS(ZydisDecoderInit(&decoder, mode, stackWidth))) {
                // Sort boundaries by begin RVA
                std::vector<std::pair<uint32_t, uint32_t>> sortedBoundaries = ctx.functionBoundaries;
                std::sort(sortedBoundaries.begin(), sortedBoundaries.end(), [](const auto& a, const auto& b) {
                    return a.first < b.first;
                });
                
                size_t offset = 0;
                ZydisDecodedInstruction ins;
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
                
                if (!sortedBoundaries.empty()) {
                    for (const auto& func : sortedBoundaries) {
                        uint32_t funcBeginOffset = func.first - baseAddress;
                        uint32_t funcEndOffset = func.second - baseAddress;
                        
                        // Copy any bytes before the function as raw unmutated data (e.g. padding/constants)
                        while (offset < funcBeginOffset && offset < code.size()) {
                            IRInstruction inst;
                            inst.rva = baseAddress + offset;
                            inst.original_bytes = { code[offset] };
                            inst.is_terminator = false;
                            inst.is_rip_relative = false;
                            irBlock.push_back(inst);
                            offset++;
                        }
                        
                        // Disassemble the function instructions in sync
                        while (offset < funcEndOffset && offset < code.size()) {
                            ZyanStatus status = ZydisDecoderDecodeFull(&decoder, &code[offset], code.size() - offset, &ins, operands);
                            IRInstruction inst;
                            inst.rva = baseAddress + offset;
                            
                            if (!ZYAN_SUCCESS(status)) {
                                inst.original_bytes = { code[offset] };
                                inst.is_terminator = false;
                                inst.is_rip_relative = false;
                                offset++;
                            } else {
                                inst.raw = ins;
                                std::copy(std::begin(operands), std::end(operands), std::begin(inst.operands));
                                inst.original_bytes.assign(code.begin() + offset, code.begin() + offset + ins.length);
                                
                                inst.is_terminator = (ins.mnemonic == ZYDIS_MNEMONIC_RET || 
                                                      ins.mnemonic == ZYDIS_MNEMONIC_JMP || 
                                                      ins.mnemonic == ZYDIS_MNEMONIC_CALL || 
                                                      (ins.mnemonic >= ZYDIS_MNEMONIC_JB && ins.mnemonic <= ZYDIS_MNEMONIC_JZ));
                                
                                inst.is_rip_relative = false;
                                if (m_is64Bit) {
                                    for (int opIdx = 0; opIdx < ins.operand_count; ++opIdx) {
                                        if (operands[opIdx].type == ZYDIS_OPERAND_TYPE_MEMORY && 
                                            operands[opIdx].mem.base == ZYDIS_REGISTER_RIP) {
                                            inst.is_rip_relative = true;
                                            inst.rip_relative_delta = ins.raw.disp.value;
                                            break;
                                        }
                                    }
                                }
                                
                                // Populate branch relocation details
                                for (int opIdx = 0; opIdx < 2; ++opIdx) {
                                    if (ins.raw.imm[opIdx].size > 0 && ins.raw.imm[opIdx].is_relative) {
                                        inst.branch_target_rva = inst.rva + ins.length + ins.raw.imm[opIdx].value.s;
                                        inst.branch_offset = ins.raw.imm[opIdx].offset;
                                        inst.branch_size = ins.raw.imm[opIdx].size / 8;
                                        break;
                                    }
                                }
                                offset += ins.length;
                            }
                            irBlock.push_back(inst);
                        }
                    }
                }
                
                // Copy any remaining trailing bytes in the section
                while (offset < code.size()) {
                    IRInstruction inst;
                    inst.rva = baseAddress + offset;
                    inst.original_bytes = { code[offset] };
                    inst.is_terminator = false;
                    inst.is_rip_relative = false;
                    irBlock.push_back(inst);
                    offset++;
                }
            }
            
            // 2. Set up pipeline in PassManager
            PassManager pm;
            // Trace original RIP-relative instructions
            for (const auto& inst : irBlock) {
                if (inst.is_rip_relative && inst.rva >= 0x1000 && inst.rva <= 0x1200) {
                    std::cout << "[ORIG_RIP] rva=0x" << std::hex << inst.rva << " bytes: ";
                    for (auto b : inst.original_bytes) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
                    }
                    std::cout << std::dec << std::endl;
                }
            }

            // Populate validInstructionRVAs for CodeReorderer safety checks
            for (const auto& inst : irBlock) {
                if (inst.rva != 0) {
                    ctx.validInstructionRVAs.insert(inst.rva);
                }
            }
            
            if (m_isMetamorphic) {
                auto metaPass = std::make_unique<MetamorphicEngine>(m_rng);
                metaPass->SetPermutationLevel(m_permuteLevel);
                metaPass->SetExpansionLevel(m_expandLevel);
                metaPass->setGarbageLevel(m_garbageLevel);
                metaPass->EnableLoopUnrolling(m_unrollLoops);
                metaPass->EnableFunctionInlining(m_inlineFunctions);
                metaPass->EnableOpaquePredicates(true);
                metaPass->EnableBranchPrediction(true);
                pm.Register(std::move(metaPass));
            }
            if (m_substituteInstructions) {
                pm.Register(std::make_unique<InstructionSubstitutor>(m_rng));
            }
            if (m_insertJunkCode) {
                pm.Register(std::make_unique<JunkCodeInserter>(m_rng));
            }
            if (m_obfuscateControlFlow) {
                pm.Register(std::make_unique<ControlFlowObfuscator>(m_rng));
            }
            if (m_reorderCode) {
                pm.Register(std::make_unique<CodeReorderer>(m_rng));
            }
            if (m_randomizeRegisters) {
                pm.Register(std::make_unique<RegisterRandomizer>(m_rng));
            }
            
            // VerifierPass always runs last
            pm.Register(std::make_unique<VerifierPass>());
            
            // 3. Run all passes
            pm.RunAll(irBlock, ctx);
            
            // 4. Assemble/Re-emit once at the end!
            std::vector<uint8_t> newCode;
            
            std::map<uint64_t, uint64_t> rvaMap;
            uint64_t currentRva = baseAddress;
            for (size_t k = 0; k < irBlock.size(); ++k) {
                if (irBlock[k].rva != 0) {
                    rvaMap[irBlock[k].rva] = currentRva;
                }
                const auto& bytes = irBlock[k].mutated_bytes.empty() ? irBlock[k].original_bytes : irBlock[k].mutated_bytes;
                currentRva += bytes.size();
            }

            uint32_t textStart = m_sections.empty() ? 0x1000 : m_sections[0]->VirtualAddress;
            uint32_t textLimit = m_sections.size() > 1 ? m_sections[1]->VirtualAddress : 0xFFFFFFFF;

            // Helper lambda for robust RVA mapping (pure RVA space, no ImageBase)
            auto MapRVA = [&](uint32_t rva) -> uint32_t {
                if (rva == 0) return 0;
                if (rva < textStart || rva >= textLimit) {
                    return rva;
                }
                if (rvaMap.count(rva)) {
                    return static_cast<uint32_t>(rvaMap[rva]);
                }
                // Fallback: find the closest instruction RVA (upper_bound)
                auto it = rvaMap.upper_bound(rva);
                if (it != rvaMap.begin()) {
                    --it;
                    uint64_t origInstRva = it->first;
                    uint64_t newInstRva = it->second;
                    return static_cast<uint32_t>(newInstRva + (rva - origInstRva));
                }
                return rva;
            };

            // Strict RVA mapping (only if it is a known instruction start RVA)
            auto MapRVAStrict = [&](uint32_t rva) -> uint32_t {
                if (rva == 0) return 0;
                if (rvaMap.count(rva)) {
                    return static_cast<uint32_t>(rvaMap[rva]);
                }
                return rva;
            };

            // Custom end RVA mapping (maps end of function to newBegin + newSize)
            auto MapEndRVA = [&](uint32_t beginRva, uint32_t endRva) -> uint32_t {
                if (endRva == 0) return 0;
                uint64_t maxNewEnd = 0;
                for (const auto& inst : irBlock) {
                    if (inst.rva >= beginRva && inst.rva < endRva) {
                        if (rvaMap.count(inst.rva)) {
                            uint64_t newInstRva = rvaMap[inst.rva];
                            uint64_t newSize = inst.mutated_bytes.empty() ? inst.original_bytes.size() : inst.mutated_bytes.size();
                            if (newInstRva + newSize > maxNewEnd) {
                                maxNewEnd = newInstRva + newSize;
                            }
                        }
                    }
                }
                if (maxNewEnd != 0) {
                    return static_cast<uint32_t>(maxNewEnd);
                }
                return endRva;
            };

            // Update AddressOfEntryPoint if it was inside the modified section
            uint32_t entryPoint = m_is64Bit ? 
                (m_optionalHeader64 ? m_optionalHeader64->AddressOfEntryPoint : 0) :
                (m_optionalHeader32 ? m_optionalHeader32->AddressOfEntryPoint : 0);
            if (entryPoint != 0) {
                uint32_t newEntryPoint = MapRVAStrict(entryPoint);
                std::cout << "[DEBUG] EntryPoint original RVA: 0x" << std::hex << entryPoint 
                          << ", new RVA: 0x" << newEntryPoint << std::dec << std::endl;
                if (m_is64Bit && m_optionalHeader64) {
                    m_optionalHeader64->AddressOfEntryPoint = newEntryPoint;
                } else if (!m_is64Bit && m_optionalHeader32) {
                    m_optionalHeader32->AddressOfEntryPoint = newEntryPoint;
                }
            }

            // Update x64 exception handling directory (.pdata) table entries
            if (m_is64Bit && m_optionalHeader64) {
                uint32_t exceptionRva = m_optionalHeader64->DataDirectory[3].VirtualAddress;
                uint32_t exceptionSize = m_optionalHeader64->DataDirectory[3].Size;
                if (exceptionRva != 0 && exceptionSize != 0) {
                    IMAGE_SECTION_HEADER* exceptionSec = nullptr;
                    for (auto* sec : m_sections) {
                        if (exceptionRva >= sec->VirtualAddress && 
                            exceptionRva < sec->VirtualAddress + sec->VirtualSize) {
                            exceptionSec = sec;
                            break;
                        }
                    }
                    if (exceptionSec) {
                        uint32_t fileOffset = exceptionSec->PointerToRawData + (exceptionRva - exceptionSec->VirtualAddress);
                        if (fileOffset + exceptionSize <= m_rawBinary.size()) {
                            struct RUNTIME_FUNCTION {
                                uint32_t BeginAddress;
                                uint32_t EndAddress;
                                uint32_t UnwindInfoAddress;
                            };
                            
                            std::vector<RUNTIME_FUNCTION> rfList;
                            uint32_t pos = fileOffset;
                            while (pos + sizeof(RUNTIME_FUNCTION) <= fileOffset + exceptionSize) {
                                RUNTIME_FUNCTION* rf = reinterpret_cast<RUNTIME_FUNCTION*>(&m_rawBinary[pos]);
                                
                                if (rf->UnwindInfoAddress != 0) {
                                    uint32_t unwRva = rf->UnwindInfoAddress;
                                    IMAGE_SECTION_HEADER* unwSec = nullptr;
                                    for (auto* sec : m_sections) {
                                        if (unwRva >= sec->VirtualAddress && 
                                            unwRva < sec->VirtualAddress + sec->VirtualSize) {
                                            unwSec = sec;
                                            break;
                                        }
                                    }
                                    if (unwSec) {
                                        uint32_t unwFileOffset = unwSec->PointerToRawData + (unwRva - unwSec->VirtualAddress);
                                        if (unwFileOffset + 4 <= m_rawBinary.size()) {
                                            uint8_t verFlags = m_rawBinary[unwFileOffset];
                                            uint8_t flags = verFlags >> 3;
                                            uint8_t countOfCodes = m_rawBinary[unwFileOffset + 2];
                                            if ((flags & 3) != 0) {
                                                uint32_t codesAligned = (countOfCodes + 1) & 0xFE;
                                                uint32_t handlerOffset = unwFileOffset + 4 + (codesAligned * 2);
                                                if (handlerOffset + 4 <= m_rawBinary.size()) {
                                                    uint32_t* handlerRvaPtr = reinterpret_cast<uint32_t*>(&m_rawBinary[handlerOffset]);
                                                    *handlerRvaPtr = MapRVAStrict(*handlerRvaPtr);
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                 RUNTIME_FUNCTION mappedRf;
                                 if (rvaMap.count(rf->BeginAddress)) {
                                     mappedRf.BeginAddress = static_cast<uint32_t>(rvaMap[rf->BeginAddress]);
                                     mappedRf.EndAddress = MapEndRVA(rf->BeginAddress, rf->EndAddress);
                                 } else {
                                     mappedRf.BeginAddress = rf->BeginAddress;
                                     mappedRf.EndAddress = rf->EndAddress;
                                 }
                                 mappedRf.UnwindInfoAddress = rf->UnwindInfoAddress;
                                 rfList.push_back(mappedRf);
                                pos += sizeof(RUNTIME_FUNCTION);
                            }
                            
                            // Sort the exception table by BeginAddress in ascending order
                            std::sort(rfList.begin(), rfList.end(), [](const RUNTIME_FUNCTION& a, const RUNTIME_FUNCTION& b) {
                                return a.BeginAddress < b.BeginAddress;
                            });
                            
                            // Write the sorted table back to the binary
                            pos = fileOffset;
                            for (const auto& rf : rfList) {
                                RUNTIME_FUNCTION* dest = reinterpret_cast<RUNTIME_FUNCTION*>(&m_rawBinary[pos]);
                                *dest = rf;
                                pos += sizeof(RUNTIME_FUNCTION);
                            }
                        }
                    }
                }
            }

            currentRva = baseAddress;
            int shortBranchOverflows = 0;
            int ripRefMismatches = 0;
            for (size_t k = 0; k < irBlock.size(); ++k) {
                auto& inst = irBlock[k];
                auto bytes = inst.mutated_bytes.empty() ? inst.original_bytes : inst.mutated_bytes;
                uint64_t nextRva = currentRva + bytes.size();
                
                // Patch branch target if present
                if (inst.branch_target_rva != 0 && inst.branch_size > 0 && inst.branch_offset < bytes.size()) {
                    uint64_t targetNewRva = inst.branch_target_rva;
                    bool shouldPatch = true;
                    if (rvaMap.count(inst.branch_target_rva)) {
                        targetNewRva = rvaMap[inst.branch_target_rva];
                    } else if (inst.branch_size == 1) {
                        shouldPatch = false;
                    }
                    if (shouldPatch) {
                        int64_t disp = static_cast<int64_t>(targetNewRva) - static_cast<int64_t>(nextRva);
                        if (inst.branch_size == 1) {
                            if (disp < -128 || disp > 127) {
                                ++shortBranchOverflows;
                                if (shortBranchOverflows <= 3) {
                                    bool targetInMap = rvaMap.count(inst.branch_target_rva) > 0;
                                    uint64_t origNewPos = 0;
                                    if (rvaMap.count(inst.rva)) origNewPos = rvaMap[inst.rva];
                                    std::cout << "[OVERFLOW#" << shortBranchOverflows
                                              << "] src=0x" << std::hex << inst.rva
                                              << " (now@0x" << currentRva << ")"
                                              << " tgt=0x" << inst.branch_target_rva
                                              << " (mapped=" << (targetInMap ? "yes" : "no")
                                              << " newTgt=0x" << targetNewRva << ")"
                                              << " disp=" << std::dec << disp << std::endl;
                                }

                            }
                            bytes[inst.branch_offset] = static_cast<uint8_t>(disp & 0xFF);
                        } else if (inst.branch_size == 4) {
                            *reinterpret_cast<int32_t*>(&bytes[inst.branch_offset]) = static_cast<int32_t>(disp);
                        }
                    }
                }
                
                // Patch RIP-relative memory displacements if present
                if (inst.is_rip_relative && inst.raw.raw.disp.size > 0) {
                    uint64_t origTargetVal = inst.rva + inst.raw.length + inst.rip_relative_delta;
                    uint64_t newTargetVal = origTargetVal;
                    if (rvaMap.count(origTargetVal)) {
                        newTargetVal = rvaMap[origTargetVal];
                    }
                    int64_t newDisp = static_cast<int64_t>(newTargetVal) - static_cast<int64_t>(nextRva);
                    if (newDisp < INT32_MIN || newDisp > INT32_MAX) {
                        ++ripRefMismatches;
                    }
                    uint8_t dispOffset = inst.raw.raw.disp.offset;
                    uint8_t dispSize = inst.raw.raw.disp.size / 8;
                    
                    if (inst.rva >= 0x1000 && inst.rva <= 0x1200) {
                        std::cout << "[RIP_PATCH] rva=0x" << std::hex << inst.rva 
                                  << " dispOffset=" << (int)dispOffset 
                                  << " dispSize=" << (int)dispSize
                                  << " original_bytes: ";
                        for (auto b : inst.original_bytes) {
                            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
                        }
                        std::cout << "newDisp=0x" << std::hex << newDisp << std::dec << std::endl;
                    }

                    if (dispOffset + dispSize <= bytes.size()) {
                        if (dispSize == 1) {
                            bytes[dispOffset] = static_cast<uint8_t>(newDisp & 0xFF);
                        } else if (dispSize == 4) {
                            *reinterpret_cast<int32_t*>(&bytes[dispOffset]) = static_cast<int32_t>(newDisp);
                        }
                    }
                }
                
                newCode.insert(newCode.end(), bytes.begin(), bytes.end());
                currentRva = nextRva;
            }
            if (shortBranchOverflows > 0) {
                std::cout << "[WARN] " << shortBranchOverflows << " short-branch (rel8) OVERFLOWS after reorder!" << std::endl;
            } else {
                std::cout << "[DEBUG] No short-branch overflows. All rel8 targets in range." << std::endl;
            }
            if (ripRefMismatches > 0) {
                std::cout << "[WARN] " << ripRefMismatches << " RIP-relative refs overflow int32_t after reorder!" << std::endl;
            }
            code = std::move(newCode);

            // Update section size if code expanded
            size_t newCodeSize = code.size();

            uint32_t fileAlign = GetFileAlignment();
            size_t newAlignedSize = (newCodeSize + fileAlign - 1) & ~(fileAlign - 1);
            size_t alignedCapacity = (size + fileAlign - 1) & ~(fileAlign - 1);
            if (alignedCapacity == 0) alignedCapacity = fileAlign;

            size_t finalRawSize = alignedCapacity;
            if (newCodeSize > alignedCapacity) {
                finalRawSize = newAlignedSize;
                uint32_t diff = static_cast<uint32_t>(newAlignedSize - alignedCapacity);
                
                // Shift physical offsets of all sections starting after this one in the file
                for (auto* sec : m_sections) {
                    if (sec->PointerToRawData > start) {
                        sec->PointerToRawData += diff;
                    }
                }
                
                // Shift the symbol table offset if it is after the modified section
                IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(m_rawBinary.data());
                IMAGE_FILE_HEADER* fileHeader = reinterpret_cast<IMAGE_FILE_HEADER*>(
                    m_rawBinary.data() + dosHeader->e_lfanew + 4);
                if (fileHeader->PointerToSymbolTable > start) {
                    fileHeader->PointerToSymbolTable += diff;
                }
                
                // Now insert the bytes (reallocates m_rawBinary)
                m_rawBinary.insert(m_rawBinary.begin() + start + alignedCapacity, diff, 0);
                
                ParsePE(); // Re-parse PE headers to update pointers inside m_rawBinary
                section = m_sections[i];
            }

            // Pad polymorphic code to match the raw section size
            if (code.size() < finalRawSize) {
                code.resize(finalRawSize, 0x90); // pad with NOPs
            }

            // Write back
            std::copy(code.begin(), code.end(), m_rawBinary.begin() + start);
            section->SizeOfRawData = static_cast<uint32_t>(finalRawSize);
            section->VirtualSize = std::max(section->VirtualSize, static_cast<uint32_t>(newCodeSize));

            // Fix relocations and rebuild the .reloc table
            uint32_t relocRva = m_is64Bit ? 
                (m_optionalHeader64 ? m_optionalHeader64->DataDirectory[5].VirtualAddress : 0) :
                (m_optionalHeader32 ? m_optionalHeader32->DataDirectory[5].VirtualAddress : 0);
            uint32_t relocSize = m_is64Bit ? 
                (m_optionalHeader64 ? m_optionalHeader64->DataDirectory[5].Size : 0) :
                (m_optionalHeader32 ? m_optionalHeader32->DataDirectory[5].Size : 0);

            if (relocRva != 0 && relocSize != 0) {
                IMAGE_SECTION_HEADER* relocSec = nullptr;
                for (auto* sec : m_sections) {
                    if (relocRva >= sec->VirtualAddress && 
                        relocRva < sec->VirtualAddress + sec->VirtualSize) {
                        relocSec = sec;
                        break;
                    }
                }
                if (relocSec) {
                    uint32_t fileOffset = relocSec->PointerToRawData + (relocRva - relocSec->VirtualAddress);
                    if (fileOffset + relocSize <= m_rawBinary.size()) {
                        struct NewReloc {
                            uint32_t rva;
                            uint16_t type;
                        };
                        std::vector<NewReloc> allRelocs;
                        
                        size_t pos = fileOffset;
                        while (pos < fileOffset + relocSize) {
                            if (pos + sizeof(PE::IMAGE_BASE_RELOCATION) > fileOffset + relocSize) break;
                            
                            auto* reloc = reinterpret_cast<PE::IMAGE_BASE_RELOCATION*>(&m_rawBinary[pos]);
                            if (reloc->VirtualAddress == 0) break;
                            if (reloc->SizeOfBlock < sizeof(PE::IMAGE_BASE_RELOCATION)) break;
                            
                            uint32_t numEntries = (reloc->SizeOfBlock - sizeof(PE::IMAGE_BASE_RELOCATION)) / 2;
                            uint16_t* entries = reinterpret_cast<uint16_t*>(&m_rawBinary[pos + sizeof(PE::IMAGE_BASE_RELOCATION)]);
                            
                            uint32_t oldPageRva = reloc->VirtualAddress;
                            
                            for (uint32_t i = 0; i < numEntries; ++i) {
                                uint16_t entry = entries[i];
                                uint16_t type = (entry >> 12) & 0xF;
                                uint16_t offset = entry & 0xFFF;
                                
                                if (type != 0) {
                                    uint32_t origRva = oldPageRva + offset;
                                    uint32_t newRva = MapRVA(origRva);
                                    allRelocs.push_back({ newRva, type });
                                    
                                    IMAGE_SECTION_HEADER* targetSec = nullptr;
                                    for (auto* sec : m_sections) {
                                        if (newRva >= sec->VirtualAddress && 
                                            newRva < sec->VirtualAddress + sec->VirtualSize) {
                                            targetSec = sec;
                                            break;
                                        }
                                    }
                                    if (targetSec) {
                                        uint32_t targetFileOffset = targetSec->PointerToRawData + (newRva - targetSec->VirtualAddress);
                                        uint64_t imgBase = imageBase;
                                            
                                        if (type == 3 && targetFileOffset + 4 <= m_rawBinary.size()) {
                                            uint32_t* addr = reinterpret_cast<uint32_t*>(&m_rawBinary[targetFileOffset]);
                                            uint32_t oldValue = *addr;
                                            if (oldValue >= imgBase && oldValue < imgBase + 0xFFFFFFFF) {
                                                uint32_t valRva = static_cast<uint32_t>(oldValue - imgBase);
                                                *addr = static_cast<uint32_t>(imgBase + MapRVA(valRva));
                                            } else {
                                                *addr = MapRVA(oldValue);
                                            }
                                        }
                                        else if (type == 10 && targetFileOffset + 8 <= m_rawBinary.size()) {
                                            uint64_t* addr64 = reinterpret_cast<uint64_t*>(&m_rawBinary[targetFileOffset]);
                                            uint64_t oldValue64 = *addr64;
                                            if (oldValue64 >= imgBase) {
                                                uint64_t valRva = oldValue64 - imgBase;
                                                *addr64 = imgBase + MapRVA(static_cast<uint32_t>(valRva));
                                            }
                                        }
                                    }
                                }
                            }
                            pos += reloc->SizeOfBlock;
                        }
                        
                        std::sort(allRelocs.begin(), allRelocs.end(), [](const NewReloc& a, const NewReloc& b) {
                            return a.rva < b.rva;
                        });
                        
                        std::map<uint32_t, std::vector<uint16_t>> pageRelocs;
                        for (const auto& r : allRelocs) {
                            uint32_t pageRva = r.rva & ~0xFFF;
                            uint16_t offset = r.rva & 0xFFF;
                            pageRelocs[pageRva].push_back((r.type << 12) | offset);
                        }
                        
                        std::vector<uint8_t> newRelocData;
                        for (auto const& [pageRva, entries] : pageRelocs) {
                            size_t startOffset = newRelocData.size();
                            newRelocData.resize(startOffset + sizeof(PE::IMAGE_BASE_RELOCATION));
                            
                            auto* hdr = reinterpret_cast<PE::IMAGE_BASE_RELOCATION*>(&newRelocData[startOffset]);
                            hdr->VirtualAddress = pageRva;
                            
                            size_t numEntries = entries.size();
                            size_t paddedEntries = (numEntries % 2 != 0) ? (numEntries + 1) : numEntries;
                            hdr->SizeOfBlock = static_cast<uint32_t>(sizeof(PE::IMAGE_BASE_RELOCATION) + paddedEntries * 2);
                            
                            for (auto entry : entries) {
                                uint8_t bytes[2];
                                bytes[0] = entry & 0xFF;
                                bytes[1] = (entry >> 8) & 0xFF;
                                newRelocData.insert(newRelocData.end(), bytes, bytes + 2);
                            }
                            if (numEntries % 2 != 0) {
                                uint8_t bytes[2] = {0, 0};
                                newRelocData.insert(newRelocData.end(), bytes, bytes + 2);
                            }
                        }
                        
                        if (newRelocData.size() <= relocSec->SizeOfRawData) {
                            std::copy(newRelocData.begin(), newRelocData.end(), m_rawBinary.begin() + fileOffset);
                            std::memset(m_rawBinary.data() + fileOffset + newRelocData.size(), 0, relocSec->SizeOfRawData - newRelocData.size());
                        } else {
                            size_t fileAlign = GetFileAlignment();
                            size_t newAlignedSize = (newRelocData.size() + fileAlign - 1) & ~(fileAlign - 1);
                            size_t diff = newAlignedSize - relocSec->SizeOfRawData;
                            
                            m_rawBinary.insert(m_rawBinary.begin() + fileOffset + relocSec->SizeOfRawData, diff, 0);
                            
                            ParsePE();
                            relocSec = m_sections.back();
                            
                            std::copy(newRelocData.begin(), newRelocData.end(), m_rawBinary.begin() + fileOffset);
                            std::memset(m_rawBinary.data() + fileOffset + newRelocData.size(), 0, newAlignedSize - newRelocData.size());
                            
                            relocSec->SizeOfRawData = static_cast<uint32_t>(newAlignedSize);
                            relocSec->VirtualSize = std::max(relocSec->VirtualSize, static_cast<uint32_t>(newRelocData.size()));
                        }
                        
                        if (m_is64Bit && m_optionalHeader64) {
                            m_optionalHeader64->DataDirectory[5].Size = static_cast<uint32_t>(newRelocData.size());
                        } else if (!m_is64Bit && m_optionalHeader32) {
                            m_optionalHeader32->DataDirectory[5].Size = static_cast<uint32_t>(newRelocData.size());
                        }
                    }
                }
            }
        }

        // Apply data transformations
        for (size_t i = 0; i < m_sections.size(); ++i) {
            auto* section = m_sections[i];
            if (section->Characteristics & 0x20000000) continue; // Skip code

            size_t start = section->PointerToRawData;
            size_t size = section->SizeOfRawData;

            if (size == 0) continue;

            std::vector<uint8_t> data(m_rawBinary.begin() + start,
                m_rawBinary.begin() + start + size);

            if (m_encodeData) {
                m_impl->EncodeDataSections(data);
            }

            std::copy(data.begin(), data.end(), m_rawBinary.begin() + start);
        }

        if (m_randomizeSections) {
            m_impl->RandomizeSectionLayout();
            ParsePE(); // Refresh all pointers since SectionRandomizer creates new raw binary data!
        }

        if (m_obfuscateImports) {
            m_impl->ObfuscateImports();
            ParsePE(); // Refresh all pointers just in case ObfuscateImports modified the PE layout
        }
        
        if (m_encryptPayload) {
            m_impl->EncryptPayload();
            ParsePE();
        }

        return RebuildPE();
    }

    bool PolymorphicEngine::RebuildPE() {
        // Recalculate checksums and fix RVAs
        // Update PE headers with new layout

        // Randomize timestamp
        m_fileHeader->TimeDateStamp = m_rng.Next();

        return true;
    }

    bool PolymorphicEngine::SaveExecutable(const std::string& filepath) {
        std::ofstream file(filepath, std::ios::binary);
        if (!file) return false;

        file.write(reinterpret_cast<const char*>(m_rawBinary.data()), m_rawBinary.size());
        return file.good();
    }

} // namespace Polymorphic