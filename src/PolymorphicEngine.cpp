// PolymorphicEngine.cpp
#include "PolymorphicEngine.h"
#include "RegisterRandomizer.h"
#include "DataEncoder.h"
#include "SectionRandomizer.h"
#include "ImportObfuscator.h"
#include <fstream>
#include <iostream>
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
        RegisterRandomizer randomizer(*m_rng);
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

            uint64_t baseAddress = section->VirtualAddress;
            if (m_is64Bit) {
                baseAddress += m_optionalHeader64 ? m_optionalHeader64->ImageBase : 0x140000000;
            } else {
                baseAddress += m_optionalHeader32 ? m_optionalHeader32->ImageBase : 0x400000;
            }

            if (m_substituteInstructions) {
                m_impl->ApplyInstructionSubstitution(code);
            }

            if (m_randomizeRegisters) {
                m_impl->ApplyRegisterRandomization(code);
            }

            if (m_reorderCode) {
                m_impl->ApplyCodeReordering(code, m_functionBoundaries, baseAddress);
            }

            if (m_insertJunkCode) {
                m_impl->InsertJunkCode(code, baseAddress);
            }

            if (m_obfuscateControlFlow) {
                m_impl->ApplyControlFlowObfuscation(code, baseAddress);
            }

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
                // we do this BEFORE insert while the pointers are valid!
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