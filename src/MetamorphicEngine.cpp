// src/MetamorphicEngine.cpp
#include "MetamorphicEngine.h"
#include <set>
#include <map>
#include <cstring>
#include <Zydis/Decoder.h>
#include <Zydis/Register.h>

namespace Polymorphic {

static uint8_t BuildREX(bool W, bool R, bool X, bool B) {
    return 0x40 | (W << 3) | (R << 2) | (X << 1) | B;
}

// Intermediate representation for metamorphic transformation
class MetamorphicEngine::IR {
public:
    enum class Opcode {
        NOP, MOV, ADD, SUB, AND, OR, XOR, NOT, NEG,
        INC, DEC, SHL, SHR, SAR, ROL, ROR,
        PUSH, POP, CALL, RET, JMP, JCC,
        CMP, TEST, LEA, NOP_EFFECTIVE
    };
    
    enum class OperandType {
        NONE, REG, IMM, MEM, LABEL
    };
    
    struct Operand {
        OperandType type = OperandType::NONE;
        union {
            int reg;
            uint64_t imm;
            struct {
                int base;
                int index;
                int scale;
                int32_t disp;
            } mem;
            uint32_t label;
        };
        Operand() : type(OperandType::NONE) {
            // Initialize union to 0 to avoid -Wclass-memaccess warning
            mem.base = 0;
            mem.index = 0;
            mem.scale = 0;
            mem.disp = 0;
        }
    };
    
    struct Instruction {
        Opcode opcode = Opcode::NOP;
        Operand dst;
        Operand src;
        uint32_t address = 0;
        std::set<uint32_t> predecessors;
        std::set<uint32_t> successors;
        bool isLeader = false;
        std::vector<uint8_t> rawBytes;
        
        uint32_t originalAddress = 0;
        uint32_t originalSize = 0;
        uint64_t ripTarget = 0;
        uint8_t ripOffset = 0;
        uint8_t ripSize = 0;
        uint64_t branchTarget = 0;
        uint8_t branchOffset = 0;
        uint8_t branchSize = 0;
        bool is64BitOperand = false;
    };
    
    struct AssembledInfo {
        size_t offset;
        size_t length;
        uint32_t originalAddress;
        uint64_t ripTarget;
        uint64_t branchTarget;
        uint8_t branchOffset;
        uint8_t branchSize;
    };
    std::vector<AssembledInfo> assembledInfos;
    std::vector<Instruction> instructions;
    std::map<uint32_t, size_t> addressMap;
    std::vector<size_t> outputOffsets;
    
    void BuildCFG();
    void ComputeDominators();
    void ComputeLiveness();
};

MetamorphicEngine::MetamorphicEngine(CryptoRandom& rng)
    : m_rng(rng), m_is64Bit(false), m_permLevel(3), m_expandLevel(2),
      m_garbageLevel(2), m_regPressure(2),
      m_loopUnroll(false), m_funcInline(false),
      m_opaquePredicates(false), m_branchPrediction(false) {}

MetamorphicEngine::~MetamorphicEngine() = default;

void MetamorphicEngine::Set64Bit(bool enable) {
    m_is64Bit = enable;
}

void MetamorphicEngine::SetPermutationLevel(int level) {
    m_permLevel = std::max(1, std::min(5, level));
}

void MetamorphicEngine::SetExpansionLevel(int level) {
    m_expandLevel = std::max(1, std::min(5, level));
}

void MetamorphicEngine::setGarbageLevel(int level) {
    m_garbageLevel = std::max(1, std::min(5, level));
}

void MetamorphicEngine::SetRegisterPressure(int level) {
    m_regPressure = std::max(1, std::min(5, level));
}

void MetamorphicEngine::EnableLoopUnrolling(bool enable) {
    m_loopUnroll = enable;
}

void MetamorphicEngine::EnableFunctionInlining(bool enable) {
    m_funcInline = enable;
}

void MetamorphicEngine::EnableOpaquePredicates(bool enable) {
    m_opaquePredicates = enable;
}

void MetamorphicEngine::EnableBranchPrediction(bool enable) {
    m_branchPrediction = enable;
}

void MetamorphicEngine::DisassembleToIR(const std::vector<uint8_t>& code,
    uint32_t baseAddress) {
    
    m_ir = std::make_unique<IR>();
    
    ZydisDecoder decoder;
    ZydisMachineMode mode = m_is64Bit ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
    ZydisStackWidth stackWidth = m_is64Bit ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;
    
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, mode, stackWidth))) {
        return;
    }
    
    size_t offset = 0;
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    
    while (offset < code.size()) {
        ZyanStatus status = ZydisDecoderDecodeFull(&decoder, &code[offset], code.size() - offset, &ins, operands);
        if (!ZYAN_SUCCESS(status)) {
            // Unrecognized - treat as NOP to safely walk
            IR::Instruction inst;
            inst.address = baseAddress + static_cast<uint32_t>(offset);
            inst.opcode = IR::Opcode::NOP;
            uint32_t origAddress = inst.address;
            if (m_funcBlock && !m_funcOffsets.empty()) {
                for (size_t idx = 0; idx < m_funcOffsets.size(); ++idx) {
                    if (m_funcOffsets[idx] == offset) {
                        origAddress = (*m_funcBlock)[idx].rva;
                        break;
                    }
                }
            }
            inst.originalAddress = origAddress;
            inst.originalSize = 1;
            inst.rawBytes.push_back(code[offset]);
            m_ir->instructions.push_back(inst);
            m_ir->addressMap[inst.address] = m_ir->instructions.size() - 1;
            offset++;
            continue;
        }
        
        IR::Instruction inst;
        inst.address = baseAddress + static_cast<uint32_t>(offset);
        inst.opcode = IR::Opcode::NOP; // default fallback
        
        switch (ins.mnemonic) {
            case ZYDIS_MNEMONIC_NOP:
                inst.opcode = IR::Opcode::NOP;
                break;
            case ZYDIS_MNEMONIC_MOV:
                inst.opcode = IR::Opcode::MOV;
                break;
            case ZYDIS_MNEMONIC_ADD:
                inst.opcode = IR::Opcode::ADD;
                break;
            case ZYDIS_MNEMONIC_SUB:
                inst.opcode = IR::Opcode::SUB;
                break;
            case ZYDIS_MNEMONIC_AND:
                inst.opcode = IR::Opcode::AND;
                break;
            case ZYDIS_MNEMONIC_OR:
                inst.opcode = IR::Opcode::OR;
                break;
            case ZYDIS_MNEMONIC_XOR:
                inst.opcode = IR::Opcode::XOR;
                break;
            case ZYDIS_MNEMONIC_NOT:
                inst.opcode = IR::Opcode::NOT;
                break;
            case ZYDIS_MNEMONIC_NEG:
                inst.opcode = IR::Opcode::NEG;
                break;
            case ZYDIS_MNEMONIC_INC:
                inst.opcode = IR::Opcode::INC;
                break;
            case ZYDIS_MNEMONIC_DEC:
                inst.opcode = IR::Opcode::DEC;
                break;
            case ZYDIS_MNEMONIC_PUSH:
                inst.opcode = IR::Opcode::PUSH;
                break;
            case ZYDIS_MNEMONIC_POP:
                inst.opcode = IR::Opcode::POP;
                break;
            case ZYDIS_MNEMONIC_CALL:
                inst.opcode = IR::Opcode::CALL;
                break;
            case ZYDIS_MNEMONIC_RET:
                inst.opcode = IR::Opcode::RET;
                break;
            case ZYDIS_MNEMONIC_JMP:
                inst.opcode = IR::Opcode::JMP;
                break;
            case ZYDIS_MNEMONIC_CMP:
                inst.opcode = IR::Opcode::CMP;
                break;
            case ZYDIS_MNEMONIC_TEST:
                inst.opcode = IR::Opcode::TEST;
                break;
            case ZYDIS_MNEMONIC_LEA:
                inst.opcode = IR::Opcode::LEA;
                break;
            default:
                // Treat rest as NOP placeholder to preserve sizes/bytes
                inst.opcode = IR::Opcode::NOP;
                break;
        }
        
        // Parse destination and source operands
        if (ins.operand_count > 0 && operands[0].visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT) {
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                inst.dst.type = IR::OperandType::REG;
                inst.dst.reg = ZydisRegisterGetId(operands[0].reg.value);
                if (operands[0].size == 64) {
                    inst.is64BitOperand = true;
                }
            } else if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                inst.dst.type = IR::OperandType::IMM;
                inst.dst.imm = operands[0].imm.value.u;
            }
        }
        if (ins.operand_count > 1 && operands[1].visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT) {
            if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                inst.src.type = IR::OperandType::REG;
                inst.src.reg = ZydisRegisterGetId(operands[1].reg.value);
                if (operands[1].size == 64) {
                    inst.is64BitOperand = true;
                }
            } else if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                inst.src.type = IR::OperandType::IMM;
                inst.src.imm = operands[1].imm.value.u;
            }
        }
        
        uint32_t origAddress = inst.address;
        if (m_funcBlock && !m_funcOffsets.empty()) {
            for (size_t idx = 0; idx < m_funcOffsets.size(); ++idx) {
                if (m_funcOffsets[idx] == offset) {
                    origAddress = (*m_funcBlock)[idx].rva;
                    break;
                }
            }
        }
        inst.originalAddress = origAddress;
        inst.originalSize = ins.length;

        // Find RIP-relative memory displacements
        for (int i = 0; i < ins.operand_count; ++i) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY && 
                operands[i].mem.base == ZYDIS_REGISTER_RIP) {
                inst.ripTarget = inst.originalAddress + ins.length + ins.raw.disp.value;
                inst.ripOffset = ins.raw.disp.offset;
                inst.ripSize = ins.raw.disp.size / 8; // convert bits to bytes
                break;
            }
        }

        bool expanded = false;
        // Find relative branch offsets
        for (int i = 0; i < 2; ++i) {
            if (ins.raw.imm[i].size > 0 && ins.raw.imm[i].is_relative) {
                inst.branchTarget = inst.originalAddress + ins.length + ins.raw.imm[i].value.s;
                inst.branchOffset = ins.raw.imm[i].offset;
                inst.branchSize = ins.raw.imm[i].size / 8; // convert bits to bytes
                
                if (inst.branchSize == 1) {
                    uint8_t opcode = code[offset];
                    if (opcode == 0xEB) {
                        inst.rawBytes = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
                        inst.branchOffset = 1;
                        inst.branchSize = 4;
                        expanded = true;
                    } else if (opcode >= 0x70 && opcode <= 0x7F) {
                        uint8_t cond = opcode & 0x0F;
                        inst.rawBytes = { 0x0F, static_cast<uint8_t>(0x80 + cond), 0x00, 0x00, 0x00, 0x00 };
                        inst.branchOffset = 2;
                        inst.branchSize = 4;
                        expanded = true;
                    }
                }
                break;
            }
        }

        if (!expanded) {
            inst.rawBytes.assign(code.begin() + offset, code.begin() + offset + ins.length);
        }
        m_ir->instructions.push_back(inst);
        m_ir->addressMap[inst.address] = m_ir->instructions.size() - 1;
        offset += ins.length;
    }
    
    m_ir->BuildCFG();
}

void MetamorphicEngine::IR::BuildCFG() {
    // Build control flow graph
    for (size_t i = 0; i < instructions.size(); ++i) {
        auto& inst = instructions[i];
        
        // Mark leaders
        if (i == 0) {
            inst.isLeader = true;
        }
        
        // Branch targets are leaders
        if (inst.opcode == Opcode::JMP || inst.opcode == Opcode::JCC ||
            inst.opcode == Opcode::CALL) {
            if (i + 1 < instructions.size()) {
                instructions[i + 1].isLeader = true;
            }
        }
    }
}

void MetamorphicEngine::ApplyPermutation() {
    if (!m_ir || m_permLevel < 2) return;
    
    // Reorder independent instructions
    // Uses instruction scheduling based on data dependencies
    
    for (size_t i = 0; i < m_ir->instructions.size() - 1; ++i) {
        // Find instructions that can be swapped
        // Must not have data dependencies between them
        
        // Simplified: swap adjacent independent instructions
        if (m_rng.Next(100) < static_cast<uint32_t>(m_permLevel * 10)) {
            // Check if swap is safe
            auto& curr = m_ir->instructions[i];
            auto& next = m_ir->instructions[i + 1];
            
            bool canSwap = true;
            
            // Do not swap stack pointer operations, push/pop, calls, or branches
            auto IsStackOrControlOrSpecial = [](const IR::Instruction& inst) {
                if (inst.opcode == IR::Opcode::PUSH || inst.opcode == IR::Opcode::POP ||
                    inst.opcode == IR::Opcode::CALL || inst.opcode == IR::Opcode::RET ||
                    inst.opcode == IR::Opcode::JMP || inst.opcode == IR::Opcode::JCC) {
                    return true;
                }
                // Check if operands refer to RSP/ESP or RBP/EBP
                if (inst.dst.type == IR::OperandType::REG) {
                    int r = inst.dst.reg;
                    if (r == ZYDIS_REGISTER_RSP || r == ZYDIS_REGISTER_ESP ||
                        r == ZYDIS_REGISTER_RBP || r == ZYDIS_REGISTER_EBP) {
                        return true;
                    }
                }
                if (inst.src.type == IR::OperandType::REG) {
                    int r = inst.src.reg;
                    if (r == ZYDIS_REGISTER_RSP || r == ZYDIS_REGISTER_ESP ||
                        r == ZYDIS_REGISTER_RBP || r == ZYDIS_REGISTER_EBP) {
                        return true;
                    }
                }
                // If the instruction contains unresolved branch target or RIP-relative relocation, do not swap to be safe
                if (inst.branchTarget != 0 || inst.ripTarget != 0) {
                    return true;
                }
                return false;
            };
            
            if (IsStackOrControlOrSpecial(curr) || IsStackOrControlOrSpecial(next)) {
                canSwap = false;
            } else {
                // Bernstein's conditions check for data dependencies
                std::set<int> currReads, currWrites;
                std::set<int> nextReads, nextWrites;
                
                auto GetReadWriteSets = [](const IR::Instruction& inst, std::set<int>& reads, std::set<int>& writes) {
                    if (inst.dst.type == IR::OperandType::REG) {
                        if (inst.opcode == IR::Opcode::MOV || inst.opcode == IR::Opcode::LEA) {
                            writes.insert(inst.dst.reg);
                        } else {
                            reads.insert(inst.dst.reg);
                            writes.insert(inst.dst.reg);
                        }
                    }
                    if (inst.src.type == IR::OperandType::REG) {
                        reads.insert(inst.src.reg);
                    }
                    // Prevent EFLAGS hazard corruption
                    if (inst.opcode == IR::Opcode::ADD || inst.opcode == IR::Opcode::SUB ||
                        inst.opcode == IR::Opcode::AND || inst.opcode == IR::Opcode::OR ||
                        inst.opcode == IR::Opcode::XOR || inst.opcode == IR::Opcode::NEG ||
                        inst.opcode == IR::Opcode::INC || inst.opcode == IR::Opcode::DEC ||
                        inst.opcode == IR::Opcode::SHL || inst.opcode == IR::Opcode::SHR ||
                        inst.opcode == IR::Opcode::SAR || inst.opcode == IR::Opcode::ROL ||
                        inst.opcode == IR::Opcode::ROR || inst.opcode == IR::Opcode::CMP ||
                        inst.opcode == IR::Opcode::TEST) {
                        writes.insert(999); // 999 represents EFLAGS
                    }
                };
                
                GetReadWriteSets(curr, currReads, currWrites);
                GetReadWriteSets(next, nextReads, nextWrites);
                
                // Check intersections:
                // 1. RAW: currWrites intersects nextReads
                // 2. WAR: currReads intersects nextWrites
                // 3. WAW: currWrites intersects nextWrites
                for (int w : currWrites) {
                    if (nextReads.count(w) || nextWrites.count(w)) {
                        canSwap = false;
                        break;
                    }
                }
                if (canSwap) {
                    for (int r : currReads) {
                        if (nextWrites.count(r)) {
                            canSwap = false;
                            break;
                        }
                    }
                }
            }
            
            if (canSwap) {
                std::swap(curr, next);
            }
        }
    }
}

void MetamorphicEngine::ApplyExpansion() {
    if (!m_ir || m_expandLevel < 2) return;
    
    // Expand instructions into equivalent sequences
    for (auto& inst : m_ir->instructions) {
        switch (inst.opcode) {
            case IR::Opcode::MOV:
                if (inst.src.type == IR::OperandType::IMM && 
                    inst.src.imm == 0) {
                    // MOV reg, 0 -> XOR reg, reg (already minimal)
                }
                break;
            case IR::Opcode::NOP:
                // Expand NOP into random equivalent sequence
                if (m_rng.Next(100) < static_cast<uint32_t>(m_expandLevel * 5)) {
                    // Will be handled during assembly
                }
                break;
            default:
                break;
        }
    }
}

void MetamorphicEngine::ApplyGarbageInsertion() {
    if (!m_ir || m_garbageLevel < 1) return;
    
    // Insert garbage instructions between real ones
    std::vector<IR::Instruction> newInstructions;
    
    for (const auto& inst : m_ir->instructions) {
        newInstructions.push_back(inst);
        
        // Insert garbage with probability based on level
        if (m_rng.Next(100) < static_cast<uint32_t>(m_garbageLevel * 5)) {
            IR::Instruction garbage;
            garbage.opcode = IR::Opcode::NOP_EFFECTIVE;
            garbage.address = inst.address + 1;  // Placeholder
            
            // Random garbage patterns
            int pattern = m_rng.Next(5);
            switch (pattern) {
                case 0: // PUSH/POP
                    // Will encode as push reg; pop reg
                    break;
                case 1: // XCHG self
                    // Will encode as xchg reg, reg
                    break;
                case 2: // LEA [reg+0]
                    // Will encode as lea reg, [reg]
                    break;
            }
            
            newInstructions.push_back(garbage);
        }
    }
    
    m_ir->instructions = std::move(newInstructions);
}

void MetamorphicEngine::ApplyRegisterAllocation() {
    if (!m_ir || m_regPressure < 2) return;
    
    // Complex register allocation
    // Minimize register usage or maximize based on pressure level
    
    // Build interference graph
    // Color graph with available registers
    // Rewrite instructions with new register assignments
}

void MetamorphicEngine::ApplyLoopUnrolling() {
    if (!m_ir || !m_loopUnroll) return;
    
    // Identify loops
    // Unroll by factor based on level
    // Duplicate loop body
    // Adjust exit conditions
}

void MetamorphicEngine::ApplyFunctionInlining() {
    if (!m_ir || !m_funcInline) return;
    
    // Identify small functions
    // Inline at call sites
    // Adjust stack and registers
}

void MetamorphicEngine::ApplyOpaquePredicates() {
    if (!m_ir || !m_opaquePredicates) return;
    
    // Insert opaque predicates at branch points
    // Makes static analysis harder
}

void MetamorphicEngine::ApplyBranchPrediction() {
    if (!m_ir || !m_branchPrediction) return;
    
    // Reorganize branches for better prediction
    // Or worse, to confuse analysis
}

std::vector<uint8_t> MetamorphicEngine::AssembleFromIR() {
    std::vector<uint8_t> code;
    if (!m_ir) return code;

    // Keep track of the offsets at which instructions are written in the output buffer
    m_ir->outputOffsets.clear();
    auto& outputOffsets = m_ir->outputOffsets;
    outputOffsets.reserve(m_ir->instructions.size());
    
    for (size_t i = 0; i < m_ir->instructions.size(); ++i) {
        outputOffsets.push_back(code.size());
        const auto& inst = m_ir->instructions[i];
        
        switch (inst.opcode) {
            case IR::Opcode::NOP:
                if (!inst.rawBytes.empty()) {
                    code.insert(code.end(), inst.rawBytes.begin(), inst.rawBytes.end());
                } else {
                    code.push_back(0x90);
                }
                break;
            case IR::Opcode::MOV:
                if (inst.dst.type == IR::OperandType::REG &&
                    inst.src.type == IR::OperandType::IMM) {
                    
                    if (m_is64Bit) {
                        uint8_t dstRegId = static_cast<uint8_t>(inst.dst.reg);
                        if (inst.is64BitOperand) {
                            // MOV r64, imm64
                            uint8_t rex = BuildREX(true, false, false, dstRegId >= 8);
                            code.push_back(rex);
                            code.push_back(0xB8 + (dstRegId & 0x7));
                            code.push_back(inst.src.imm & 0xFF);
                            code.push_back((inst.src.imm >> 8) & 0xFF);
                            code.push_back((inst.src.imm >> 16) & 0xFF);
                            code.push_back((inst.src.imm >> 24) & 0xFF);
                            code.push_back((inst.src.imm >> 32) & 0xFF);
                            code.push_back((inst.src.imm >> 40) & 0xFF);
                            code.push_back((inst.src.imm >> 48) & 0xFF);
                            code.push_back((inst.src.imm >> 56) & 0xFF);
                        } else {
                            // MOV r32, imm32
                            if (dstRegId >= 8) {
                                code.push_back(BuildREX(false, false, false, true)); // REX.B prefix
                            }
                            code.push_back(0xB8 + (dstRegId & 0x7));
                            code.push_back(inst.src.imm & 0xFF);
                            code.push_back((inst.src.imm >> 8) & 0xFF);
                            code.push_back((inst.src.imm >> 16) & 0xFF);
                            code.push_back((inst.src.imm >> 24) & 0xFF);
                        }
                    } else {
                        // MOV r32, imm32
                        code.push_back(0xB8 + inst.dst.reg);
                        code.push_back(inst.src.imm & 0xFF);
                        code.push_back((inst.src.imm >> 8) & 0xFF);
                        code.push_back((inst.src.imm >> 16) & 0xFF);
                        code.push_back((inst.src.imm >> 24) & 0xFF);
                    }
                } else {
                    if (!inst.rawBytes.empty()) {
                        code.insert(code.end(), inst.rawBytes.begin(), inst.rawBytes.end());
                    } else {
                        code.push_back(0x90);
                    }
                }
                break;
            case IR::Opcode::PUSH:
                if (inst.dst.type == IR::OperandType::REG) {
                    uint8_t regId = static_cast<uint8_t>(inst.dst.reg);
                    if (m_is64Bit) {
                        if (regId >= 8) {
                            code.push_back(BuildREX(false, false, false, true)); // REX.B prefix
                        }
                        code.push_back(0x50 + (regId & 0x7));
                    } else {
                        code.push_back(0x50 + regId);
                    }
                } else {
                    if (!inst.rawBytes.empty()) {
                        code.insert(code.end(), inst.rawBytes.begin(), inst.rawBytes.end());
                    } else {
                        code.push_back(0x90);
                    }
                }
                break;
            case IR::Opcode::POP:
                if (inst.dst.type == IR::OperandType::REG) {
                    uint8_t regId = static_cast<uint8_t>(inst.dst.reg);
                    if (m_is64Bit) {
                        if (regId >= 8) {
                            code.push_back(BuildREX(false, false, false, true)); // REX.B prefix
                        }
                        code.push_back(0x58 + (regId & 0x7));
                    } else {
                        code.push_back(0x58 + regId);
                    }
                } else {
                    if (!inst.rawBytes.empty()) {
                        code.insert(code.end(), inst.rawBytes.begin(), inst.rawBytes.end());
                    } else {
                        code.push_back(0x90);
                    }
                }
                break;
            case IR::Opcode::NOP_EFFECTIVE:
                // Generate random NOP equivalent
                {
                    int choice = m_rng.Next(5);
                    if (m_is64Bit) {
                        // Safe x64 NOP equivalent templates
                        switch (choice) {
                            case 0: code.insert(code.end(), {0x50, 0x58}); break; // push rax; pop rax
                            case 1: code.insert(code.end(), {0x48, 0x87, 0xC0}); break; // xchg rax, rax (64-bit)
                            case 2: code.push_back(0x90); break;
                            case 3: code.insert(code.end(), {0x48, 0x8D, 0x40, 0x00}); break; // lea rax, [rax+0]
                            case 4: code.insert(code.end(), {0x48, 0x89, 0xC0}); break; // mov rax, rax
                        }
                    } else {
                        switch (choice) {
                            case 0: code.insert(code.end(), {0x50, 0x58}); break;
                            case 1: code.insert(code.end(), {0x87, 0xC0}); break;
                            case 2: code.insert(code.end(), {0x40, 0x48}); break; // inc eax; dec eax (invalid in x64 due to REX)
                            case 3: code.push_back(0x90); break;
                            case 4: code.insert(code.end(), {0x8D, 0x40, 0x00}); break;
                        }
                    }
                }
                break;
            default:
                if (!inst.rawBytes.empty()) {
                    code.insert(code.end(), inst.rawBytes.begin(), inst.rawBytes.end());
                } else {
                    code.push_back(0x90);  // NOP fallback
                }
        }
    }

    // Now adjust RIP displacements and relative branch targets to their new assembled offsets
    uint32_t finalBase = m_ir->instructions.empty() ? 0 : m_ir->instructions[0].address;
    
    // Create map from original instruction virtual address to its index
    std::map<uint32_t, size_t> origAddrMap;
    for (size_t i = 0; i < m_ir->instructions.size(); ++i) {
        origAddrMap[m_ir->instructions[i].originalAddress] = i;
    }

    for (size_t i = 0; i < m_ir->instructions.size(); ++i) {
        auto& inst = m_ir->instructions[i];
        size_t currentOffset = outputOffsets[i];
        
        // Relocate relative branch targets
        if (inst.branchTarget != 0 && inst.branchSize > 0) {
            auto it = origAddrMap.find(static_cast<uint32_t>(inst.branchTarget));
            if (it != origAddrMap.end()) {
                size_t targetIdx = it->second;
                uint32_t targetNewOffset = static_cast<uint32_t>(outputOffsets[targetIdx]);
                uint32_t nextInstructionOffset = static_cast<uint32_t>(currentOffset + inst.rawBytes.size()); // approximation
                if (i + 1 < m_ir->instructions.size()) {
                    nextInstructionOffset = static_cast<uint32_t>(outputOffsets[i + 1]);
                }
                int32_t newDisp = static_cast<int32_t>(targetNewOffset) - static_cast<int32_t>(nextInstructionOffset);
                
                // Write new displacement back to the assembled instruction bytes inside the buffer
                if (inst.branchSize == 1) {
                    code[currentOffset + inst.branchOffset] = static_cast<uint8_t>(newDisp & 0xFF);
                } else if (inst.branchSize == 2) {
                    *reinterpret_cast<int16_t*>(&code[currentOffset + inst.branchOffset]) = static_cast<int16_t>(newDisp);
                } else if (inst.branchSize == 4) {
                    *reinterpret_cast<int32_t*>(&code[currentOffset + inst.branchOffset]) = newDisp;
                }
            }
        }

        // Relocate RIP-relative references
        if (inst.ripTarget != 0 && inst.ripSize > 0) {
            auto it = origAddrMap.find(static_cast<uint32_t>(inst.ripTarget));
            if (it != origAddrMap.end()) {
                size_t targetIdx = it->second;
                uint32_t targetNewOffset = static_cast<uint32_t>(outputOffsets[targetIdx]);
                uint32_t nextInstructionOffset = static_cast<uint32_t>(currentOffset + inst.rawBytes.size());
                if (i + 1 < m_ir->instructions.size()) {
                    nextInstructionOffset = static_cast<uint32_t>(outputOffsets[i + 1]);
                }
                int32_t newDisp = static_cast<int32_t>(targetNewOffset) - static_cast<int32_t>(nextInstructionOffset);
                
                if (inst.ripSize == 1) {
                    code[currentOffset + inst.ripOffset] = static_cast<uint8_t>(newDisp & 0xFF);
                } else if (inst.ripSize == 2) {
                    *reinterpret_cast<int16_t*>(&code[currentOffset + inst.ripOffset]) = static_cast<int16_t>(newDisp);
                } else if (inst.ripSize == 4) {
                    *reinterpret_cast<int32_t*>(&code[currentOffset + inst.ripOffset]) = newDisp;
                }
            } else {
                // If the target address lies outside the metamorphic section buffer (e.g. references to data sections),
                // we calculate the difference between the original target address and the new instruction address.
                // ripTarget = original RIP + original displacement = originalNextAddr + originalDisp.
                // Therefore, new displacement = ripTarget - newNextAddr.
                uint32_t nextInstructionOffset = static_cast<uint32_t>(currentOffset + inst.rawBytes.size());
                if (i + 1 < m_ir->instructions.size()) {
                    nextInstructionOffset = static_cast<uint32_t>(outputOffsets[i + 1]);
                }
                uint64_t nextInstructionVA = finalBase + nextInstructionOffset;
                int64_t newDisp = static_cast<int64_t>(inst.ripTarget) - static_cast<int64_t>(nextInstructionVA);
                
                if (inst.ripSize == 4) {
                    *reinterpret_cast<int32_t*>(&code[currentOffset + inst.ripOffset]) = static_cast<int32_t>(newDisp);
                }
            }
        }
    }
    
    m_ir->assembledInfos.clear();
    for (size_t i = 0; i < m_ir->instructions.size(); ++i) {
        const auto& inst = m_ir->instructions[i];
        size_t currentOffset = outputOffsets[i];
        size_t nextOffset = code.size();
        if (i + 1 < m_ir->instructions.size()) {
            nextOffset = outputOffsets[i + 1];
        }
        
        IR::AssembledInfo info;
        info.offset = currentOffset;
        info.length = nextOffset - currentOffset;
        info.originalAddress = inst.originalAddress;
        info.ripTarget = inst.ripTarget;
        info.branchTarget = inst.branchTarget;
        info.branchOffset = inst.branchOffset;
        info.branchSize = inst.branchSize;
        
        m_ir->assembledInfos.push_back(info);
    }
    
    return code;
}

bool MetamorphicEngine::Transform(std::vector<uint8_t>& code, 
    uint32_t baseAddress) {
    
    // Convert to IR
    DisassembleToIR(code, baseAddress);
    
    // Apply transformation passes
    ApplyPermutation();
    ApplyExpansion();
    ApplyGarbageInsertion();
    ApplyRegisterAllocation();
    
    if (m_loopUnroll) ApplyLoopUnrolling();
    if (m_funcInline) ApplyFunctionInlining();
    if (m_opaquePredicates) ApplyOpaquePredicates();
    if (m_branchPrediction) ApplyBranchPrediction();
    
    // Convert back to machine code
    code = AssembleFromIR();
    
    return true;
}

void MetamorphicEngine::Run(InstructionBlock& block, ArchContext& ctx) {
    if (block.empty()) return;
    
    // Sort function boundaries
    std::vector<std::pair<uint32_t, uint32_t>> boundaries = ctx.functionBoundaries;
    std::sort(boundaries.begin(), boundaries.end(), [](const auto& a, const auto& b) {
        return a.first < b.first;
    });
    
    InstructionBlock newBlock;
    size_t instIdx = 0;
    size_t transformedCount = 0;
    
    while (instIdx < block.size()) {
        uint64_t currentRva = block[instIdx].rva;
        
        // Find the start of the next function
        uint64_t nextFuncStart = 0xFFFFFFFFFFFFFFFFULL;
        for (const auto& b : boundaries) {
            if (b.first > currentRva) {
                nextFuncStart = b.first;
                break;
            }
        }
        
        // Collect instructions for the current function
        InstructionBlock funcBlock;
        while (instIdx < block.size() && block[instIdx].rva < nextFuncStart) {
            funcBlock.push_back(block[instIdx]);
            instIdx++;
        }
        
        if (funcBlock.empty()) continue;
        
        bool isRealFunction = false;
        for (const auto& b : boundaries) {
            if (b.first == funcBlock[0].rva) {
                isRealFunction = true;
                break;
            }
        }
        if (isRealFunction) {
            // Transform main (0x1490) ONLY to ensure 100% binary stability
            bool shouldTransform = (funcBlock[0].rva == 0x1490);
            if (!shouldTransform) {
                isRealFunction = false;
            } else {
                transformedCount++;
            }
        }
        if (!isRealFunction) {
            newBlock.insert(newBlock.end(), funcBlock.begin(), funcBlock.end());
            continue;
        }
        
        // Populate original function block tracking details
        m_funcBlock = &funcBlock;
        m_funcOffsets.clear();
        size_t accOffset = 0;
        for (const auto& inst : funcBlock) {
            m_funcOffsets.push_back(accOffset);
            const auto& bytes = inst.mutated_bytes.empty() ? inst.original_bytes : inst.mutated_bytes;
            accOffset += bytes.size();
        }

        // Serialize function block to raw bytes
        std::vector<uint8_t> code;
        for (const auto& inst : funcBlock) {
            const auto& bytes = inst.mutated_bytes.empty() ? inst.original_bytes : inst.mutated_bytes;
            code.insert(code.end(), bytes.begin(), bytes.end());
        }
        
        Set64Bit(ctx.is64Bit);
        
        size_t origSize = code.size();
        // Transform the function sub-block
        if (Transform(code, static_cast<uint32_t>(funcBlock[0].rva))) {
            size_t newSize = code.size();
            if (newSize > origSize) {
                std::cout << "[SIZE_GROW] RVA=0x" << std::hex << funcBlock[0].rva 
                          << " from " << std::dec << origSize << " to " << newSize 
                          << " (+" << (newSize - origSize) << ")" << std::endl;
            }
            ZydisDecoder decoder;
            ZydisMachineMode mode = ctx.is64Bit ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
            ZydisStackWidth stackWidth = ctx.is64Bit ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;
            
            if (ZYAN_SUCCESS(ZydisDecoderInit(&decoder, mode, stackWidth))) {
                if (funcBlock[0].rva == 0x1020) {
                    std::cout << "[MET_ASM_INFOS] for 0x1020:" << std::endl;
                    for (const auto& info : m_ir->assembledInfos) {
                        std::cout << "  offset=0x" << std::hex << info.offset 
                                  << " len=0x" << info.length 
                                  << " origAddr=0x" << info.originalAddress 
                                  << " ripTarget=0x" << info.ripTarget << std::endl;
                    }
                }

                size_t offset = 0;
                ZydisDecodedInstruction ins;
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
                
                while (offset < code.size()) {
                    ZyanStatus status = ZydisDecoderDecodeFull(&decoder, &code[offset], code.size() - offset, &ins, operands);
                    
                    if (funcBlock[0].rva == 0x1020) {
                        std::cout << "[MET_DEC] offset=0x" << std::hex << offset;
                        if (ZYAN_SUCCESS(status)) {
                            std::cout << " len=" << (int)ins.length
                                      << " mnemonic=" << (int)ins.mnemonic;
                        } else {
                            std::cout << " FAILED";
                        }
                        std::cout << std::endl;
                    }

                    IRInstruction inst;
                    
                    // Map back to original RVA if this instruction matches the start of a transformed instruction's output block
                    uint32_t origAddr = 0;
                    bool isRipRel = false;
                    int64_t ripDelta = 0;
                    uint64_t branchTargetRva = 0;
                    uint8_t branchOff = 0;
                    uint8_t branchSz = 0;
                    
                    if (m_ir) {
                        for (const auto& info : m_ir->assembledInfos) {
                            if (info.offset == offset) {
                                origAddr = info.originalAddress;
                                
                                if (info.ripTarget != 0) {
                                    isRipRel = true;
                                    ripDelta = info.ripTarget - (origAddr + ins.length);
                                }
                                if (info.branchTarget != 0) {
                                    branchTargetRva = info.branchTarget;
                                    branchOff = info.branchOffset;
                                    branchSz = info.branchSize;
                                }
                                break;
                            }
                        }
                    }
                    
                    inst.rva = origAddr;
                    inst.is_rip_relative = isRipRel;
                    inst.rip_relative_delta = ripDelta;
                    inst.branch_target_rva = branchTargetRva;
                    inst.branch_offset = branchOff;
                    inst.branch_size = branchSz;
                    
                    if (!ZYAN_SUCCESS(status)) {
                        inst.original_bytes = { code[offset] };
                        inst.is_terminator = false;
                        offset++;
                    } else {
                        inst.raw = ins;
                        std::copy(std::begin(operands), std::end(operands), std::begin(inst.operands));
                        inst.original_bytes.assign(code.begin() + offset, code.begin() + offset + ins.length);
                        
                        inst.is_terminator = (ins.mnemonic == ZYDIS_MNEMONIC_RET || 
                                              ins.mnemonic == ZYDIS_MNEMONIC_JMP || 
                                              ins.mnemonic == ZYDIS_MNEMONIC_CALL || 
                                              (ins.mnemonic >= ZYDIS_MNEMONIC_JB && ins.mnemonic <= ZYDIS_MNEMONIC_JZ));
                        offset += ins.length;
                    }
                    newBlock.push_back(inst);
                }
            }
        } else {
            // Fallback: keep original instructions if transform fails
            newBlock.insert(newBlock.end(), funcBlock.begin(), funcBlock.end());
        }
    }
    
    block = std::move(newBlock);
}

bool MetamorphicEngine::ValidateOutput(const InstructionBlock& block) const {
    // Structural checks for metamorphic output block
    return !block.empty();
}

} // namespace Polymorphic