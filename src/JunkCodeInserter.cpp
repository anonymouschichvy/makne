#include "JunkCodeInserter.h"
#include <algorithm>
#include <cstring>
#include <Zydis/Register.h>

namespace Polymorphic {

struct LiveSet {
    uint32_t dead_gprs_mask = 0; // bit mask of registers that are written-before-read
    bool flags_dead = false;     // status flags dead
};

static LiveSet AnalyzeLiveness(const InstructionBlock& block, size_t idx, bool is64Bit) {
    LiveSet live;
    uint32_t written = 0;
    uint32_t read = 0;
    
    ZydisMachineMode mode = is64Bit ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32;

    auto ProcessReg = [&](ZydisRegister reg, bool isWrite) {
        if (reg == ZYDIS_REGISTER_NONE) return;
        ZydisRegisterClass regClass = ZydisRegisterGetClass(reg);
        if (regClass == ZYDIS_REGCLASS_GPR8 ||
            regClass == ZYDIS_REGCLASS_GPR16 ||
            regClass == ZYDIS_REGCLASS_GPR32 ||
            regClass == ZYDIS_REGCLASS_GPR64) {
            
            ZydisRegister baseReg = ZydisRegisterGetLargestEnclosing(mode, reg);
            if (baseReg == ZYDIS_REGISTER_NONE) baseReg = reg;
            uint8_t regId = ZydisRegisterGetId(baseReg);
            if (regId < 16) {
                if (isWrite) {
                    written |= (1 << regId);
                } else {
                    if (!(written & (1 << regId))) {
                        read |= (1 << regId);
                    }
                }
            }
        }
    };

    // Scan forward inside the current basic block block to find written-before-read registers
    for (size_t i = idx + 1; i < block.size() && i < idx + 12; ++i) {
        const auto& inst = block[i];
        if (inst.is_terminator) break;
        
        for (int opIdx = 0; opIdx < inst.raw.operand_count; ++opIdx) {
            const auto& op = inst.operands[opIdx];
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                bool isWrite = (op.actions & ZYDIS_OPERAND_ACTION_WRITE) != 0;
                ProcessReg(op.reg.value, isWrite);
            } 
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                // Memory base and index registers are always read
                ProcessReg(op.mem.base, false);
                ProcessReg(op.mem.index, false);
            }
        }
    }
    
    live.dead_gprs_mask = written & ~read;
    return live;
}

JunkCodeInserter::JunkCodeInserter(CryptoRandom& rng) : m_rng(rng), m_density(0.15f) {}

void JunkCodeInserter::SetDensity(float density) {
    m_density = std::max(0.0f, std::min(1.0f, density));
}

void JunkCodeInserter::Run(InstructionBlock& block, ArchContext& ctx) {
    InstructionBlock newBlock;
    newBlock.reserve(block.size() * 1.5);
    
    // Multi-byte NOP templates (Tier 0: always safe, doesn't clobber registers or flags)
    std::vector<std::vector<uint8_t>> tier0Templates = {
        {0x90},                                         // NOP
        {0x66, 0x90},                                   // 2-byte NOP
        {0x0F, 0x1F, 0x00},                             // 3-byte NOP
        {0x0F, 0x1F, 0x40, 0x00},                       // 4-byte NOP
        {0x0F, 0x1F, 0x44, 0x00, 0x00},                 // 5-byte NOP
        {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00},           // 6-byte NOP
        {0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00}      // 7-byte NOP
    };
    
    // Stack push/pop and flag-safe pairs (Tier 1: preserves registers and flags)
    std::vector<std::vector<uint8_t>> x64Tier1Templates = {
        {0x50, 0x58},                         // push rax; pop rax
        {0x53, 0x5B},                         // push rbx; pop rbx
        {0x51, 0x59},                         // push rcx; pop rcx
        {0x52, 0x5A},                         // push rdx; pop rdx
        {0x48, 0x8D, 0x40, 0x00},             // lea rax, [rax+0]
        {0x48, 0x8D, 0x5B, 0x00},             // lea rbx, [rbx+0]
        {0x9C, 0x9D}                          // pushfq; popfq
    };
    
    std::vector<std::vector<uint8_t>> x86Tier1Templates = {
        {0x50, 0x58},                         // push eax; pop eax
        {0x53, 0x5B},                         // push ebx; pop ebx
        {0x51, 0x59},                         // push ecx; pop ecx
        {0x52, 0x5A},                         // push edx; pop edx
        {0x8D, 0x40, 0x00},                   // lea eax, [eax+0]
        {0x8D, 0x5B, 0x00},                   // lea ebx, [ebx+0]
        {0x9C, 0x9D},                         // pushfd; popfd
        {0x60, 0x61}                          // pushad; popad
    };
    
    const auto& tier1Templates = ctx.is64Bit ? x64Tier1Templates : x86Tier1Templates;
    
    size_t currentTotalSize = 0;
    for (const auto& inst : block) {
        currentTotalSize += inst.mutated_bytes.empty() ? inst.original_bytes.size() : inst.mutated_bytes.size();
    }
    
    for (size_t i = 0; i < block.size(); ++i) {
        newBlock.push_back(block[i]);
        
        // Decide whether to insert junk instruction at this instruction boundary
        if (m_rng.Next(100) < static_cast<uint32_t>(m_density * 100)) {
            LiveSet liveness = AnalyzeLiveness(block, i, ctx.is64Bit);
            
            IRInstruction junkInst;
            junkInst.rva = block[i].rva + block[i].original_bytes.size();
            junkInst.is_terminator = false;
            junkInst.is_rip_relative = false;
            
            // Choose template based on register availability (Tiers 0-2)
            uint32_t choice = m_rng.Next(3);
            if (choice == 0) {
                // Tier 0 NOP
                size_t idx = m_rng.Next(static_cast<uint32_t>(tier0Templates.size()));
                junkInst.mutated_bytes = tier0Templates[idx];
            } 
            else if (choice == 1) {
                // Tier 1 Push/Pop or Lea
                size_t idx = m_rng.Next(static_cast<uint32_t>(tier1Templates.size()));
                junkInst.mutated_bytes = tier1Templates[idx];
            } 
            else {
                // Tier 2: Clobber a dead register if one exists
                bool clobbered = false;
                for (uint8_t regId = 0; regId < 8; ++regId) {
                    if (regId == ZydisRegisterGetId(ZYDIS_REGISTER_ESP) ||
                        regId == ZydisRegisterGetId(ZYDIS_REGISTER_EBP) ||
                        regId == ZydisRegisterGetId(ZYDIS_REGISTER_RSP) ||
                        regId == ZydisRegisterGetId(ZYDIS_REGISTER_RBP)) {
                        continue;
                    }
                    if (liveness.dead_gprs_mask & (1 << regId)) {
                        // Safe to clobber regId! Emit: mov reg, 0
                        std::vector<uint8_t> bytes;
                        if (ctx.is64Bit) {
                            bytes.push_back(0x48); // REX.W
                        }
                        bytes.push_back(0xB8 + regId); // mov reg, imm
                        bytes.push_back(0); bytes.push_back(0); bytes.push_back(0); bytes.push_back(0);
                        if (ctx.is64Bit) {
                            bytes.push_back(0); bytes.push_back(0); bytes.push_back(0); bytes.push_back(0);
                        }
                        junkInst.mutated_bytes = bytes;
                        clobbered = true;
                        break;
                    }
                }
                if (!clobbered) {
                    // Fallback to Tier 0 NOP
                    size_t idx = m_rng.Next(static_cast<uint32_t>(tier0Templates.size()));
                    junkInst.mutated_bytes = tier0Templates[idx];
                }
            }
            
            // Verify size constraint
            size_t junkSize = junkInst.mutated_bytes.size();
            if (currentTotalSize + junkSize <= ctx.maxRawSize) {
                newBlock.push_back(junkInst);
                currentTotalSize += junkSize;
            }
        }
    }
    block = std::move(newBlock);
}

bool JunkCodeInserter::ValidateOutput(const InstructionBlock& block) const {
    return !block.empty();
}

} // namespace Polymorphic