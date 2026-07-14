#include "ControlFlowObfuscator.h"
#include <algorithm>
#include <cstring>

namespace Polymorphic {

ControlFlowObfuscator::ControlFlowObfuscator(CryptoRandom& rng) : m_rng(rng), m_level(3) {}

void ControlFlowObfuscator::SetLevel(int level) {
    m_level = std::max(1, std::min(5, level));
}

void ControlFlowObfuscator::Run(InstructionBlock& block, ArchContext& ctx) {
    InstructionBlock newBlock;
    newBlock.reserve(block.size() * 1.3);
    
    size_t currentTotalSize = 0;
    for (const auto& inst : block) {
        currentTotalSize += inst.mutated_bytes.empty() ? inst.original_bytes.size() : inst.mutated_bytes.size();
    }
    
    for (size_t i = 0; i < block.size(); ++i) {
        const auto& inst = block[i];
        
        // Find JMP relative instructions (unconditional)
        if (inst.raw.mnemonic == ZYDIS_MNEMONIC_JMP && 
            inst.raw.operand_count > 0 && inst.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            
            uint64_t targetRva = inst.branch_target_rva;
            if (targetRva == 0 && inst.is_rip_relative) {
                targetRva = inst.rva + inst.raw.length + inst.rip_relative_delta;
            }
            
            if (targetRva != 0 && m_level >= 3) {
                // Split JMP target -> JO target; JNO target (using safe near Jcc with 4-byte displacements)
                IRInstruction joInst;
                joInst.rva = inst.rva;
                joInst.raw = inst.raw;
                joInst.raw.mnemonic = ZYDIS_MNEMONIC_JO;
                joInst.mutated_bytes = {0x0F, 0x80, 0x00, 0x00, 0x00, 0x00};
                joInst.branch_offset = 2;
                joInst.branch_size = 4;
                joInst.branch_target_rva = targetRva;
                joInst.is_terminator = true;
                joInst.is_rip_relative = true;
                
                IRInstruction jnoInst;
                jnoInst.rva = 0; // Set to 0 to avoid rvaMap collision
                jnoInst.raw = inst.raw;
                jnoInst.raw.mnemonic = ZYDIS_MNEMONIC_JNO;
                jnoInst.mutated_bytes = {0x0F, 0x81, 0x00, 0x00, 0x00, 0x00};
                jnoInst.branch_offset = 2;
                jnoInst.branch_size = 4;
                jnoInst.branch_target_rva = targetRva;
                jnoInst.is_terminator = true;
                jnoInst.is_rip_relative = true;
                
                size_t originalSize = inst.mutated_bytes.empty() ? inst.original_bytes.size() : inst.mutated_bytes.size();
                size_t newSize = joInst.mutated_bytes.size() + jnoInst.mutated_bytes.size();
                if (currentTotalSize - originalSize + newSize <= ctx.maxRawSize) {
                    newBlock.push_back(joInst);
                    newBlock.push_back(jnoInst);
                    currentTotalSize = currentTotalSize - originalSize + newSize;
                    continue;
                }
            }
        }
        // Find conditional short jumps (Jcc short)
        else if (inst.raw.mnemonic >= ZYDIS_MNEMONIC_JB && inst.raw.mnemonic <= ZYDIS_MNEMONIC_JZ &&
                 inst.original_bytes.size() == 2 && inst.original_bytes[0] >= 0x70 && inst.original_bytes[0] <= 0x7F) {
            
            uint64_t targetRva = inst.branch_target_rva;
            if (targetRva == 0 && inst.is_rip_relative) {
                targetRva = inst.rva + inst.raw.length + inst.rip_relative_delta;
            }
            
            if (targetRva != 0 && m_level >= 2) {
                // Invert condition: opposite Jcc short jump skipping 5 bytes, followed by JMP rel32 target
                uint8_t originalOpcode = inst.original_bytes[0];
                uint8_t oppositeOpcode = 0x70 + ((originalOpcode - 0x70) ^ 1);
                
                IRInstruction jccInst;
                jccInst.rva = inst.rva;
                jccInst.raw = inst.raw;
                jccInst.original_bytes = {oppositeOpcode, 0x05};
                jccInst.mutated_bytes = {oppositeOpcode, 0x05};
                jccInst.is_terminator = false;
                jccInst.is_rip_relative = false;
                
                IRInstruction jmpInst;
                jmpInst.rva = 0; // Set to 0 to avoid rvaMap collision
                jmpInst.raw = inst.raw;
                jmpInst.raw.mnemonic = ZYDIS_MNEMONIC_JMP;
                jmpInst.mutated_bytes = {0xE9, 0x00, 0x00, 0x00, 0x00};
                jmpInst.branch_offset = 1;
                jmpInst.branch_size = 4;
                jmpInst.branch_target_rva = targetRva;
                jmpInst.is_terminator = true;
                jmpInst.is_rip_relative = true;
                
                size_t originalSize = inst.mutated_bytes.empty() ? inst.original_bytes.size() : inst.mutated_bytes.size();
                size_t newSize = jccInst.mutated_bytes.size() + jmpInst.mutated_bytes.size();
                if (currentTotalSize - originalSize + newSize <= ctx.maxRawSize) {
                    newBlock.push_back(jccInst);
                    newBlock.push_back(jmpInst);
                    currentTotalSize = currentTotalSize - originalSize + newSize;
                    continue;
                }
            }
        }
        
        newBlock.push_back(inst);
    }
    block = std::move(newBlock);
}

bool ControlFlowObfuscator::ValidateOutput(const InstructionBlock& block) const {
    return !block.empty();
}

} // namespace Polymorphic