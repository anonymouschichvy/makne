#include "InstructionSubstitutor.h"
#include <cstring>

namespace Polymorphic {

static uint8_t BuildREX(bool W, bool R, bool X, bool B) {
    return 0x40 | (W << 3) | (R << 2) | (X << 1) | B;
}

InstructionSubstitutor::InstructionSubstitutor(CryptoRandom& rng) : m_rng(rng) {}

void InstructionSubstitutor::Run(InstructionBlock& block, ArchContext& ctx) {
    for (auto& inst : block) {
        if (inst.raw.attributes & ZYDIS_ATTRIB_HAS_MODRM) {
            uint8_t mod = inst.raw.raw.modrm.mod;
            
            // Get register details
            uint8_t dstRegId = 0;
            if (inst.raw.operand_count > 0 && inst.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                dstRegId = ZydisRegisterGetId(inst.operands[0].reg.value);
            }
            
            bool is64Bit = (inst.raw.operand_width == 64);
            
            // XOR reg, reg -> SUB reg, reg
            if (inst.raw.mnemonic == ZYDIS_MNEMONIC_XOR && 
                inst.raw.operand_count == 2 &&
                inst.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                inst.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                inst.operands[0].reg.value == inst.operands[1].reg.value) {
                
                if (m_rng.Next(2) == 0) {
                    std::vector<uint8_t> newBytes = inst.original_bytes;
                    size_t opcodeOffset = inst.raw.raw.prefix_count;
                    if (inst.raw.attributes & ZYDIS_ATTRIB_HAS_REX) opcodeOffset++;
                    
                    if (opcodeOffset < newBytes.size()) {
                        // Keep the opcode format (0x31 or 0x33) but swap to SUB (0x29 or 0x2B)
                        if (newBytes[opcodeOffset] == 0x31) newBytes[opcodeOffset] = 0x29;
                        else if (newBytes[opcodeOffset] == 0x33) newBytes[opcodeOffset] = 0x2B;
                        inst.mutated_bytes = newBytes;
                    }
                }
            }
            // TEST reg, reg -> OR reg, reg / AND reg, reg
            else if (inst.raw.mnemonic == ZYDIS_MNEMONIC_TEST && 
                     inst.raw.operand_count == 2 &&
                     inst.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                     inst.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                     inst.operands[0].reg.value == inst.operands[1].reg.value) {
                
                std::vector<uint8_t> newBytes = inst.original_bytes;
                size_t opcodeOffset = inst.raw.raw.prefix_count;
                if (inst.raw.attributes & ZYDIS_ATTRIB_HAS_REX) opcodeOffset++;
                
                if (opcodeOffset < newBytes.size() && newBytes[opcodeOffset] == 0x85) {
                    uint32_t choice = m_rng.Next(4);
                    if (choice == 0) newBytes[opcodeOffset] = 0x09; // OR r/m, r
                    else if (choice == 1) newBytes[opcodeOffset] = 0x0B; // OR r, r/m
                    else if (choice == 2) newBytes[opcodeOffset] = 0x21; // AND r/m, r
                    else newBytes[opcodeOffset] = 0x23; // AND r, r/m
                    inst.mutated_bytes = newBytes;
                }
            }
            // LEA reg, [reg] -> MOV reg, reg
            else if (inst.raw.mnemonic == ZYDIS_MNEMONIC_LEA && 
                     inst.raw.operand_count == 2 &&
                     inst.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                     inst.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                     inst.operands[1].mem.base == inst.operands[0].reg.value &&
                     inst.operands[1].mem.index == ZYDIS_REGISTER_NONE &&
                     inst.operands[1].mem.disp.value == 0 &&
                     dstRegId < 8) { // exclude extended registers to keep it simple and safe
                
                size_t prefixIdx = 0;
                while (prefixIdx < inst.original_bytes.size()) {
                    uint8_t b = inst.original_bytes[prefixIdx];
                    if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                        (b >= 0x2E && b <= 0x3E) || b == 0x64 || b == 0x65) {
                        prefixIdx++;
                    } else {
                        break;
                    }
                }
                
                uint8_t rexByte = 0;
                if (ctx.is64Bit && prefixIdx < inst.original_bytes.size()) {
                    uint8_t b = inst.original_bytes[prefixIdx];
                    if (b >= 0x40 && b <= 0x4F) {
                        rexByte = b;
                    }
                }
                
                std::vector<uint8_t> newBytes;
                // Copy legacy prefixes
                for (size_t k = 0; k < prefixIdx; ++k) {
                    newBytes.push_back(inst.original_bytes[k]);
                }
                // Copy REX prefix if found
                if (rexByte != 0) {
                    newBytes.push_back(rexByte);
                }
                
                uint32_t choice = m_rng.Next(2);
                if (choice == 0) {
                    newBytes.push_back(0x8B); // MOV r, r/m
                } else {
                    newBytes.push_back(0x89); // MOV r/m, r
                }
                newBytes.push_back(0xC0 | (dstRegId & 0x7) | ((dstRegId & 0x7) << 3));
                inst.mutated_bytes = newBytes;
            }
            // ADD reg, 1 -> INC reg
            else if (inst.raw.mnemonic == ZYDIS_MNEMONIC_ADD && mod == 3 && 
                     inst.raw.operand_count == 2 &&
                     inst.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                     inst.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                     inst.operands[1].imm.value.u == 1) {
                
                if (inst.raw.operand_width != 32 && inst.raw.operand_width != 64) {
                    // Deferred, not forbidden: 16-bit and 8-bit substitutions are skipped due to
                    // flags-corruption risk until a dedicated 16-bit/8-bit emitter is available.
                } else if (m_rng.Next(2) == 0) {
                    std::vector<uint8_t> newBytes;
                    if (ctx.is64Bit) {
                        if (is64Bit) {
                            newBytes.push_back(BuildREX(true, false, false, dstRegId >= 8));
                        } else if (dstRegId >= 8) {
                            newBytes.push_back(BuildREX(false, false, false, true));
                        }
                        newBytes.push_back(0xFF);
                        newBytes.push_back(0xC0 | (dstRegId & 0x7)); // mod=3, reg=0 (INC)
                    } else {
                        newBytes.push_back(0x40 + dstRegId);
                    }
                    inst.mutated_bytes = newBytes;
                }
            }
            // SUB reg, 1 -> DEC reg
            else if (inst.raw.mnemonic == ZYDIS_MNEMONIC_SUB && mod == 3 && 
                     inst.raw.operand_count == 2 &&
                     inst.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                     inst.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                     inst.operands[1].imm.value.u == 1) {
                
                if (inst.raw.operand_width != 32 && inst.raw.operand_width != 64) {
                    // Deferred, not forbidden: 16-bit and 8-bit substitutions are skipped due to
                    // flags-corruption risk until a dedicated 16-bit/8-bit emitter is available.
                } else if (m_rng.Next(2) == 0) {
                    std::vector<uint8_t> newBytes;
                    if (ctx.is64Bit) {
                        if (is64Bit) {
                            newBytes.push_back(BuildREX(true, false, false, dstRegId >= 8));
                        } else if (dstRegId >= 8) {
                            newBytes.push_back(BuildREX(false, false, false, true));
                        }
                        newBytes.push_back(0xFF);
                        newBytes.push_back(0xC8 | (dstRegId & 0x7)); // mod=3, reg=1 (DEC)
                    } else {
                        newBytes.push_back(0x48 + dstRegId);
                    }
                    inst.mutated_bytes = newBytes;
                }
            }
            // CMP reg, 0 -> TEST reg, reg
            else if (inst.raw.mnemonic == ZYDIS_MNEMONIC_CMP && mod == 3 && 
                     inst.raw.operand_count == 2 &&
                     inst.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                     inst.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                     inst.operands[1].imm.value.u == 0) {
                
                if (inst.raw.operand_width != 32 && inst.raw.operand_width != 64) {
                    // Deferred, not forbidden: 16-bit and 8-bit substitutions are skipped due to
                    // flags-corruption risk until a dedicated 16-bit/8-bit emitter is available.
                } else if (m_rng.Next(2) == 0) {
                    std::vector<uint8_t> newBytes;
                    if (ctx.is64Bit) {
                        if (is64Bit) {
                            newBytes.push_back(BuildREX(true, dstRegId >= 8, false, dstRegId >= 8));
                        } else if (dstRegId >= 8) {
                            newBytes.push_back(BuildREX(false, true, false, true));
                        }
                        newBytes.push_back(0x85); // TEST r/m, r
                        newBytes.push_back(0xC0 | (dstRegId & 0x7) | ((dstRegId & 0x7) << 3));
                    } else {
                        newBytes.push_back(0x85);
                        newBytes.push_back(0xC0 | dstRegId | (dstRegId << 3));
                    }
                    inst.mutated_bytes = newBytes;
                }
            }
        }
    }
}

bool InstructionSubstitutor::ValidateOutput(const InstructionBlock& block) const {
    return !block.empty();
}

} // namespace Polymorphic