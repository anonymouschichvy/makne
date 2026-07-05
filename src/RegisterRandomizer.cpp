// src/RegisterRandomizer.cpp
#include "RegisterRandomizer.h"
#include <algorithm>
#include <map>
#include <set>
#include <vector>
#include <Zydis/Decoder.h>
#include <Zydis/Register.h>

namespace Polymorphic {

RegisterRandomizer::RegisterRandomizer(CryptoRandom& rng)
    : m_rng(rng), m_is64Bit(false) {
    // Default allowed registers: RAX/EAX, RCX/ECX, RDX/EDX, RBX/EBX, RSI/ESI, RDI/EDI
    // and additionally R8-R15 in 64-bit mode (mapped by their Zydis Register IDs)
    Set64Bit(false);
}

void RegisterRandomizer::Set64Bit(bool enable) {
    m_is64Bit = enable;
    if (m_is64Bit) {
        m_allowedIds = {
            ZYDIS_REGISTER_RBX, ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_RDI,
            ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11, ZYDIS_REGISTER_R12,
            ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R15
        };
        m_preservedIds = {
            ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX,
            ZYDIS_REGISTER_RSP, ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_R8,
            ZYDIS_REGISTER_R9
        };
    } else {
        m_allowedIds = {
            ZYDIS_REGISTER_EBX, ZYDIS_REGISTER_ESI, ZYDIS_REGISTER_EDI
        };
        m_preservedIds = {
            ZYDIS_REGISTER_EAX, ZYDIS_REGISTER_ECX, ZYDIS_REGISTER_EDX,
            ZYDIS_REGISTER_ESP, ZYDIS_REGISTER_EBP
        };
    }
}

void RegisterRandomizer::SetAllowedRegisters(const std::vector<X86Register>& regs) {
    m_allowedIds.clear();
    for (auto reg : regs) {
        uint8_t zydisReg = ZYDIS_REGISTER_NONE;
        if (m_is64Bit) {
            switch (reg) {
                case X86Register::EAX: zydisReg = ZYDIS_REGISTER_RAX; break;
                case X86Register::ECX: zydisReg = ZYDIS_REGISTER_RCX; break;
                case X86Register::EDX: zydisReg = ZYDIS_REGISTER_RDX; break;
                case X86Register::EBX: zydisReg = ZYDIS_REGISTER_RBX; break;
                case X86Register::ESP: zydisReg = ZYDIS_REGISTER_RSP; break;
                case X86Register::EBP: zydisReg = ZYDIS_REGISTER_RBP; break;
                case X86Register::ESI: zydisReg = ZYDIS_REGISTER_RSI; break;
                case X86Register::EDI: zydisReg = ZYDIS_REGISTER_RDI; break;
                default: break;
            }
        } else {
            switch (reg) {
                case X86Register::EAX: zydisReg = ZYDIS_REGISTER_EAX; break;
                case X86Register::ECX: zydisReg = ZYDIS_REGISTER_ECX; break;
                case X86Register::EDX: zydisReg = ZYDIS_REGISTER_EDX; break;
                case X86Register::EBX: zydisReg = ZYDIS_REGISTER_EBX; break;
                case X86Register::ESP: zydisReg = ZYDIS_REGISTER_ESP; break;
                case X86Register::EBP: zydisReg = ZYDIS_REGISTER_EBP; break;
                case X86Register::ESI: zydisReg = ZYDIS_REGISTER_ESI; break;
                case X86Register::EDI: zydisReg = ZYDIS_REGISTER_EDI; break;
                default: break;
            }
        }
        if (zydisReg != ZYDIS_REGISTER_NONE) {
            m_allowedIds.push_back(zydisReg);
        }
    }
}

void RegisterRandomizer::PreserveRegisters(const std::vector<X86Register>& regs) {
    m_preservedIds.clear();
    for (auto reg : regs) {
        uint8_t zydisReg = ZYDIS_REGISTER_NONE;
        if (m_is64Bit) {
            switch (reg) {
                case X86Register::EAX: zydisReg = ZYDIS_REGISTER_RAX; break;
                case X86Register::ECX: zydisReg = ZYDIS_REGISTER_RCX; break;
                case X86Register::EDX: zydisReg = ZYDIS_REGISTER_RDX; break;
                case X86Register::EBX: zydisReg = ZYDIS_REGISTER_RBX; break;
                case X86Register::ESP: zydisReg = ZYDIS_REGISTER_RSP; break;
                case X86Register::EBP: zydisReg = ZYDIS_REGISTER_RBP; break;
                case X86Register::ESI: zydisReg = ZYDIS_REGISTER_RSI; break;
                case X86Register::EDI: zydisReg = ZYDIS_REGISTER_RDI; break;
                default: break;
            }
        } else {
            switch (reg) {
                case X86Register::EAX: zydisReg = ZYDIS_REGISTER_EAX; break;
                case X86Register::ECX: zydisReg = ZYDIS_REGISTER_ECX; break;
                case X86Register::EDX: zydisReg = ZYDIS_REGISTER_EDX; break;
                case X86Register::EBX: zydisReg = ZYDIS_REGISTER_EBX; break;
                case X86Register::ESP: zydisReg = ZYDIS_REGISTER_ESP; break;
                case X86Register::EBP: zydisReg = ZYDIS_REGISTER_EBP; break;
                case X86Register::ESI: zydisReg = ZYDIS_REGISTER_ESI; break;
                case X86Register::EDI: zydisReg = ZYDIS_REGISTER_EDI; break;
                default: break;
            }
        }
        if (zydisReg != ZYDIS_REGISTER_NONE) {
            m_preservedIds.push_back(zydisReg);
        }
    }
}

std::map<uint8_t, uint8_t> RegisterRandomizer::GenerateIdMapping() {
    std::map<uint8_t, uint8_t> mapping;
    
    std::vector<uint8_t> legacyIds;
    std::vector<uint8_t> extVolatileIds;
    std::vector<uint8_t> extNonVolatileIds;
    
    for (uint8_t id : m_allowedIds) {
        ZydisRegister reg = static_cast<ZydisRegister>(id);
        uint8_t regId = ZydisRegisterGetId(reg);
        
        // Preserve RSP (4), RBP (5), R12 (12), R13 (13) to keep instruction length constant
        if (regId == 4 || regId == 5 || regId == 12 || regId == 13) {
            mapping[id] = id;
            continue;
        }
        
        if (regId < 8) {
            legacyIds.push_back(id);
        } else {
            // Separate extension volatile (R10, R11) from non-volatile (R14, R15)
            // to respect calling conventions
            if (regId == 10 || regId == 11) {
                extVolatileIds.push_back(id);
            } else {
                extNonVolatileIds.push_back(id);
            }
        }
    }
    
    // Helper to shuffle a group
    auto shuffleGroup = [&](const std::vector<uint8_t>& ids) {
        if (!ids.empty()) {
            std::vector<uint8_t> shuffled = ids;
            std::shuffle(shuffled.begin(), shuffled.end(), std::mt19937(m_rng.Next()));
            for (size_t i = 0; i < ids.size(); ++i) {
                uint8_t from = ids[i];
                uint8_t to = shuffled[i];
                if (from == to && ids.size() > 1) {
                    to = shuffled[(i + 1) % shuffled.size()];
                }
                mapping[from] = to;
            }
        }
    };

    shuffleGroup(legacyIds);
    shuffleGroup(extVolatileIds);
    shuffleGroup(extNonVolatileIds);

    for (auto id : m_preservedIds) {
        mapping[id] = id;
    }
    return mapping;
}

std::vector<uint8_t> RegisterRandomizer::Randomize(const std::vector<uint8_t>& code) {
    ZydisDecoder decoder;
    ZydisMachineMode mode = m_is64Bit ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
    ZydisStackWidth stackWidth = m_is64Bit ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;
    
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, mode, stackWidth))) {
        return code;
    }
    
    // First pass: scan for implicit registers
    std::set<uint8_t> implicitRegs;
    size_t scanOffset = 0;
    while (scanOffset < code.size()) {
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZyanStatus status = ZydisDecoderDecodeFull(&decoder, &code[scanOffset], code.size() - scanOffset, &ins, operands);
        if (!ZYAN_SUCCESS(status)) {
            scanOffset++;
            continue;
        }
        
        for (int opIdx = 0; opIdx < ins.operand_count; ++opIdx) {
            auto& op = operands[opIdx];
            if (op.visibility == ZYDIS_OPERAND_VISIBILITY_IMPLICIT) {
                if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    ZydisRegister baseReg = ZydisRegisterGetLargestEnclosing(mode, op.reg.value);
                    if (baseReg == ZYDIS_REGISTER_NONE) baseReg = op.reg.value;
                    implicitRegs.insert(static_cast<uint8_t>(baseReg));
                } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    if (op.mem.base != ZYDIS_REGISTER_NONE) {
                        ZydisRegister baseReg = ZydisRegisterGetLargestEnclosing(mode, op.mem.base);
                        if (baseReg == ZYDIS_REGISTER_NONE) baseReg = op.mem.base;
                        implicitRegs.insert(static_cast<uint8_t>(baseReg));
                    }
                    if (op.mem.index != ZYDIS_REGISTER_NONE) {
                        ZydisRegister baseReg = ZydisRegisterGetLargestEnclosing(mode, op.mem.index);
                        if (baseReg == ZYDIS_REGISTER_NONE) baseReg = op.mem.index;
                        implicitRegs.insert(static_cast<uint8_t>(baseReg));
                    }
                }
            }
        }
        scanOffset += ins.length;
    }
    
    // Dynamically filter m_allowedIds to exclude implicit registers
    std::vector<uint8_t> finalAllowed;
    for (uint8_t id : m_allowedIds) {
        if (implicitRegs.count(id)) {
            if (std::find(m_preservedIds.begin(), m_preservedIds.end(), id) == m_preservedIds.end()) {
                m_preservedIds.push_back(id);
            }
        } else {
            finalAllowed.push_back(id);
        }
    }
    m_allowedIds = finalAllowed;
    
    auto mapping = GenerateIdMapping();
    std::vector<uint8_t> result = code;
    
    size_t offset = 0;
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    
    while (offset < result.size()) {
        ZyanStatus status = ZydisDecoderDecodeFull(&decoder, &result[offset], result.size() - offset, &ins, operands);
        if (!ZYAN_SUCCESS(status)) {
            offset++;
            continue;
        }
        
        // Skip RIP-relative instructions to avoid corrupting displacement addressing
        bool hasRipRelative = false;
        for (int opIdx = 0; opIdx < ins.operand_count; ++opIdx) {
            if (operands[opIdx].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                (operands[opIdx].mem.base == ZYDIS_REGISTER_RIP || operands[opIdx].mem.base == ZYDIS_REGISTER_EIP)) {
                hasRipRelative = true;
                break;
            }
        }
        if (hasRipRelative) {
            offset += ins.length;
            continue;
        }
        
        // Loop through decoded operands to find registers
        for (int opIdx = 0; opIdx < ins.operand_count; ++opIdx) {
            auto& op = operands[opIdx];
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                // Determine base register encoding matching our active level
                ZydisRegister baseReg = ZydisRegisterGetLargestEnclosing(mode, op.reg.value);
                if (baseReg == ZYDIS_REGISTER_NONE) baseReg = op.reg.value;
                
                auto it = mapping.find(static_cast<uint8_t>(baseReg));
                if (it != mapping.end() && it->second != baseReg) {
                    // Calculate the size class translation offset
                    int offsetDiff = static_cast<int>(it->second) - static_cast<int>(baseReg);
                    ZydisRegister newReg = static_cast<ZydisRegister>(static_cast<int>(op.reg.value) + offsetDiff);
                    
                    // ModR/M, SIB, or Opcode encoding modifications
                    if (op.encoding == ZYDIS_OPERAND_ENCODING_MODRM_REG) {
                        if (ins.attributes & ZYDIS_ATTRIB_HAS_MODRM) {
                            uint8_t& modrmByte = result[offset + ins.raw.modrm.offset];
                            uint8_t newRegId = ZydisRegisterGetId(newReg);
                            // Reg field is bits 5-3, lower 3 bits specify register id (0-7), 
                            // high bit (id >= 8) requires modifying the REX.R (or VEX.R) bit.
                            uint8_t newRegVal = newRegId & 0x7;
                            modrmByte = (modrmByte & 0xC7) | (newRegVal << 3);
                            
                            // Adjust prefix extensions
                            if (ins.attributes & ZYDIS_ATTRIB_HAS_REX) {
                                uint8_t& rexByte = result[offset + ins.raw.rex.offset];
                                uint8_t rexR = (newRegId >= 8) ? 1 : 0;
                                rexByte = (rexByte & 0xFB) | (rexR << 2);
                            }
                        }
                    } else if (op.encoding == ZYDIS_OPERAND_ENCODING_MODRM_RM) {
                        if (ins.attributes & ZYDIS_ATTRIB_HAS_MODRM) {
                            uint8_t& modrmByte = result[offset + ins.raw.modrm.offset];
                            uint8_t newRegId = ZydisRegisterGetId(newReg);
                            
                            if (ins.attributes & ZYDIS_ATTRIB_HAS_SIB) {
                                // If base register is encoded inside SIB
                                uint8_t& sibByte = result[offset + ins.raw.sib.offset];
                                uint8_t newBaseVal = newRegId & 0x7;
                                sibByte = (sibByte & 0xF8) | newBaseVal;
                                
                                if (ins.attributes & ZYDIS_ATTRIB_HAS_REX) {
                                    uint8_t& rexByte = result[offset + ins.raw.rex.offset];
                                    uint8_t rexB = (newRegId >= 8) ? 1 : 0;
                                    rexByte = (rexByte & 0xFE) | rexB;
                                }
                            } else {
                                uint8_t newRmVal = newRegId & 0x7;
                                modrmByte = (modrmByte & 0xF8) | newRmVal;
                                
                                if (ins.attributes & ZYDIS_ATTRIB_HAS_REX) {
                                    uint8_t& rexByte = result[offset + ins.raw.rex.offset];
                                    uint8_t rexB = (newRegId >= 8) ? 1 : 0;
                                    rexByte = (rexByte & 0xFE) | rexB;
                                }
                            }
                        }
                    } else if (op.encoding == ZYDIS_OPERAND_ENCODING_OPCODE) {
                        // Embedded register inside the opcode byte
                        uint8_t newRegId = ZydisRegisterGetId(newReg);
                        size_t opcodeOffset = ins.raw.prefix_count;
                        if (ins.attributes & ZYDIS_ATTRIB_HAS_REX) {
                            opcodeOffset++;
                        }
                        if (opcodeOffset < ins.length) {
                            uint8_t baseOpcode = result[offset + opcodeOffset] & 0xF8;
                            result[offset + opcodeOffset] = baseOpcode | (newRegId & 0x7);
                        }
                        
                        if (ins.attributes & ZYDIS_ATTRIB_HAS_REX) {
                            uint8_t& rexByte = result[offset + ins.raw.rex.offset];
                            uint8_t rexB = (newRegId >= 8) ? 1 : 0;
                            rexByte = (rexByte & 0xFE) | rexB;
                        }
                    }
                }
            } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                // Randomize Base Register
                if (op.mem.base != ZYDIS_REGISTER_NONE && op.mem.base != ZYDIS_REGISTER_RIP && op.mem.base != ZYDIS_REGISTER_EIP) {
                    ZydisRegister baseReg = ZydisRegisterGetLargestEnclosing(mode, op.mem.base);
                    if (baseReg == ZYDIS_REGISTER_NONE) baseReg = op.mem.base;
                    
                    auto it = mapping.find(static_cast<uint8_t>(baseReg));
                    if (it != mapping.end() && it->second != baseReg) {
                        int offsetDiff = static_cast<int>(it->second) - static_cast<int>(baseReg);
                        ZydisRegister newBase = static_cast<ZydisRegister>(static_cast<int>(op.mem.base) + offsetDiff);
                        uint8_t newBaseId = ZydisRegisterGetId(newBase);
                        
                        if (ins.attributes & ZYDIS_ATTRIB_HAS_SIB) {
                            uint8_t& sibByte = result[offset + ins.raw.sib.offset];
                            sibByte = (sibByte & 0xF8) | (newBaseId & 0x7);
                        } else {
                            uint8_t& modrmByte = result[offset + ins.raw.modrm.offset];
                            modrmByte = (modrmByte & 0xF8) | (newBaseId & 0x7);
                        }
                        if (ins.attributes & ZYDIS_ATTRIB_HAS_REX) {
                            uint8_t& rexByte = result[offset + ins.raw.rex.offset];
                            uint8_t rexB = (newBaseId >= 8) ? 1 : 0;
                            rexByte = (rexByte & 0xFE) | rexB;
                        }
                    }
                }
                // Randomize Index Register
                if (op.mem.index != ZYDIS_REGISTER_NONE) {
                    ZydisRegister baseReg = ZydisRegisterGetLargestEnclosing(mode, op.mem.index);
                    if (baseReg == ZYDIS_REGISTER_NONE) baseReg = op.mem.index;
                    
                    auto it = mapping.find(static_cast<uint8_t>(baseReg));
                    if (it != mapping.end() && it->second != baseReg) {
                        int offsetDiff = static_cast<int>(it->second) - static_cast<int>(baseReg);
                        ZydisRegister newIndex = static_cast<ZydisRegister>(static_cast<int>(op.mem.index) + offsetDiff);
                        uint8_t newIndexId = ZydisRegisterGetId(newIndex);
                        
                        if (ins.attributes & ZYDIS_ATTRIB_HAS_SIB) {
                            uint8_t& sibByte = result[offset + ins.raw.sib.offset];
                            sibByte = (sibByte & 0xC7) | ((newIndexId & 0x7) << 3);
                            
                            if (ins.attributes & ZYDIS_ATTRIB_HAS_REX) {
                                uint8_t& rexByte = result[offset + ins.raw.rex.offset];
                                uint8_t rexX = (newIndexId >= 8) ? 1 : 0;
                                rexByte = (rexByte & 0xFD) | (rexX << 1);
                            }
                        }
                    }
                }
            }
        }
        
        offset += ins.length;
    }
    
    return result;
}

} // namespace Polymorphic