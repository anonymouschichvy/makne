// src/RegisterRandomizer.cpp
#include "RegisterRandomizer.h"
#include <algorithm>
#include <map>
#include <set>
#include <vector>
#include <iostream>
#include <Zydis/Decoder.h>
#include <Zydis/Register.h>

namespace Polymorphic {

// =============================================================================
//  RegisterRandomizerCore  (raw-byte register substitution logic)
// =============================================================================

RegisterRandomizerCore::RegisterRandomizerCore(CryptoRandom& rng)
    : m_rng(rng), m_is64Bit(false) {
    Set64Bit(false);
}

void RegisterRandomizerCore::Set64Bit(bool enable) {
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

void RegisterRandomizerCore::SetAllowedRegisters(const std::vector<X86Register>& regs) {
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

void RegisterRandomizerCore::PreserveRegisters(const std::vector<X86Register>& regs) {
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

std::map<uint8_t, uint8_t> RegisterRandomizerCore::GenerateIdMapping() {
    std::map<uint8_t, uint8_t> mapping;

    std::vector<uint8_t> legacyIds;
    std::vector<uint8_t> extVolatileIds;
    std::vector<uint8_t> extNonVolatileIds;

    for (uint8_t id : m_allowedIds) {
        ZydisRegister reg = static_cast<ZydisRegister>(id);
        uint8_t regId = ZydisRegisterGetId(reg);

        // Preserve RSP (4), RBP (5), R12 (12), R13 (13) to keep instruction
        // length constant (they require SIB/disp32 in certain encodings).
        if (regId == 4 || regId == 5 || regId == 12 || regId == 13) {
            mapping[id] = id;
            continue;
        }

        if (regId < 8) {
            legacyIds.push_back(id);
        } else {
            if (regId == 10 || regId == 11) {
                extVolatileIds.push_back(id);
            } else {
                extNonVolatileIds.push_back(id);
            }
        }
    }

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

std::vector<uint8_t> RegisterRandomizerCore::Randomize(const std::vector<uint8_t>& code) {
    ZydisDecoder decoder;
    ZydisMachineMode mode = m_is64Bit ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
    ZydisStackWidth stackWidth = m_is64Bit ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;

    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, mode, stackWidth))) {
        return code;
    }

    // First pass: scan for implicit registers and exclude them from renaming
    std::set<uint8_t> implicitRegs;
    size_t scanOffset = 0;
    while (scanOffset < code.size()) {
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZyanStatus status = ZydisDecoderDecodeFull(&decoder, &code[scanOffset],
            code.size() - scanOffset, &ins, operands);
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

    // Filter out implicit registers from the allowed set
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
        ZyanStatus status = ZydisDecoderDecodeFull(&decoder, &result[offset],
            result.size() - offset, &ins, operands);
        if (!ZYAN_SUCCESS(status)) {
            offset++;
            continue;
        }

        // Skip RIP-relative instructions to avoid corrupting displacement
        bool hasRipRelative = false;
        for (int opIdx = 0; opIdx < ins.operand_count; ++opIdx) {
            if (operands[opIdx].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                (operands[opIdx].mem.base == ZYDIS_REGISTER_RIP ||
                 operands[opIdx].mem.base == ZYDIS_REGISTER_EIP)) {
                hasRipRelative = true;
                break;
            }
        }
        if (hasRipRelative) {
            offset += ins.length;
            continue;
        }

        for (int opIdx = 0; opIdx < ins.operand_count; ++opIdx) {
            auto& op = operands[opIdx];
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                ZydisRegister baseReg = ZydisRegisterGetLargestEnclosing(mode, op.reg.value);
                if (baseReg == ZYDIS_REGISTER_NONE) baseReg = op.reg.value;

                auto it = mapping.find(static_cast<uint8_t>(baseReg));
                if (it == mapping.end() || it->second == baseReg) continue;

                int offsetDiff = static_cast<int>(it->second) - static_cast<int>(baseReg);
                ZydisRegister newReg = static_cast<ZydisRegister>(static_cast<int>(op.reg.value) + offsetDiff);

                if (op.encoding == ZYDIS_OPERAND_ENCODING_MODRM_REG) {
                    if (ins.attributes & ZYDIS_ATTRIB_HAS_MODRM) {
                        uint8_t& modrmByte = result[offset + ins.raw.modrm.offset];
                        uint8_t newRegId = ZydisRegisterGetId(newReg);
                        modrmByte = (modrmByte & 0xC7) | ((newRegId & 0x7) << 3);
                        if (ins.attributes & ZYDIS_ATTRIB_HAS_REX) {
                            uint8_t& rexByte = result[offset + ins.raw.rex.offset];
                            rexByte = (rexByte & 0xFB) | (((newRegId >= 8) ? 1u : 0u) << 2);
                        }
                    }
                } else if (op.encoding == ZYDIS_OPERAND_ENCODING_MODRM_RM) {
                    if (ins.attributes & ZYDIS_ATTRIB_HAS_MODRM) {
                        uint8_t newRegId = ZydisRegisterGetId(newReg);
                        if (ins.attributes & ZYDIS_ATTRIB_HAS_SIB) {
                            uint8_t& sibByte = result[offset + ins.raw.sib.offset];
                            sibByte = (sibByte & 0xF8) | (newRegId & 0x7);
                            if (ins.attributes & ZYDIS_ATTRIB_HAS_REX) {
                                uint8_t& rexByte = result[offset + ins.raw.rex.offset];
                                rexByte = (rexByte & 0xFE) | ((newRegId >= 8) ? 1u : 0u);
                            }
                        } else {
                            uint8_t& modrmByte = result[offset + ins.raw.modrm.offset];
                            modrmByte = (modrmByte & 0xF8) | (newRegId & 0x7);
                            if (ins.attributes & ZYDIS_ATTRIB_HAS_REX) {
                                uint8_t& rexByte = result[offset + ins.raw.rex.offset];
                                rexByte = (rexByte & 0xFE) | ((newRegId >= 8) ? 1u : 0u);
                            }
                        }
                    }
                } else if (op.encoding == ZYDIS_OPERAND_ENCODING_OPCODE) {
                    uint8_t newRegId = ZydisRegisterGetId(newReg);
                    size_t opcodeOffset = ins.raw.prefix_count;
                    if (ins.attributes & ZYDIS_ATTRIB_HAS_REX) opcodeOffset++;
                    if (opcodeOffset < ins.length) {
                        result[offset + opcodeOffset] = (result[offset + opcodeOffset] & 0xF8) | (newRegId & 0x7);
                    }
                    if (ins.attributes & ZYDIS_ATTRIB_HAS_REX) {
                        uint8_t& rexByte = result[offset + ins.raw.rex.offset];
                        rexByte = (rexByte & 0xFE) | ((newRegId >= 8) ? 1u : 0u);
                    }
                }
            } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                // Base register
                if (op.mem.base != ZYDIS_REGISTER_NONE &&
                    op.mem.base != ZYDIS_REGISTER_RIP &&
                    op.mem.base != ZYDIS_REGISTER_EIP) {
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
                            rexByte = (rexByte & 0xFE) | ((newBaseId >= 8) ? 1u : 0u);
                        }
                    }
                }
                // Index register
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
                                rexByte = (rexByte & 0xFD) | (((newIndexId >= 8) ? 1u : 0u) << 1);
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

// =============================================================================
//  RegisterRandomizer  (IObfuscationPass wrapper)
//
//  Processes each function independently (using ctx.functionBoundaries) and
//  ONLY processes leaf functions (functions with no CALL instructions).
//  This preserves calling-convention safety across function boundaries.
// =============================================================================

void RegisterRandomizer::Run(InstructionBlock& block, ArchContext& ctx) {
    if (block.empty()) return;

    const auto& bounds = ctx.functionBoundaries;
    if (bounds.empty()) return;

    size_t totalRandomized = 0;
    const size_t N = block.size();

    // Sort boundaries by begin RVA (should already be sorted)
    std::vector<std::pair<uint32_t, uint32_t>> sortedBounds = bounds;
    std::sort(sortedBounds.begin(), sortedBounds.end());

    size_t instCursor = 0;
    for (const auto& [fnBegin, fnEnd] : sortedBounds) {
        // Advance cursor to the start of this function
        while (instCursor < N && block[instCursor].rva < fnBegin) instCursor++;
        if (instCursor >= N || block[instCursor].rva >= fnEnd) continue;

        size_t startIdx = instCursor;
        size_t endIdx = startIdx;
        while (endIdx < N && block[endIdx].rva < fnEnd) endIdx++;

        // Skip non-leaf functions: any CALL instruction disqualifies the function
        bool hasCall = false;
        for (size_t i = startIdx; i < endIdx; ++i) {
            if (block[i].raw.mnemonic == ZYDIS_MNEMONIC_CALL) {
                hasCall = true;
                break;
            }
        }
        if (hasCall) continue;

        // Assemble function bytes
        std::vector<uint8_t> fnCode;
        for (size_t i = startIdx; i < endIdx; ++i)
            fnCode.insert(fnCode.end(),
                block[i].original_bytes.begin(),
                block[i].original_bytes.end());

        // Apply register randomization with a fresh core per function
        RegisterRandomizerCore core(m_rng);
        core.Set64Bit(ctx.is64Bit);
        std::vector<uint8_t> randomized = core.Randomize(fnCode);

        // Write back — instruction lengths are unchanged by register renaming
        size_t byteOffset = 0;
        for (size_t i = startIdx; i < endIdx; ++i) {
            size_t len = block[i].original_bytes.size();
            if (byteOffset + len <= randomized.size()) {
                std::copy(randomized.begin() + byteOffset,
                          randomized.begin() + byteOffset + len,
                          block[i].original_bytes.begin());
                totalRandomized++;
            }
            byteOffset += len;
        }
    }

    std::cout << "[*] Running pass: RegisterRandomizer -- randomized "
              << totalRandomized << " instructions in leaf functions" << std::endl;
}

} // namespace Polymorphic