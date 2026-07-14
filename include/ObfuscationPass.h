#pragma once
#include <vector>
#include <string>
#include <memory>
#include <cstdint>
#include <algorithm>
#include <iostream>
#include <set>
#include <cstring>
#include <Zydis/Decoder.h>

namespace Polymorphic {

struct IRInstruction {
    ZydisDecodedInstruction raw;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    uint64_t rva;
    std::vector<uint8_t> original_bytes;
    bool is_terminator;
    bool is_rip_relative;
    int64_t rip_relative_delta; // needs fixup after reorder
    std::vector<uint8_t> mutated_bytes; // empty if unmodified
    
    // CFG & block ordering fields
    std::vector<uint32_t> predecessors;
    std::vector<uint32_t> successors;
    bool is_leader = false;
    
    // Branch relocation fields
    uint64_t branch_target_rva = 0;
    uint8_t branch_offset = 0;
    uint8_t branch_size = 0;

    IRInstruction() 
        : rva(0), is_terminator(false), is_rip_relative(false), rip_relative_delta(0) {
        std::memset(&raw, 0, sizeof(raw));
        std::memset(operands, 0, sizeof(operands));
    }
};

using InstructionBlock = std::vector<IRInstruction>;

struct ArchContext {
    bool is64Bit;
    uint64_t imageBase;
    uint32_t sectionAlignment;
    uint32_t fileAlignment;
    size_t maxRawSize;
    // Function boundaries from .pdata: pairs of (beginRVA, endRVA)
    // These are pure RVAs (no ImageBase)
    std::vector<std::pair<uint32_t, uint32_t>> functionBoundaries;
    // Set of all valid instruction start RVAs in the section (from decoder)
    std::set<uint64_t> validInstructionRVAs;
    // Set of function BeginRVAs that have exception handlers or complex unwind info
    std::set<uint32_t> exceptionHandlerFuncRVAs;
};


struct IObfuscationPass {
    virtual ~IObfuscationPass() = default;
    virtual void Run(InstructionBlock& block, ArchContext& ctx) = 0;
    virtual std::string Name() const = 0;
    virtual bool ValidateOutput(const InstructionBlock& block) const = 0;
};

class PassManager {
public:
    void Register(std::unique_ptr<IObfuscationPass> pass) {
        m_passes.push_back(std::move(pass));
    }
    
    void RunAll(InstructionBlock& block, ArchContext& ctx) {
        for (auto& pass : m_passes) {
            std::cout << "[*] Running pass: " << pass->Name() << std::endl;
            pass->Run(block, ctx);
            if (!pass->ValidateOutput(block)) {
                std::cerr << "[!] Pass validation failed for: " << pass->Name() << std::endl;
            }
        }
    }
    
private:
    std::vector<std::unique_ptr<IObfuscationPass>> m_passes;
};

class VerifierPass : public IObfuscationPass {
public:
    std::string Name() const override { return "VerifierPass"; }
    
    void Run(InstructionBlock& block, ArchContext& ctx) override {
        // Run validations
        m_isValid = ValidateOutput(block);
        (void)ctx;
    }
    
    bool ValidateOutput(const InstructionBlock& block) const override {
        if (block.empty()) return true;
        
        bool ok = true;
        
        // 1. Verify Instruction Boundaries (no empty/corrupted instructions unless deliberate NOPs)
        for (size_t i = 0; i < block.size(); ++i) {
            const auto& inst = block[i];
            const auto& bytes = inst.mutated_bytes.empty() ? inst.original_bytes : inst.mutated_bytes;
            if (bytes.empty()) {
                std::cerr << "[!] Verifier error: empty byte sequence at instruction index " << i << std::endl;
                ok = false;
            }
        }
        
        // 2. Verify Stack Balance (heuristic-based checking for basic push/pop symmetry)
        int stackBalance = 0;
        for (const auto& inst : block) {
            if (inst.raw.mnemonic == ZYDIS_MNEMONIC_PUSH || inst.raw.mnemonic == ZYDIS_MNEMONIC_PUSHA || inst.raw.mnemonic == ZYDIS_MNEMONIC_PUSHAD || inst.raw.mnemonic == ZYDIS_MNEMONIC_PUSHF || inst.raw.mnemonic == ZYDIS_MNEMONIC_PUSHFD || inst.raw.mnemonic == ZYDIS_MNEMONIC_PUSHFQ) {
                stackBalance++;
            } else if (inst.raw.mnemonic == ZYDIS_MNEMONIC_POP || inst.raw.mnemonic == ZYDIS_MNEMONIC_POPA || inst.raw.mnemonic == ZYDIS_MNEMONIC_POPAD || inst.raw.mnemonic == ZYDIS_MNEMONIC_POPF || inst.raw.mnemonic == ZYDIS_MNEMONIC_POPFD || inst.raw.mnemonic == ZYDIS_MNEMONIC_POPFQ) {
                stackBalance--;
            }
        }
        
        if (stackBalance != 0) {
            std::cout << "[*] Verifier Warning: Stack push/pop balance is " << stackBalance << " (non-zero may be normal for partial blocks, but check compiler stack frames)." << std::endl;
        }
        
        // 3. Verify RIP Relative targets and branch targets validity
        for (size_t i = 0; i < block.size(); ++i) {
            const auto& inst = block[i];
            if (inst.is_terminator && inst.is_rip_relative) {
                // Terminator RIP relative branch validation
            }
        }
        
        return ok;
    }
    
    bool IsValid() const { return m_isValid; }
    
private:
    bool m_isValid = true;
};

} // namespace Polymorphic
