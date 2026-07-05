#include "CodeReorderer.h"
#include <algorithm>

namespace Polymorphic {

CodeReorderer::CodeReorderer(CryptoRandom& rng) : m_rng(rng), m_strategy("random") {}

std::vector<uint8_t> CodeReorderer::Reorder(const std::vector<uint8_t>& code, uint32_t /*baseAddress*/) {
    return code;
}

void CodeReorderer::SetStrategy(const std::string& strategy) {
    m_strategy = strategy;
}

std::vector<CodeReorderer::BasicBlock> CodeReorderer::IdentifyBlocks(const std::vector<uint8_t>& /*code*/, uint32_t /*baseAddress*/) {
    return {};
}

size_t CodeReorderer::GetInstructionLength(const std::vector<uint8_t>& /*code*/, size_t /*pos*/) {
    return 1;
}

bool CodeReorderer::IsBranch(const std::vector<uint8_t>& /*code*/, size_t /*pos*/, uint32_t& /*target*/, bool& /*isConditional*/) {
    return false;
}

std::vector<CodeReorderer::BasicBlock> CodeReorderer::ShuffleBlocks(const std::vector<BasicBlock>& blocks) {
    return blocks;
}

std::vector<uint8_t> CodeReorderer::RebuildCode(const std::vector<BasicBlock>& /*blocks*/, uint32_t /*baseAddress*/) {
    return {};
}

void CodeReorderer::FixJumpTargets(std::vector<uint8_t>& /*code*/, const std::vector<BasicBlock>& /*oldBlocks*/, const std::vector<BasicBlock>& /*newBlocks*/, uint32_t /*baseAddress*/) {}

} // namespace Polymorphic
