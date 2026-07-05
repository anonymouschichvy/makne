#include "DataEncoder.h"

namespace Polymorphic {

DataEncoder::DataEncoder(CryptoRandom& rng) : m_rng(rng), m_is64Bit(false) {}

void DataEncoder::SetIs64Bit(bool is64) {
    m_is64Bit = is64;
}

std::vector<uint8_t> DataEncoder::Encode(const std::vector<uint8_t>& data, Encoding /*method*/) {
    return data;
}

std::vector<uint8_t> DataEncoder::EncodeString(const std::string& str, Encoding /*method*/) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::vector<uint8_t> DataEncoder::GenerateDecoder(const std::vector<uint8_t>& /*encoded*/, Encoding /*method*/, uint32_t /*dataRva*/) {
    return {};
}

void DataEncoder::SetCustomEncoding(std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)> encoder, std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)> decoder) {
    m_customEncoder = encoder;
    m_customDecoder = decoder;
}

std::vector<uint8_t> DataEncoder::XorEncode(const std::vector<uint8_t>& data) {
    return data;
}

std::vector<uint8_t> DataEncoder::Base64Encode(const std::vector<uint8_t>& data) {
    return data;
}

std::vector<uint8_t> DataEncoder::CustomEncode(const std::vector<uint8_t>& data) {
    return data;
}

std::vector<uint8_t> DataEncoder::StringSplitEncode(const std::vector<uint8_t>& data) {
    return data;
}

std::vector<uint8_t> DataEncoder::UnicodeTransformEncode(const std::vector<uint8_t>& data) {
    return data;
}

std::vector<uint8_t> DataEncoder::GenerateXORDecoder(uint32_t /*dataRva*/, size_t /*size*/) {
    return {};
}

std::vector<uint8_t> DataEncoder::GenerateBase64Decoder(uint32_t /*dataRva*/, size_t /*size*/) {
    return {};
}

} // namespace Polymorphic
