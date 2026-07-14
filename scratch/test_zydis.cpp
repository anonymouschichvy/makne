#include <iostream>
#include <vector>
#include <Zydis/Zydis.h>

int main() {
    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        std::cerr << "Failed to init Zydis" << std::endl;
        return 1;
    }
    
    std::vector<uint8_t> code = { 0xeb, 0x10 }; // jmp short $+0x12
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    
    if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code.data(), code.size(), &ins, operands))) {
        std::cout << "Decoded JMP successfully!" << std::endl;
        std::cout << "Imm size (bits): " << (int)ins.raw.imm[0].size << std::endl;
        std::cout << "Imm offset (units?): " << (int)ins.raw.imm[0].offset << std::endl;
    } else {
        std::cerr << "Failed to decode" << std::endl;
    }
    return 0;
}
