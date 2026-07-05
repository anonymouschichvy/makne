#include "PolymorphicEngine.h"
#include "InstructionSubstitutor.h"
#include "RegisterRandomizer.h"
#include "CodeReorderer.h"
#include "JunkCodeInserter.h"
#include "ControlFlowObfuscator.h"
#include "PayloadEncryptor.h"
#include "DecryptorGenerator.h"
#include "DataEncoder.h"
#include "SectionRandomizer.h"
#include "ImportObfuscator.h"
#include "MetamorphicEngine.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <memory>

#ifdef _WIN32
#include <windows.h>
#endif

void PrintBanner() {
#ifdef _WIN32
    // Set console output code page to UTF-8
    SetConsoleOutputCP(CP_UTF8);
#endif

    std::cout << 
    "      ███╗   ███╗ █████╗ ██╗  ██╗███╗   ██╗███████╗  \n"
    "      ████╗ ████║██╔══██╗██║ ██╔╝████╗  ██║██╔════╝ \n"
    "      ██╔████╔██║███████║█████╔╝ ██╔██╗ ██║█████╗  \n"
    "      ██║╚██╔╝██║██╔══██║██╔═██╗ ██║╚██╗██║██╔══╝  \n"
    "      ██║ ╚═╝ ██║██║  ██║██║  ██╗██║ ╚████║███████╗ \n"
    "      ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ \n"
    "     Advanced Polymorphic & Metamorphic Engine v2.0\n" << std::endl;
}

void PrintUsage(const char* program) {
    std::string progStr(program);
    size_t lastSlash = progStr.find_last_of("\\/");
    std::string progName = (lastSlash == std::string::npos) ? progStr : progStr.substr(lastSlash + 1);
    std::cout << "Usage: " << progName << " <input.exe> <output.exe> [options]" << std::endl;
    std::cout << "\nTransformation Modes:" << std::endl;
    std::cout << "  --polymorphic          Polymorphic transformation (default)" << std::endl;
    std::cout << "  --metamorphic          Full metamorphic transformation" << std::endl;
    std::cout << "  --mixed                Combined polymorphic + metamorphic" << std::endl;
    std::cout << "\nPolymorphic Options:" << std::endl;
    std::cout << "  --substitution         Enable instruction substitution" << std::endl;
    std::cout << "  --registers            Enable register randomization" << std::endl;
    std::cout << "  --reorder              Enable code reordering" << std::endl;
    std::cout << std::endl;
    std::cout << "  --junk                 Enable junk code insertion" << std::endl;
    std::cout << "  --cflow                Enable control flow obfuscation" << std::endl;
    std::cout << "  --encrypt              Enable payload encryption" << std::endl;
    std::cout << "  --data                 Enable data encoding" << std::endl;
    std::cout << "  --sections             Enable section randomization" << std::endl;
    std::cout << "  --imports              Enable import obfuscation" << std::endl;
    std::cout << "\nMetamorphic Options:" << std::endl;
    std::cout << "  --permute <1-5>        Instruction permutation level" << std::endl;
    std::cout << "  --expand <1-5>         Code expansion level" << std::endl;
    std::cout << "  --garbage <1-5>        Garbage insertion level" << std::endl;
    std::cout << "  --unroll               Enable loop unrolling" << std::endl;
    std::cout << "  --inline               Enable function inlining" << std::endl;
    std::cout << "\nAdvanced Options:" << std::endl;
    std::cout << "  --antidebug            Enable anti-debugging code" << std::endl;
    std::cout << "  --antiemu              Enable anti-emulation code" << std::endl;
    std::cout << "  --level <1-5>          Set overall obfuscation level" << std::endl;
    std::cout << "  --iterations <n>       Number of transformation passes" << std::endl;
    std::cout << "  --help                 Show this help message" << std::endl;
}

enum class Mode {
    POLYMORPHIC,
    METAMORPHIC,
    MIXED
};

int main(int argc, char* argv[]) {
    PrintBanner();

    if (argc < 3) {
        PrintUsage(argv[0]);
        return 1;
    }

    std::string inputFile = argv[1];
    std::string outputFile = argv[2];

    // Default configuration
    Mode mode = Mode::POLYMORPHIC;
    int level = 3;
    int iterations = 1;
    bool antiDebug = false;
    [[maybe_unused]] bool antiEmu = false;

    // Feature flags
    bool substitution = false;
    bool registers = false;
    bool reorder = false;
    bool junk = false;
    bool cflow = false;
    bool encrypt = false;
    bool data = false;
    bool sections = false;
    bool imports = false;

    // Metamorphic settings
    int permuteLevel = 3;
    int expandLevel = 2;
    int garbageLevel = 2;
    bool unroll = false;
    bool inlining = false;

    // Parse arguments
    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--polymorphic") mode = Mode::POLYMORPHIC;
        else if (arg == "--metamorphic") mode = Mode::METAMORPHIC;
        else if (arg == "--mixed") mode = Mode::MIXED;
        else if (arg == "--substitution") substitution = true;
        else if (arg == "--registers") registers = true;
        else if (arg == "--reorder") reorder = true;
        else if (arg == "--junk") junk = true;
        else if (arg == "--cflow") cflow = true;
        else if (arg == "--encrypt") encrypt = true;
        else if (arg == "--data") data = true;
        else if (arg == "--sections") sections = true;
        else if (arg == "--imports") imports = true;
        else if (arg == "--antidebug") antiDebug = true;
        else if (arg == "--antiemu") antiEmu = true;
        else if (arg == "--unroll") unroll = true;
        else if (arg == "--inline") inlining = true;
        else if (arg == "--level" && i + 1 < argc) level = std::stoi(argv[++i]);
        else if (arg == "--iterations" && i + 1 < argc) iterations = std::stoi(argv[++i]);
        else if (arg == "--permute" && i + 1 < argc) permuteLevel = std::stoi(argv[++i]);
        else if (arg == "--expand" && i + 1 < argc) expandLevel = std::stoi(argv[++i]);
        else if (arg == "--garbage" && i + 1 < argc) garbageLevel = std::stoi(argv[++i]);
        else if (arg == "--help") {
            PrintUsage(argv[0]);
            return 0;
        }
    }

    std::cout << "[*] Mode: " << (mode == Mode::POLYMORPHIC ? "Polymorphic" :
        mode == Mode::METAMORPHIC ? "Metamorphic" : "Mixed") << std::endl;
    std::cout << "[*] Level: " << level << std::endl;

    // Initialize RNG
    Polymorphic::CryptoRandom rng;

    std::string currentInput = inputFile;

    // Apply transformations
    for (int pass = 0; pass < iterations; ++pass) {
        std::cout << "[*] Transformation pass " << (pass + 1) << "/" << iterations << std::endl;

        if (mode == Mode::POLYMORPHIC || mode == Mode::MIXED) {
            std::cout << "  [+] Running Polymorphic Engine..." << std::endl;
            Polymorphic::PolymorphicEngine polyEngine;
            polyEngine.SetInstructionSubstitution(substitution);
            polyEngine.SetRegisterRandomization(registers);
            polyEngine.SetCodeReordering(reorder);
            polyEngine.SetJunkCodeInsertion(junk);
            polyEngine.SetControlFlowObfuscation(cflow);
            polyEngine.SetPayloadEncryption(encrypt);
            polyEngine.SetDataEncoding(data);
            polyEngine.SetSectionRandomization(sections);
            polyEngine.SetImportObfuscation(imports);
            polyEngine.SetAntiDebug(antiDebug);

            if (!polyEngine.LoadExecutable(currentInput)) {
                std::cerr << "[!] Failed to load and parse input executable: " << currentInput << std::endl;
                return 1;
            }

            if (!polyEngine.Process()) {
                std::cerr << "[!] Polymorphic processing failed on pass " << (pass + 1) << std::endl;
                return 1;
            }

            if (!polyEngine.SaveExecutable(outputFile)) {
                std::cerr << "[!] Failed to save modified executable: " << outputFile << std::endl;
                return 1;
            }

            currentInput = outputFile;
        }

        if (mode == Mode::METAMORPHIC || mode == Mode::MIXED) {
            std::cout << "  [+] Applying metamorphic transformation..." << std::endl;

            Polymorphic::PolymorphicEngine polyEngine;
            if (!polyEngine.LoadExecutable(currentInput)) {
                std::cerr << "[!] Failed to load executable for metamorphic pass: " << currentInput << std::endl;
                return 1;
            }

            auto& rawBinary = polyEngine.GetRawBinary();
            auto& sections = polyEngine.GetSections();

            Polymorphic::MetamorphicEngine metaEngine(rng);
            metaEngine.Set64Bit(polyEngine.Is64Bit());
            metaEngine.SetPermutationLevel(permuteLevel);
            metaEngine.SetExpansionLevel(expandLevel);
            metaEngine.setGarbageLevel(garbageLevel);
            metaEngine.EnableLoopUnrolling(unroll);
            metaEngine.EnableFunctionInlining(inlining);
            metaEngine.EnableOpaquePredicates(level >= 4);
            metaEngine.EnableBranchPrediction(level >= 3);

            uint32_t fileAlign = polyEngine.GetFileAlignment();
            for (size_t i = 0; i < sections.size(); ++i) {
                auto* section = sections[i];
                if (section->Characteristics & 0x20000000) { // Executable
                    size_t start = section->PointerToRawData;
                    size_t size = section->SizeOfRawData;

                    std::vector<uint8_t> code(rawBinary.begin() + start, rawBinary.begin() + start + size);
                    metaEngine.Transform(code, static_cast<uint32_t>(section->VirtualAddress));
                    
                    size_t newCodeSize = code.size();
                    size_t newAlignedSize = (newCodeSize + fileAlign - 1) & ~(fileAlign - 1);
                    
                    size_t alignedCapacity = (size + fileAlign - 1) & ~(fileAlign - 1);
                    if (alignedCapacity == 0) alignedCapacity = fileAlign;

                    size_t finalRawSize = alignedCapacity;
                    if (newCodeSize > alignedCapacity) {
                        finalRawSize = newAlignedSize;
                        uint32_t diff = static_cast<uint32_t>(newAlignedSize - alignedCapacity);
                        
                        // Shift physical offsets of all sections starting after this one in the file
                        // we do this BEFORE insert while the pointers are valid!
                        for (auto* sec : sections) {
                            if (sec->PointerToRawData > start) {
                                sec->PointerToRawData += diff;
                            }
                        }
                        
                        // Shift the symbol table offset if it is after the modified section
                        Polymorphic::IMAGE_FILE_HEADER* fileHeader = reinterpret_cast<Polymorphic::IMAGE_FILE_HEADER*>(
                            rawBinary.data() + reinterpret_cast<Polymorphic::IMAGE_DOS_HEADER*>(rawBinary.data())->e_lfanew + 4);
                        if (fileHeader->PointerToSymbolTable > start) {
                            fileHeader->PointerToSymbolTable += diff;
                        }
                        
                        // Now insert the bytes (reallocates rawBinary buffer)
                        rawBinary.insert(rawBinary.begin() + start + alignedCapacity, diff, 0);
                        
                        polyEngine.ParsePE(); // Re-parse PE headers to update pointers inside rawBinary
                        sections = polyEngine.GetSections();
                        section = sections[i];
                    }
                    
                    // Pad metamorphic code to match the raw section size
                    if (code.size() < finalRawSize) {
                        code.resize(finalRawSize, 0x90); // pad with NOPs
                    }
                    
                    std::copy(code.begin(), code.end(), rawBinary.begin() + start);
                    section->SizeOfRawData = static_cast<uint32_t>(finalRawSize);
                    section->VirtualSize = std::max(section->VirtualSize, static_cast<uint32_t>(newCodeSize));
                }
            }
            polyEngine.ParsePE(); // Trigger final re-parsing and structure validation step

            if (!polyEngine.SaveExecutable(outputFile)) {
                std::cerr << "[!] Failed to save metamorphic output: " << outputFile << std::endl;
                return 1;
            }
            currentInput = outputFile;
        }
    }

    std::cout << "[+] Transformation complete!" << std::endl;
    std::cout << "[+] Saved modified executable to: " << outputFile << std::endl;
    std::cout << "[+] Each generation produces a unique binary fingerprint" << std::endl;

    return 0;
}