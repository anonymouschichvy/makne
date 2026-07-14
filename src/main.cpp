// Disable windows.h min/max macros BEFORE any includes to prevent
// transitive inclusion of windows.h from defining min/max macros. Dummy: 12345
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

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
    "     Advanced Polymorphic & Metamorphic Engine v3.0\n" << std::endl;
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

        Polymorphic::PolymorphicEngine polyEngine;
        
        // Configure polymorphic options
        if (mode == Mode::POLYMORPHIC || mode == Mode::MIXED) {
            polyEngine.SetInstructionSubstitution(substitution);
            polyEngine.SetRegisterRandomization(registers);
            polyEngine.SetCodeReordering(reorder);
            polyEngine.SetJunkCodeInsertion(junk);
            polyEngine.SetControlFlowObfuscation(cflow);
            polyEngine.SetPayloadEncryption(encrypt);
            polyEngine.SetDataEncoding(data);
            polyEngine.SetSectionRandomization(sections);
            polyEngine.SetImportObfuscation(imports);
        } else {
            polyEngine.SetInstructionSubstitution(false);
            polyEngine.SetRegisterRandomization(false);
            polyEngine.SetCodeReordering(false);
            polyEngine.SetJunkCodeInsertion(false);
            polyEngine.SetControlFlowObfuscation(false);
            polyEngine.SetPayloadEncryption(false);
            polyEngine.SetDataEncoding(false);
            polyEngine.SetSectionRandomization(false);
            polyEngine.SetImportObfuscation(false);
        }
        
        polyEngine.SetAntiDebug(antiDebug);

        // Configure metamorphic options
        if (mode == Mode::METAMORPHIC || mode == Mode::MIXED) {
            polyEngine.SetMetamorphic(true);
            polyEngine.SetPermutationLevel(permuteLevel);
            polyEngine.SetExpansionLevel(expandLevel);
            polyEngine.SetGarbageLevel(garbageLevel);
            polyEngine.EnableLoopUnrolling(unroll);
            polyEngine.EnableFunctionInlining(inlining);
        } else {
            polyEngine.SetMetamorphic(false);
        }

        if (!polyEngine.LoadExecutable(currentInput)) {
            std::cerr << "[!] Failed to load and parse input executable: " << currentInput << std::endl;
            return 1;
        }

        if (!polyEngine.Process()) {
            std::cerr << "[!] Obfuscation processing failed on pass " << (pass + 1) << std::endl;
            return 1;
        }

        if (!polyEngine.SaveExecutable(outputFile)) {
            std::cerr << "[!] Failed to save modified executable: " << outputFile << std::endl;
            return 1;
        }

        currentInput = outputFile;
    }

    std::cout << "[+] Transformation complete!" << std::endl;
    std::cout << "[+] Saved modified executable to: " << outputFile << std::endl;
    std::cout << "[+] Each generation produces a unique binary fingerprint" << std::endl;

    return 0;
}