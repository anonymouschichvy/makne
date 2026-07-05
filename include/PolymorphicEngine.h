// PolymorphicEngine.h
#pragma once
#include <vector>
#include <string>
#include <random>
#include <memory>
#include <functional>
#include "Utils.h"

namespace Polymorphic {

    // PE structures
#pragma pack(push, 1)
    struct IMAGE_DOS_HEADER {
        uint16_t e_magic;
        uint16_t e_cblp;
        uint16_t e_cp;
        uint16_t e_crlc;
        uint16_t e_cparhdr;
        uint16_t e_minalloc;
        uint16_t e_maxalloc;
        uint16_t e_ss;
        uint16_t e_sp;
        uint16_t e_csum;
        uint16_t e_ip;
        uint16_t e_cs;
        uint16_t e_lfarlc;
        uint16_t e_ovno;
        uint16_t e_res[4];
        uint16_t e_oemid;
        uint16_t e_oeminfo;
        uint16_t e_res2[10];
        uint32_t e_lfanew;
    };

    struct IMAGE_FILE_HEADER {
        uint16_t Machine;
        uint16_t NumberOfSections;
        uint32_t TimeDateStamp;
        uint32_t PointerToSymbolTable;
        uint32_t NumberOfSymbols;
        uint16_t SizeOfOptionalHeader;
        uint16_t Characteristics;
    };

    struct IMAGE_DATA_DIRECTORY {
        uint32_t VirtualAddress;
        uint32_t Size;
    };

    struct IMAGE_OPTIONAL_HEADER32 {
        uint16_t Magic;
        uint8_t MajorLinkerVersion;
        uint8_t MinorLinkerVersion;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializedData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
        uint32_t BaseOfData;
        uint32_t ImageBase;
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        uint32_t SizeOfStackReserve;
        uint32_t SizeOfStackCommit;
        uint32_t SizeOfHeapReserve;
        uint32_t SizeOfHeapCommit;
        uint32_t LoaderFlags;
        uint32_t NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[16];
    };

    struct IMAGE_OPTIONAL_HEADER64 {
        uint16_t Magic;
        uint8_t MajorLinkerVersion;
        uint8_t MinorLinkerVersion;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializedData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
        uint64_t ImageBase;
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        uint64_t SizeOfStackReserve;
        uint64_t SizeOfStackCommit;
        uint64_t SizeOfHeapReserve;
        uint64_t SizeOfHeapCommit;
        uint32_t LoaderFlags;
        uint32_t NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[16];
    };

    struct IMAGE_SECTION_HEADER {
        uint8_t Name[8];
        uint32_t VirtualSize;
        uint32_t VirtualAddress;
        uint32_t SizeOfRawData;
        uint32_t PointerToRawData;
        uint32_t PointerToRelocations;
        uint32_t PointerToLinenumbers;
        uint16_t NumberOfRelocations;
        uint16_t NumberOfLinenumbers;
        uint32_t Characteristics;
    };
#pragma pack(pop)



    // Main engine class
    class PolymorphicEngine {
    public:
        PolymorphicEngine();
        ~PolymorphicEngine();

        // Load and process executable
        bool LoadExecutable(const std::string& filepath);
        bool Process();
        bool SaveExecutable(const std::string& filepath);
        bool Is64Bit() const { return m_is64Bit; }
        bool ParsePE();
        uint32_t GetFileAlignment() const;
        
        std::vector<uint8_t>& GetRawBinary() { return m_rawBinary; }
        std::vector<IMAGE_SECTION_HEADER*>& GetSections() { return m_sections; }

        // Configuration
        void SetInstructionSubstitution(bool enable) { m_substituteInstructions = enable; }
        void SetRegisterRandomization(bool enable) { m_randomizeRegisters = enable; }
        void SetCodeReordering(bool enable) { m_reorderCode = enable; }
        void SetJunkCodeInsertion(bool enable) { m_insertJunkCode = enable; }
        void SetControlFlowObfuscation(bool enable) { m_obfuscateControlFlow = enable; }
        void SetPayloadEncryption(bool enable) { m_encryptPayload = enable; }
        void SetDataEncoding(bool enable) { m_encodeData = enable; }
        void SetSectionRandomization(bool enable) { m_randomizeSections = enable; }
        void SetImportObfuscation(bool enable) { m_obfuscateImports = enable; }
        void SetAntiDebug(bool enable) { m_antiDebug = enable; }

    private:
        // Core data
        std::vector<uint8_t> m_rawBinary;
        IMAGE_DOS_HEADER* m_dosHeader;
        IMAGE_FILE_HEADER* m_fileHeader;
        bool m_is64Bit;
        IMAGE_OPTIONAL_HEADER32* m_optionalHeader32;
        IMAGE_OPTIONAL_HEADER64* m_optionalHeader64;
        std::vector<IMAGE_SECTION_HEADER*> m_sections;

        // Code analysis
        std::vector<Instruction> m_instructions;
        std::vector<size_t> m_functionBoundaries;

        // Configuration flags
        bool m_substituteInstructions;
        bool m_randomizeRegisters;
        bool m_reorderCode;
        bool m_insertJunkCode;
        bool m_obfuscateControlFlow;
        bool m_encryptPayload;
        bool m_encodeData;
        bool m_randomizeSections;
        bool m_obfuscateImports;
        bool m_antiDebug;

        // Random generator
        CryptoRandom m_rng;

        // Processing stages
        bool AnalyzeCode();
        bool ApplyTransformations();
        bool RebuildPE();

        // Individual transformation modules
        class Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace Polymorphic