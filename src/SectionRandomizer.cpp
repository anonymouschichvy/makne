#include "SectionRandomizer.h"
#include <algorithm>
#include <cstring>
#include <map>
#include <functional>
#include <iostream>

namespace {
#pragma pack(push, 1)
struct IMAGE_RESOURCE_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint16_t NumberOfNamedEntries;
    uint16_t NumberOfIdEntries;
};

struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
    uint32_t NameOrId;
    uint32_t OffsetToDataOrDirectory;
    
    bool isDirectory() const {
        return (OffsetToDataOrDirectory & 0x80000000) != 0;
    }
    uint32_t getOffset() const {
        return OffsetToDataOrDirectory & 0x7FFFFFFF;
    }
};

struct IMAGE_RESOURCE_DATA_ENTRY {
    uint32_t OffsetToData;
    uint32_t Size;
    uint32_t CodePage;
    uint32_t Reserved;
};
#pragma pack(pop)
}

namespace Polymorphic {

SectionRandomizer::SectionRandomizer(CryptoRandom& rng)
    : m_rng(rng), m_randomizeOrder(true), m_randomizeNames(false),
      m_mergeSections(false), m_addPadding(true), m_randomAlignment(false) {}

void SectionRandomizer::SetRandomizeOrder(bool enable) {
    m_randomizeOrder = enable;
}

void SectionRandomizer::SetRandomizeNames(bool enable) {
    m_randomizeNames = enable;
}

void SectionRandomizer::SetMergeSections(bool enable) {
    m_mergeSections = enable;
}

void SectionRandomizer::SetAddPadding(bool enable) {
    m_addPadding = enable;
}

void SectionRandomizer::SetRandomAlignment(bool enable) {
    m_randomAlignment = enable;
}

void SectionRandomizer::AddCustomSection(const SectionInfo& section) {
    m_customSections.push_back(section);
}

// Stub out unused declared private methods to keep compilation working
bool SectionRandomizer::ParsePE(std::vector<uint8_t>&,
    PE::IMAGE_DOS_HEADER*&,
    PE::IMAGE_FILE_HEADER*&,
    PE::IMAGE_OPTIONAL_HEADER32*&,
    std::vector<PE::IMAGE_SECTION_HEADER*>&) {
    return false;
}

void SectionRandomizer::ShuffleSections(std::vector<PE::IMAGE_SECTION_HEADER*>&) {}
void SectionRandomizer::RenameSections(std::vector<PE::IMAGE_SECTION_HEADER*>&) {}
void SectionRandomizer::MergeSections(std::vector<uint8_t>&, std::vector<PE::IMAGE_SECTION_HEADER*>&) {}
void SectionRandomizer::AddRandomPadding(std::vector<uint8_t>&, std::vector<PE::IMAGE_SECTION_HEADER*>&) {}
void SectionRandomizer::RandomizeAlignment(std::vector<PE::IMAGE_SECTION_HEADER*>&) {}
void SectionRandomizer::FixRVAs(std::vector<uint8_t>&,
    const std::vector<PE::IMAGE_SECTION_HEADER*>&,
    const std::vector<PE::IMAGE_SECTION_HEADER*>&) {}

std::string SectionRandomizer::GenerateSectionName() {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz";
    std::string name = ".";

    for (int i = 0; i < 5; ++i) {
        name += charset[m_rng.Next(26)];
    }

    return name;
}

void SectionRandomizer::UpdateChecksum(std::vector<uint8_t>& data) {
    if (data.size() < sizeof(PE::IMAGE_DOS_HEADER)) return;
    
    PE::IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<PE::IMAGE_DOS_HEADER*>(data.data());
    uint32_t peOffset = dosHeader->e_lfanew;
    if (peOffset + sizeof(uint32_t) + sizeof(PE::IMAGE_FILE_HEADER) > data.size()) return;
    
    PE::IMAGE_FILE_HEADER* fileHeader = reinterpret_cast<PE::IMAGE_FILE_HEADER*>(
        data.data() + peOffset + 4);
        
    uint16_t magic = *reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(fileHeader) + sizeof(PE::IMAGE_FILE_HEADER));
    
    if (magic == 0x20B) {
        PE::IMAGE_OPTIONAL_HEADER64* optionalHeader =
            reinterpret_cast<PE::IMAGE_OPTIONAL_HEADER64*>(
                reinterpret_cast<uint8_t*>(fileHeader) + sizeof(PE::IMAGE_FILE_HEADER));
        optionalHeader->CheckSum = 0;
    } else if (magic == 0x10B) {
        PE::IMAGE_OPTIONAL_HEADER32* optionalHeader =
            reinterpret_cast<PE::IMAGE_OPTIONAL_HEADER32*>(
                reinterpret_cast<uint8_t*>(fileHeader) + sizeof(PE::IMAGE_FILE_HEADER));
        optionalHeader->CheckSum = 0;
    } else {
        return;
    }

    // Calculate new checksum according to standard IMAGHELP algorithm
    uint32_t checksumOffset = 0;
    if (magic == 0x20B) {
        checksumOffset = peOffset + 4 + sizeof(PE::IMAGE_FILE_HEADER) + 64;
    } else {
        checksumOffset = peOffset + 4 + sizeof(PE::IMAGE_FILE_HEADER) + 64;
    }

    uint64_t checksum = 0;
    for (size_t i = 0; i < data.size(); i += 2) {
        if (i == checksumOffset || i == checksumOffset + 2) {
            continue; // Skip CheckSum field (4 bytes)
        }
        if (i + 2 <= data.size()) {
            checksum += *reinterpret_cast<const uint16_t*>(&data[i]);
        } else {
            checksum += data[i]; // Odd byte
        }
    }
    
    while (checksum >> 16) {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    uint32_t finalChecksum = static_cast<uint32_t>(checksum) + static_cast<uint32_t>(data.size());
    
    if (magic == 0x20B) {
        PE::IMAGE_OPTIONAL_HEADER64* optionalHeader =
            reinterpret_cast<PE::IMAGE_OPTIONAL_HEADER64*>(
                reinterpret_cast<uint8_t*>(fileHeader) + sizeof(PE::IMAGE_FILE_HEADER));
        optionalHeader->CheckSum = finalChecksum;
    } else {
        PE::IMAGE_OPTIONAL_HEADER32* optionalHeader =
            reinterpret_cast<PE::IMAGE_OPTIONAL_HEADER32*>(
                reinterpret_cast<uint8_t*>(fileHeader) + sizeof(PE::IMAGE_FILE_HEADER));
        optionalHeader->CheckSum = finalChecksum;
    }
}

static uint32_t alignUp(uint32_t value, uint32_t alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

struct InternalSection {
    PE::IMAGE_SECTION_HEADER header;
    std::vector<uint8_t> data;
    uint32_t oldVirtualAddress = 0;
    uint32_t virtualSize = 0;
    uint32_t virtualAddress = 0;
    uint32_t rawSize = 0;
    uint32_t rawAddress = 0;
    std::string name;
    uint32_t characteristics = 0;
};

bool SectionRandomizer::Randomize(std::vector<uint8_t>& peData) {
    if (peData.size() < sizeof(PE::IMAGE_DOS_HEADER)) return false;

    PE::IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<PE::IMAGE_DOS_HEADER*>(peData.data());
    if (dosHeader->e_magic != 0x5A4D) return false;

    uint32_t peOffset = dosHeader->e_lfanew;
    if (peOffset + sizeof(uint32_t) + sizeof(PE::IMAGE_FILE_HEADER) > peData.size()) {
        return false;
    }

    uint32_t* peSignature = reinterpret_cast<uint32_t*>(peData.data() + peOffset);
    if (*peSignature != 0x00004550) return false;

    PE::IMAGE_FILE_HEADER* fileHeader = reinterpret_cast<PE::IMAGE_FILE_HEADER*>(
        peData.data() + peOffset + 4);
        
    uint8_t* optionalHeaderPtr = reinterpret_cast<uint8_t*>(fileHeader) + sizeof(PE::IMAGE_FILE_HEADER);
    uint16_t magic = *reinterpret_cast<uint16_t*>(optionalHeaderPtr);
    bool is64Bit = false;
    PE::IMAGE_OPTIONAL_HEADER32* optionalHeader32 = nullptr;
    PE::IMAGE_OPTIONAL_HEADER64* optionalHeader64 = nullptr;
    
    if (magic == 0x20B) {
        is64Bit = true;
        optionalHeader64 = reinterpret_cast<PE::IMAGE_OPTIONAL_HEADER64*>(optionalHeaderPtr);
        // On x64, relative offsets between sections must be preserved because of %rip-relative addressing.
        // We disable order shuffling and padding but enable name randomization.
        m_randomizeOrder = false;
        m_addPadding = false;
        m_randomAlignment = false;
        m_randomizeNames = true;
    } else if (magic == 0x10B) {
        is64Bit = false;
        optionalHeader32 = reinterpret_cast<PE::IMAGE_OPTIONAL_HEADER32*>(optionalHeaderPtr);
    } else {
        return false; // Unsupported magic
    }

    PE::IMAGE_SECTION_HEADER* firstSectionHeader = reinterpret_cast<PE::IMAGE_SECTION_HEADER*>(
        optionalHeaderPtr + fileHeader->SizeOfOptionalHeader);

    // Extract trailing overlay and symbols data
    uint32_t originalMaxRaw = 0;
    for (int i = 0; i < fileHeader->NumberOfSections; ++i) {
        PE::IMAGE_SECTION_HEADER* secHeader = firstSectionHeader + i;
        if (secHeader->SizeOfRawData > 0) {
            uint32_t endRaw = secHeader->PointerToRawData + secHeader->SizeOfRawData;
            if (endRaw > originalMaxRaw) {
                originalMaxRaw = endRaw;
            }
        }
    }

    std::vector<uint8_t> trailingData;
    if (peData.size() > originalMaxRaw) {
        trailingData.assign(peData.begin() + originalMaxRaw, peData.end());
    }

    // 1. Parse current sections
    std::vector<InternalSection> sections;
    sections.reserve(fileHeader->NumberOfSections + m_customSections.size());

    for (int i = 0; i < fileHeader->NumberOfSections; ++i) {
        PE::IMAGE_SECTION_HEADER* secHeader = firstSectionHeader + i;
        InternalSection sec;
        sec.header = *secHeader;
        sec.oldVirtualAddress = secHeader->VirtualAddress;
        sec.virtualSize = secHeader->VirtualSize;
        sec.virtualAddress = secHeader->VirtualAddress;
        sec.rawSize = secHeader->SizeOfRawData;
        sec.rawAddress = secHeader->PointerToRawData;
        sec.characteristics = secHeader->Characteristics;

        char nameBuf[9] = {0};
        memcpy(nameBuf, secHeader->Name, 8);
        sec.name = nameBuf;

        if (secHeader->PointerToRawData > 0 && secHeader->SizeOfRawData > 0) {
            if (secHeader->PointerToRawData + secHeader->SizeOfRawData <= peData.size()) {
                sec.data.assign(
                    peData.begin() + secHeader->PointerToRawData,
                    peData.begin() + secHeader->PointerToRawData + secHeader->SizeOfRawData
                );
            } else {
                sec.data.assign(peData.begin() + secHeader->PointerToRawData, peData.end());
            }
        }
        sections.push_back(sec);
    }

    // 2. Add custom sections if any
    for (const auto& cs : m_customSections) {
        InternalSection sec;
        memset(&sec.header, 0, sizeof(sec.header));
        sec.name = cs.name;
        sec.virtualSize = cs.virtualSize;
        sec.virtualAddress = 0;
        sec.rawSize = cs.rawSize;
        sec.rawAddress = 0;
        sec.characteristics = cs.characteristics;
        sec.data = cs.data;
        sec.oldVirtualAddress = 0;
        sections.push_back(sec);
    }

    // 3. Shuffle sections (keep first section in place for stability)
    if (m_randomizeOrder && sections.size() >= 2) {
        std::vector<InternalSection> shufflable(sections.begin() + 1, sections.end());
        std::shuffle(shufflable.begin(), shufflable.end(),
            std::mt19937(m_rng.Next()));

        std::vector<InternalSection> newOrder;
        newOrder.push_back(sections[0]);
        newOrder.insert(newOrder.end(), shufflable.begin(), shufflable.end());
        sections = newOrder;
    }

    // 4. Rename sections
    if (m_randomizeNames) {
        const char* commonNames[] = {
            ".text", ".data", ".rdata", ".bss", ".idata", ".edata",
            ".pdata", ".xdata", ".reloc", ".rsrc", ".tls",
            ".crt", ".debug", ".00cfg", ".gehcont"
        };

        const char* randomNames[] = {
            ".axyz", ".bcode", ".cdata", ".dsect", ".entry",
            ".fdata", ".gcode", ".hdata", ".idata", ".jsect",
            ".kcode", ".ldata", ".mdata", ".ncode", ".odata"
        };

        for (auto& sec : sections) {
            std::string newName;
            if (m_rng.Next(2) == 0) {
                newName = commonNames[m_rng.Next(14)];
            } else {
                newName = randomNames[m_rng.Next(15)];
            }
            sec.name = newName;
        }
    }

    // 5. Add random padding
    if (m_addPadding) {
        for (auto& sec : sections) {
            uint32_t paddingSize = m_rng.Next(0, 512);
            paddingSize = (paddingSize + 3) & ~3;  // Align to 4 bytes

            if (paddingSize > 0) {
                std::vector<uint8_t> padding(paddingSize);
                m_rng.GetBytes(padding);

                for (size_t i = 0; i < padding.size(); ++i) {
                    if (m_rng.Next(2) == 0) {
                        padding[i] = 0x90;  // NOP
                    }
                }

                sec.data.insert(sec.data.end(), padding.begin(), padding.end());
                sec.virtualSize += paddingSize;
            }
        }
    }

    // 6. Randomize alignment
    if (m_randomAlignment) {
        for (auto& sec : sections) {
            uint32_t alignment = 512 << m_rng.Next(0, 4);
            sec.characteristics &= ~0x00F00000;
            sec.characteristics |= (alignment == 512) ? 0x00100000 :
                                   (alignment == 1024) ? 0x00200000 :
                                   (alignment == 2048) ? 0x00300000 :
                                   0x00400000;
        }
    }

    // 7. Layout sections in virtual and raw memory space
    uint32_t sectionAlignment = is64Bit ? optionalHeader64->SectionAlignment : optionalHeader32->SectionAlignment;
    uint32_t fileAlignment = is64Bit ? optionalHeader64->FileAlignment : optionalHeader32->FileAlignment;

    sections[0].rawAddress = sections[0].header.PointerToRawData;
    if (sections[0].header.SizeOfRawData == 0) {
        sections[0].rawAddress = 0;
        sections[0].rawSize = 0;
    } else {
        sections[0].rawSize = alignUp(static_cast<uint32_t>(sections[0].data.size()), fileAlignment);
    }

    // 8. Reconstruct new PE image
    uint32_t headersSize = sections[0].rawAddress;
    if (headersSize == 0) {
        headersSize = is64Bit ? optionalHeader64->SizeOfHeaders : optionalHeader32->SizeOfHeaders;
    }

    for (size_t i = 1; i < sections.size(); ++i) {
        sections[i].virtualAddress = sections[i-1].virtualAddress +
            alignUp(sections[i-1].virtualSize, sectionAlignment);

        if (sections[i].header.SizeOfRawData == 0) {
            sections[i].rawAddress = 0;
            sections[i].rawSize = 0;
        } else {
            // Find preceding section that has non-zero raw configuration to calculate raw offset
            uint32_t prevRawAddress = 0;
            uint32_t prevRawSize = 0;
            for (int prev = static_cast<int>(i) - 1; prev >= 0; --prev) {
                if (sections[prev].rawAddress != 0 || sections[prev].rawSize != 0) {
                    prevRawAddress = sections[prev].rawAddress;
                    prevRawSize = sections[prev].rawSize;
                    break;
                }
            }
            if (prevRawAddress == 0) {
                // If all preceding sections were uninitialized data (extremely rare), use headers size
                sections[i].rawAddress = alignUp(headersSize, fileAlignment);
            } else {
                sections[i].rawAddress = prevRawAddress + prevRawSize;
            }
            sections[i].rawSize = alignUp(static_cast<uint32_t>(sections[i].data.size()), fileAlignment);
        }
    }

    std::vector<uint8_t> newPeData;
    if (headersSize > peData.size()) return false;

    newPeData.assign(peData.begin(), peData.begin() + headersSize);

    // Update section count in File Header
    auto* newDosHeader = reinterpret_cast<PE::IMAGE_DOS_HEADER*>(newPeData.data());
    uint32_t newPeOffset = newDosHeader->e_lfanew;
    auto* newFileHeader = reinterpret_cast<PE::IMAGE_FILE_HEADER*>(
        newPeData.data() + newPeOffset + 4);
    newFileHeader->NumberOfSections = static_cast<uint16_t>(sections.size());

    uint8_t* newOptionalHeaderPtr = reinterpret_cast<uint8_t*>(newFileHeader) + sizeof(PE::IMAGE_FILE_HEADER);

    // Update Section Table headers in new PE headers
    PE::IMAGE_SECTION_HEADER* newFirstSectionHeader = reinterpret_cast<PE::IMAGE_SECTION_HEADER*>(
        newOptionalHeaderPtr + newFileHeader->SizeOfOptionalHeader);

    for (size_t i = 0; i < sections.size(); ++i) {
        PE::IMAGE_SECTION_HEADER* secHeader = newFirstSectionHeader + i;
        
        // Preserve original section header fields not modified by layout
        if (i < static_cast<size_t>(fileHeader->NumberOfSections)) {
            *secHeader = sections[i].header;
        } else {
            memset(secHeader, 0, sizeof(PE::IMAGE_SECTION_HEADER));
        }

        memset(secHeader->Name, 0, 8);
        memcpy(secHeader->Name, sections[i].name.c_str(),
            std::min(sections[i].name.size(), size_t(8)));

        secHeader->VirtualSize = sections[i].virtualSize;
        secHeader->VirtualAddress = sections[i].virtualAddress;
        secHeader->SizeOfRawData = sections[i].rawSize;
        secHeader->PointerToRawData = sections[i].rawAddress;
        secHeader->Characteristics = sections[i].characteristics;
    }

    // Write section data blocks (and zero-pad them to rawSize)
    for (size_t i = 0; i < sections.size(); ++i) {
        if (sections[i].rawAddress == 0) continue; // Skip uninitialized sections (like .bss)

        if (newPeData.size() < sections[i].rawAddress) {
            newPeData.resize(sections[i].rawAddress, 0);
        } else if (newPeData.size() > sections[i].rawAddress) {
            newPeData.resize(sections[i].rawAddress);
        }

        newPeData.insert(newPeData.end(), sections[i].data.begin(), sections[i].data.end());

        uint32_t expectedEnd = sections[i].rawAddress + sections[i].rawSize;
        if (newPeData.size() < expectedEnd) {
            newPeData.resize(expectedEnd, 0);
        }
    }

    // Refresh optional header pointers
    newDosHeader = reinterpret_cast<PE::IMAGE_DOS_HEADER*>(newPeData.data());
    newPeOffset = newDosHeader->e_lfanew;
    newFileHeader = reinterpret_cast<PE::IMAGE_FILE_HEADER*>(
        newPeData.data() + newPeOffset + 4);
    newOptionalHeaderPtr = reinterpret_cast<uint8_t*>(newFileHeader) + sizeof(PE::IMAGE_FILE_HEADER);
    
    PE::IMAGE_OPTIONAL_HEADER32* newOptionalHeader32 = nullptr;
    PE::IMAGE_OPTIONAL_HEADER64* newOptionalHeader64 = nullptr;
    if (is64Bit) {
        newOptionalHeader64 = reinterpret_cast<PE::IMAGE_OPTIONAL_HEADER64*>(newOptionalHeaderPtr);
    } else {
        newOptionalHeader32 = reinterpret_cast<PE::IMAGE_OPTIONAL_HEADER32*>(newOptionalHeaderPtr);
    }

    // Update SizeOfImage
    uint32_t newSizeOfImage = sections.back().virtualAddress +
        alignUp(sections.back().virtualSize, sectionAlignment);
    if (is64Bit) {
        newOptionalHeader64->SizeOfImage = newSizeOfImage;
    } else {
        newOptionalHeader32->SizeOfImage = newSizeOfImage;
    }

    // Helper lambdas for RVA adjusting
    auto AdjustRVA = [&](uint32_t rva) -> uint32_t {
        if (rva == 0) return 0;
        for (const auto& sec : sections) {
            if (sec.oldVirtualAddress != 0 &&
                rva >= sec.oldVirtualAddress && rva < sec.oldVirtualAddress + alignUp(sec.header.VirtualSize, sectionAlignment)) {
                return sec.virtualAddress + (rva - sec.oldVirtualAddress);
            }
        }
        return rva;
    };

    // 9. Fix RVAs in Data Directories
    for (int i = 0; i < 16; ++i) {
        uint32_t rva = is64Bit ? newOptionalHeader64->DataDirectory[i].VirtualAddress : newOptionalHeader32->DataDirectory[i].VirtualAddress;
        if (rva != 0) {
            std::cout << "[DEBUG] Directory " << i << " original RVA: 0x" << std::hex << rva << std::dec << std::endl;
            for (size_t j = 0; j < sections.size(); ++j) {
                uint32_t origVirtualAddress = sections[j].oldVirtualAddress;
                uint32_t origVirtualSize = sections[j].header.VirtualSize;

                if (origVirtualAddress != 0 &&
                    rva >= origVirtualAddress && rva < origVirtualAddress + origVirtualSize) {
                    uint32_t offset = rva - origVirtualAddress;
                    std::cout << "[DEBUG] Matched section: " << sections[j].name 
                              << ", oldVA: 0x" << std::hex << origVirtualAddress 
                              << ", newVA: 0x" << sections[j].virtualAddress 
                              << ", offset: 0x" << offset << std::dec << std::endl;
                    if (is64Bit) {
                        newOptionalHeader64->DataDirectory[i].VirtualAddress =
                            sections[j].virtualAddress + offset;
                    } else {
                        newOptionalHeader32->DataDirectory[i].VirtualAddress =
                            sections[j].virtualAddress + offset;
                    }
                    break;
                }
            }
        }
    }

    // 9.5 Fix x64 exception handling directory (.pdata) table entries
    if (is64Bit) {
        uint32_t exceptionRva = newOptionalHeader64->DataDirectory[3].VirtualAddress;
        uint32_t exceptionSize = newOptionalHeader64->DataDirectory[3].Size;
        if (exceptionRva != 0 && exceptionSize != 0) {
            std::cout << "[DEBUG] Exception Directory RVA: 0x" << std::hex << exceptionRva 
                      << ", Size: 0x" << exceptionSize << std::dec << std::endl;
            for (const auto& sec : sections) {
                if (exceptionRva >= sec.virtualAddress && exceptionRva < sec.virtualAddress + alignUp(sec.virtualSize, sectionAlignment)) {
                    uint32_t fileOffset = sec.rawAddress + (exceptionRva - sec.virtualAddress);
                    if (fileOffset + exceptionSize <= newPeData.size()) {
                        struct RUNTIME_FUNCTION {
                            uint32_t BeginAddress;
                            uint32_t EndAddress;
                            uint32_t UnwindInfoAddress;
                        };
                        
                        uint32_t pos = fileOffset;
                        int updatedHandlersCount = 0;
                        while (pos + sizeof(RUNTIME_FUNCTION) <= fileOffset + exceptionSize) {
                            RUNTIME_FUNCTION* rf = reinterpret_cast<RUNTIME_FUNCTION*>(&newPeData[pos]);
                            
                            // Adjust ExceptionHandler RVA inside the UNWIND_INFO structure if it exists.
                            // Note: at this point, UnwindInfoAddress is still the ORIGINAL RVA (it hasn't been updated yet!).
                            // So we search for the section containing the original RVA (using s.oldVirtualAddress).
                            if (rf->UnwindInfoAddress != 0) {
                                uint32_t unwRva = rf->UnwindInfoAddress;
                                for (const auto& s : sections) {
                                    if (s.oldVirtualAddress != 0 &&
                                        unwRva >= s.oldVirtualAddress && unwRva < s.oldVirtualAddress + alignUp(s.header.VirtualSize, sectionAlignment)) {
                                        // But UNWIND_INFO content itself is stored in the REBUILT section data, 
                                        // so we locate it inside newPeData using the NEW layout offset of s.
                                        uint32_t offsetInSec = unwRva - s.oldVirtualAddress;
                                        uint32_t unwFileOffset = s.rawAddress + offsetInSec;
                                        
                                        if (unwFileOffset + 4 <= newPeData.size()) {
                                            uint8_t verFlags = newPeData[unwFileOffset];
                                            uint8_t flags = verFlags >> 3;
                                            uint8_t countOfCodes = newPeData[unwFileOffset + 2];
                                            
                                            // UNW_FLAG_EHANDLER = 1, UNW_FLAG_UHANDLER = 2
                                            if ((flags & 3) != 0) {
                                                uint32_t codesAligned = (countOfCodes + 1) & 0xFE;
                                                uint32_t handlerOffset = unwFileOffset + 4 + (codesAligned * 2);
                                                if (handlerOffset + 4 <= newPeData.size()) {
                                                    uint32_t* handlerRvaPtr = reinterpret_cast<uint32_t*>(&newPeData[handlerOffset]);
                                                    *handlerRvaPtr = AdjustRVA(*handlerRvaPtr);
                                                    updatedHandlersCount++;
                                                }
                                            }
                                        }
                                        break;
                                    }
                                }
                            }
                            
                            rf->BeginAddress = AdjustRVA(rf->BeginAddress);
                            rf->EndAddress = AdjustRVA(rf->EndAddress);
                            rf->UnwindInfoAddress = AdjustRVA(rf->UnwindInfoAddress);
                            pos += sizeof(RUNTIME_FUNCTION);
                        }
                        std::cout << "[DEBUG] Updated " << updatedHandlersCount << " exception handler pointers inside UNWIND_INFO structures." << std::endl;
                    }
                    break;
                }
            }
        }
    }

    // 10. Fix RVAs in Relocations
    uint32_t relocRva = is64Bit ? newOptionalHeader64->DataDirectory[5].VirtualAddress : newOptionalHeader32->DataDirectory[5].VirtualAddress;
    uint32_t relocSize = is64Bit ? newOptionalHeader64->DataDirectory[5].Size : newOptionalHeader32->DataDirectory[5].Size;

    if (relocRva != 0 && relocSize != 0) {
        for (const auto& sec : sections) {
            if (relocRva >= sec.virtualAddress && relocRva < sec.virtualAddress + alignUp(sec.virtualSize, sectionAlignment)) {
                uint32_t fileOffset = sec.rawAddress + (relocRva - sec.virtualAddress);

                if (fileOffset + relocSize <= newPeData.size()) {
                    size_t pos = fileOffset;
                    while (pos < fileOffset + relocSize) {
                        if (pos + sizeof(PE::IMAGE_BASE_RELOCATION) > fileOffset + relocSize) break;

                        auto* reloc = reinterpret_cast<PE::IMAGE_BASE_RELOCATION*>(&newPeData[pos]);
                        if (reloc->VirtualAddress == 0) break;
                        if (reloc->SizeOfBlock < sizeof(PE::IMAGE_BASE_RELOCATION)) break;

                        uint32_t numEntries = (reloc->SizeOfBlock - sizeof(PE::IMAGE_BASE_RELOCATION)) / 2;
                        uint16_t* entries = reinterpret_cast<uint16_t*>(
                            &newPeData[pos + sizeof(PE::IMAGE_BASE_RELOCATION)]);

                        uint32_t oldPageRva = reloc->VirtualAddress;
                        uint32_t newPageRva = oldPageRva;
                        uint32_t targetSectionIndex = 0xFFFFFFFF;

                        for (size_t j = 0; j < sections.size(); ++j) {
                            if (sections[j].oldVirtualAddress != 0 &&
                                oldPageRva >= sections[j].oldVirtualAddress &&
                                oldPageRva < sections[j].oldVirtualAddress + alignUp(sections[j].header.VirtualSize, sectionAlignment)) {
                                uint32_t offset = oldPageRva - sections[j].oldVirtualAddress;
                                newPageRva = sections[j].virtualAddress + offset;
                                targetSectionIndex = static_cast<uint32_t>(j);
                                break;
                            }
                        }

                        reloc->VirtualAddress = newPageRva;

                        for (uint32_t i = 0; i < numEntries; ++i) {
                            uint16_t entry = entries[i];
                            uint16_t type = (entry >> 12) & 0xF;
                            uint16_t offset = entry & 0xFFF;

                            if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                                if (targetSectionIndex != 0xFFFFFFFF) {
                                    const auto& targetSec = sections[targetSectionIndex];
                                    uint32_t targetFileOffset = targetSec.rawAddress +
                                        (newPageRva + offset - targetSec.virtualAddress);

                                    if (type == IMAGE_REL_BASED_HIGHLOW && targetFileOffset + 4 <= newPeData.size()) {
                                        uint32_t* addr = reinterpret_cast<uint32_t*>(&newPeData[targetFileOffset]);
                                        uint32_t oldValue = *addr;
                                        uint64_t imageBase = is64Bit ? newOptionalHeader64->ImageBase : newOptionalHeader32->ImageBase;

                                        for (const auto& s : sections) {
                                            if (s.oldVirtualAddress != 0) {
                                                // Absolute address match
                                                if (oldValue >= imageBase + s.oldVirtualAddress &&
                                                    oldValue < imageBase + s.oldVirtualAddress + alignUp(s.header.VirtualSize, sectionAlignment)) {
                                                    *addr = oldValue - s.oldVirtualAddress + s.virtualAddress;
                                                    break;
                                                }
                                                // RVA match
                                                if (oldValue >= s.oldVirtualAddress &&
                                                    oldValue < s.oldVirtualAddress + alignUp(s.header.VirtualSize, sectionAlignment)) {
                                                    *addr = oldValue - s.oldVirtualAddress + s.virtualAddress;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    else if (type == IMAGE_REL_BASED_DIR64 && targetFileOffset + 8 <= newPeData.size()) {
                                        uint64_t* addr64 = reinterpret_cast<uint64_t*>(&newPeData[targetFileOffset]);
                                        uint64_t oldValue64 = *addr64;
                                        uint64_t imageBase = is64Bit ? newOptionalHeader64->ImageBase : newOptionalHeader32->ImageBase;

                                        for (const auto& s : sections) {
                                            if (s.oldVirtualAddress != 0) {
                                                // Absolute address match
                                                if (oldValue64 >= imageBase + s.oldVirtualAddress &&
                                                    oldValue64 < imageBase + s.oldVirtualAddress + alignUp(s.header.VirtualSize, sectionAlignment)) {
                                                    *addr64 = oldValue64 - s.oldVirtualAddress + s.virtualAddress;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        pos += reloc->SizeOfBlock;
                    }
                }
                break;
            }
        }
    }

    // Helper lambdas for RVA adjusting
    auto FixThunks = [&](uint32_t thunkRva) {
        for (const auto& sec : sections) {
            if (thunkRva >= sec.virtualAddress && thunkRva < sec.virtualAddress + alignUp(sec.virtualSize, sectionAlignment)) {
                uint32_t fileOffset = sec.rawAddress + (thunkRva - sec.virtualAddress);
                uint32_t pos = fileOffset;
                
                if (is64Bit) {
                    while (pos + 8 <= newPeData.size()) {
                        auto* thunk64 = reinterpret_cast<PE::IMAGE_THUNK_DATA64*>(&newPeData[pos]);
                        if (thunk64->u1.AddressOfData == 0) break;
                        
                        if (!(thunk64->u1.Ordinal & 0x8000000000000000ULL)) {
                            thunk64->u1.AddressOfData = AdjustRVA(static_cast<uint32_t>(thunk64->u1.AddressOfData));
                        }
                        pos += 8;
                    }
                } else {
                    while (pos + 4 <= newPeData.size()) {
                        auto* thunk32 = reinterpret_cast<PE::IMAGE_THUNK_DATA32*>(&newPeData[pos]);
                        if (thunk32->u1.AddressOfData == 0) break;
                        
                        if (!(thunk32->u1.Ordinal & 0x80000000)) {
                            thunk32->u1.AddressOfData = AdjustRVA(thunk32->u1.AddressOfData);
                        }
                        pos += 4;
                    }
                }
                break;
            }
        }
    };

    // 11. Fix entry point and headers RVAs
    if (is64Bit) {
        newOptionalHeader64->AddressOfEntryPoint = AdjustRVA(newOptionalHeader64->AddressOfEntryPoint);
        newOptionalHeader64->BaseOfCode = AdjustRVA(newOptionalHeader64->BaseOfCode);
    } else {
        newOptionalHeader32->AddressOfEntryPoint = AdjustRVA(newOptionalHeader32->AddressOfEntryPoint);
        newOptionalHeader32->BaseOfCode = AdjustRVA(newOptionalHeader32->BaseOfCode);
        newOptionalHeader32->BaseOfData = AdjustRVA(newOptionalHeader32->BaseOfData);
    }

    // 12. Fix Import Directory pointers
    uint32_t importRva = is64Bit ? newOptionalHeader64->DataDirectory[1].VirtualAddress : newOptionalHeader32->DataDirectory[1].VirtualAddress;
    uint32_t importSize = is64Bit ? newOptionalHeader64->DataDirectory[1].Size : newOptionalHeader32->DataDirectory[1].Size;
    if (importRva != 0 && importSize != 0) {
        for (const auto& sec : sections) {
            if (importRva >= sec.virtualAddress && importRva < sec.virtualAddress + alignUp(sec.virtualSize, sectionAlignment)) {
                uint32_t fileOffset = sec.rawAddress + (importRva - sec.virtualAddress);
                if (fileOffset + importSize <= newPeData.size()) {
                    uint32_t descOffset = fileOffset;
                    while (descOffset + sizeof(PE::IMAGE_IMPORT_DESCRIPTOR) <= fileOffset + importSize) {
                        auto* importDesc = reinterpret_cast<PE::IMAGE_IMPORT_DESCRIPTOR*>(&newPeData[descOffset]);
                        if (importDesc->Name == 0) break;
                        
                        importDesc->Name = AdjustRVA(importDesc->Name);
                        if (importDesc->OriginalFirstThunk != 0) {
                            importDesc->OriginalFirstThunk = AdjustRVA(importDesc->OriginalFirstThunk);
                            FixThunks(importDesc->OriginalFirstThunk);
                        }
                        if (importDesc->FirstThunk != 0) {
                            importDesc->FirstThunk = AdjustRVA(importDesc->FirstThunk);
                            FixThunks(importDesc->FirstThunk);
                        }
                        descOffset += sizeof(PE::IMAGE_IMPORT_DESCRIPTOR);
                    }
                }
                break;
            }
        }
    }

    // 13. Fix Export Directory pointers
    uint32_t exportRva = is64Bit ? newOptionalHeader64->DataDirectory[0].VirtualAddress : newOptionalHeader32->DataDirectory[0].VirtualAddress;
    uint32_t exportSize = is64Bit ? newOptionalHeader64->DataDirectory[0].Size : newOptionalHeader32->DataDirectory[0].Size;
    if (exportRva != 0 && exportSize != 0) {
        for (const auto& sec : sections) {
            if (exportRva >= sec.virtualAddress && exportRva < sec.virtualAddress + alignUp(sec.virtualSize, sectionAlignment)) {
                uint32_t fileOffset = sec.rawAddress + (exportRva - sec.virtualAddress);
                if (fileOffset + sizeof(PE::IMAGE_EXPORT_DIRECTORY) <= newPeData.size()) {
                    auto* exportDir = reinterpret_cast<PE::IMAGE_EXPORT_DIRECTORY*>(&newPeData[fileOffset]);
                    exportDir->Name = AdjustRVA(exportDir->Name);
                    exportDir->AddressOfFunctions = AdjustRVA(exportDir->AddressOfFunctions);
                    exportDir->AddressOfNames = AdjustRVA(exportDir->AddressOfNames);
                    exportDir->AddressOfNameOrdinals = AdjustRVA(exportDir->AddressOfNameOrdinals);
                    
                    uint32_t funcTableRva = exportDir->AddressOfFunctions;
                    uint32_t nameTableRva = exportDir->AddressOfNames;
                    
                    if (funcTableRva != 0) {
                        for (const auto& s : sections) {
                            if (funcTableRva >= s.virtualAddress && funcTableRva < s.virtualAddress + alignUp(s.virtualSize, sectionAlignment)) {
                                uint32_t funcFileOffset = s.rawAddress + (funcTableRva - s.virtualAddress);
                                for (uint32_t k = 0; k < exportDir->NumberOfFunctions; ++k) {
                                    if (funcFileOffset + (k + 1) * 4 <= newPeData.size()) {
                                        uint32_t* funcAddr = reinterpret_cast<uint32_t*>(&newPeData[funcFileOffset + k * 4]);
                                        *funcAddr = AdjustRVA(*funcAddr);
                                    }
                                }
                                break;
                            }
                        }
                    }
                    if (nameTableRva != 0) {
                        for (const auto& s : sections) {
                            if (nameTableRva >= s.virtualAddress && nameTableRva < s.virtualAddress + alignUp(s.virtualSize, sectionAlignment)) {
                                uint32_t nameFileOffset = s.rawAddress + (nameTableRva - s.virtualAddress);
                                for (uint32_t k = 0; k < exportDir->NumberOfNames; ++k) {
                                    if (nameFileOffset + (k + 1) * 4 <= newPeData.size()) {
                                        uint32_t* nameAddr = reinterpret_cast<uint32_t*>(&newPeData[nameFileOffset + k * 4]);
                                        *nameAddr = AdjustRVA(*nameAddr);
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
                break;
            }
        }
    }

    // 13.5 Fix Resource Directory pointers
    uint32_t rsrcRva = is64Bit ? newOptionalHeader64->DataDirectory[2].VirtualAddress : newOptionalHeader32->DataDirectory[2].VirtualAddress;
    uint32_t rsrcSize = is64Bit ? newOptionalHeader64->DataDirectory[2].Size : newOptionalHeader32->DataDirectory[2].Size;
    if (rsrcRva != 0 && rsrcSize != 0) {
        for (const auto& sec : sections) {
            if (rsrcRva >= sec.virtualAddress && rsrcRva < sec.virtualAddress + alignUp(sec.virtualSize, sectionAlignment)) {
                uint32_t fileOffset = sec.rawAddress + (rsrcRva - sec.virtualAddress);
                if (fileOffset + rsrcSize <= newPeData.size()) {
                    uint8_t* resourceBase = &newPeData[fileOffset];
                    
                    std::function<void(uint32_t)> FixResourceDirectory = [&](uint32_t dirOffset) {
                        if (dirOffset + sizeof(IMAGE_RESOURCE_DIRECTORY) > rsrcSize) return;
                        auto* dir = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY*>(resourceBase + dirOffset);
                        uint32_t numEntries = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
                        uint32_t entryOffset = dirOffset + sizeof(IMAGE_RESOURCE_DIRECTORY);
                        
                        for (uint32_t i = 0; i < numEntries; ++i) {
                            if (entryOffset + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > rsrcSize) return;
                            auto* entry = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY*>(resourceBase + entryOffset);
                            
                            if (entry->isDirectory()) {
                                FixResourceDirectory(entry->getOffset());
                            } else {
                                uint32_t dataEntryOffset = entry->getOffset();
                                if (dataEntryOffset + sizeof(IMAGE_RESOURCE_DATA_ENTRY) <= rsrcSize) {
                                    auto* dataEntry = reinterpret_cast<IMAGE_RESOURCE_DATA_ENTRY*>(resourceBase + dataEntryOffset);
                                    dataEntry->OffsetToData = AdjustRVA(dataEntry->OffsetToData);
                                }
                            }
                            entryOffset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
                        }
                    };
                    
                    FixResourceDirectory(0);
                }
                break;
            }
        }
    }

    // 14. Append trailing overlay data and adjust PointerToSymbolTable
    uint32_t newMaxRaw = 0;
    for (const auto& sec : sections) {
        if (sec.rawSize > 0) {
            uint32_t endRaw = sec.rawAddress + sec.rawSize;
            if (endRaw > newMaxRaw) {
                newMaxRaw = endRaw;
            }
        }
    }

    if (!trailingData.empty()) {
        if (newPeData.size() < newMaxRaw) {
            newPeData.resize(newMaxRaw, 0);
        } else if (newPeData.size() > newMaxRaw) {
            newPeData.resize(newMaxRaw);
        }
        newPeData.insert(newPeData.end(), trailingData.begin(), trailingData.end());

        // Refresh headers pointers to adjust PointerToSymbolTable
        newDosHeader = reinterpret_cast<PE::IMAGE_DOS_HEADER*>(newPeData.data());
        newPeOffset = newDosHeader->e_lfanew;
        newFileHeader = reinterpret_cast<PE::IMAGE_FILE_HEADER*>(
            newPeData.data() + newPeOffset + 4);
            
        if (newFileHeader->PointerToSymbolTable != 0) {
            uint32_t symOffset = newFileHeader->PointerToSymbolTable;
            if (symOffset >= originalMaxRaw) {
                newFileHeader->PointerToSymbolTable = symOffset - originalMaxRaw + newMaxRaw;
            }
        }
    }

    peData = std::move(newPeData);
    UpdateChecksum(peData);
    return true;
}

} // namespace Polymorphic