// src/SectionRandomizer.h
#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include "Utils.h"
#include "PEStructs.h"

namespace Polymorphic {

class SectionRandomizer {
public:
    struct SectionInfo {
        std::string name;
        uint32_t virtualSize;
        uint32_t virtualAddress;
        uint32_t rawSize;
        uint32_t rawAddress;
        uint32_t characteristics;
        std::vector<uint8_t> data;
    };

    SectionRandomizer(CryptoRandom& rng);
    
    // Randomize section order and properties
    bool Randomize(std::vector<uint8_t>& peData);
    
    // Set randomization options
    void SetRandomizeOrder(bool enable);
    void SetRandomizeNames(bool enable);
    void SetMergeSections(bool enable);
    void SetAddPadding(bool enable);
    void SetRandomAlignment(bool enable);
    
    // Add custom section
    void AddCustomSection(const SectionInfo& section);
    
private:
    CryptoRandom& m_rng;
    bool m_randomizeOrder;
    bool m_randomizeNames;
    bool m_mergeSections;
    bool m_addPadding;
    bool m_randomAlignment;
    
    std::vector<SectionInfo> m_customSections;
    
    // PE parsing
    bool ParsePE(std::vector<uint8_t>& data, 
        PE::IMAGE_DOS_HEADER*& dosHeader,
        PE::IMAGE_FILE_HEADER*& fileHeader,
        PE::IMAGE_OPTIONAL_HEADER32*& optionalHeader,
        std::vector<PE::IMAGE_SECTION_HEADER*>& sections);
    
    // Randomization methods
    void ShuffleSections(std::vector<PE::IMAGE_SECTION_HEADER*>& sections);
    void RenameSections(std::vector<PE::IMAGE_SECTION_HEADER*>& sections);
    void MergeSections(std::vector<uint8_t>& data,
        std::vector<PE::IMAGE_SECTION_HEADER*>& sections);
    void AddRandomPadding(std::vector<uint8_t>& data,
        std::vector<PE::IMAGE_SECTION_HEADER*>& sections);
    void RandomizeAlignment(std::vector<PE::IMAGE_SECTION_HEADER*>& sections);
    
    // Fix RVAs after reordering
    void FixRVAs(std::vector<uint8_t>& data,
        const std::vector<PE::IMAGE_SECTION_HEADER*>& oldSections,
        const std::vector<PE::IMAGE_SECTION_HEADER*>& newSections);
    
    // Generate random section name
    std::string GenerateSectionName();
    
    // Calculate new checksum
    void UpdateChecksum(std::vector<uint8_t>& data);
};

} // namespace Polymorphic