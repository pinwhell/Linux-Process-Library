#pragma once

#include <functional>
#include <elf.h>
#include <string>

union ElfPack {
    Elf32_Ehdr* header;
    Elf64_Ehdr* header64;
    uintptr_t base;
    void* baseV;
    int res;
};

bool ElfOpen(const std::string& fullModulePath, std::function<void(ElfPack libMap)> callback);
bool ElfPeekIs64(const std::string& fullModulePath, bool& outResult);
Elf32_Shdr* ElfSectionByIndex(ElfPack libMap, unsigned int sectionIdx);
void ElfForEachSection(ElfPack libMap, std::function<bool(Elf32_Shdr* pCurrentSection)> callback);
Elf32_Shdr* ElfLookupSectionByType(ElfPack libMap, uint32_t sectionType);
const char* ElfGetSectionHeadersStringBlob(ElfPack libMap);
const char* ElfGetSectionName(ElfPack libMap, Elf32_Shdr* sectionHdr);
Elf32_Shdr* ElfLookupSectionByName(ElfPack libMap, const std::string& sectionName);
Elf32_Shdr* ElfGetSymbolSection(ElfPack libMap);
bool ElfForEachSymbol(ElfPack libMap, std::function<bool(Elf32_Sym* pCurrentSym, const char* pCurrSymName)> callback);
bool ElfLookupSymbol(ElfPack libMap, const std::string& symbolName, uint64_t* outSymbolOff = nullptr);