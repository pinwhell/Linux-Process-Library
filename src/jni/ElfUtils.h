#pragma once

#include <functional>
#include <elf.h>
#include <string>

union ElfPack {
    Elf32_Ehdr* header;
    uintptr_t base;
    void* baseV;
    int res;
};

bool ElfOpen(const std::string& fullModulePath, std::function<void(ElfPack libMap)> callback);
Elf32_Shdr* ElfSectionByIndex(ElfPack libMap, unsigned int sectionIdx);
void ElfForEachSection(ElfPack libMap, std::function<bool(Elf32_Shdr* pCurrentSection)> callback);
Elf32_Shdr* ElfLookupSection(ElfPack libMap, uint32_t sectionType);
Elf32_Shdr* ElfGetSymbolSection(ElfPack libMap);
bool ElfForEachSymbol(ElfPack libMap, std::function<bool(Elf32_Sym* pCurrentSym, const char* pCurrSymName)> callback);
bool ElfLookupSymbol(ElfPack libMap, const std::string& symbolName, uint64_t* outSymbolOff = nullptr);