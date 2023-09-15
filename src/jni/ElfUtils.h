#pragma once

#include <functional>
#include <elf.h>
#include <string>

/**
 * @brief Holds the ELF File Mapping
*/
union ElfPack {
    /**
     * @brief Pointer to ELF Header
    */
    Elf32_Ehdr* header;

    /**
     * @brief Pointer to ELF64 Header
    */
    Elf64_Ehdr* header64;

    /**
     * @brief ELF File mapping base address
    */
    uintptr_t base;

    /**
     * @brief Pointer to the ELF Mapping
    */
    void* baseV;

    /**
     * @brief Lazy int version of the Mapping Pointer, to easily do checks
    */
    int res;
};

/**
 * @brief Initializes the ELF Library, Notify Callback, Cleanup, Frees the ELF library
 * @returns true if all the operations was sucessfully, false otherwise
*/
bool ElfOpen(const std::string& fullModulePath, std::function<void(ElfPack libMap)> callback);

/**
 * @brief Check if ELF file is 64 bits.
 * @returns true if ELF File is 64 bits, false otherwise
*/
bool ElfPeekIs64(const std::string& fullModulePath, bool& outResult);

/**
 * @brief Get a ELF Section by its given Index.
 * @param sectionIdx: the given section index
 * @returns a pointer to a section header if valid, nullptr otherwise
*/
Elf32_Shdr* ElfSectionByIndex(ElfPack libMap, unsigned int sectionIdx);

/**
 * @brief Traverses all sections within the ELF File
 * @param callback: will be reported, all the given sections
*/
void ElfForEachSection(ElfPack libMap, std::function<bool(Elf32_Shdr* pCurrentSection)> callback);

/**
 * @brief Lookup an ELF Section by its given type
 * @param sectionType: ELF Section Type
 * @returns A pointer to the section if it exists; nullptr otherwise. 
*/
Elf32_Shdr* ElfLookupSectionByType(ElfPack libMap, uint32_t sectionType);

/**
 * @brief Retrieve the ELF Section Headers Name Blob (shstr) Entry.
 * @returns A pointer to the char blob entry if exist; nullptr otherwise
*/
const char* ElfGetSectionHeadersStringBlob(ElfPack libMap);

/**
 * @brief Retrieve ELF Section name
 * @param sectionHdr: Pointer to ELF Section Header
 * @returns A Pointer to the section name if exist; nullptr otherwise.
*/
const char* ElfGetSectionName(ElfPack libMap, Elf32_Shdr* sectionHdr);

/**
 * @brief Lookup a ELF Header by its name
 * @param sectionName: Name of the section (ex: ".rodata", ".text" ...)
 * @returns A Pointer to the ELF Section if found; nullptr otherwise.
*/
Elf32_Shdr* ElfLookupSectionByName(ElfPack libMap, const std::string& sectionName);

/**
 * @brief Retrieve any available Symbol Table ELF Section.
 * @returns A pointer to the Symbol Table ELF Section if exist; nullptr otherwise;
 * @note This function first searches for an SHT_SYMTAB type, and if none is found,
 * it searches for an SHT_DYNSYM type.
*/
Elf32_Shdr* ElfGetSymbolSection(ElfPack libMap);

/**
 * @brief Traverse the symbol table.
 * @param callback: A callback, for each symbol found, this callback will be invocated with the actual symbol & its name.
 * @returns true if a symbol table to traverse was found, nullptr otherwise.
*/
bool ElfForEachSymbol(ElfPack libMap, std::function<bool(Elf32_Sym* pCurrentSym, const char* pCurrSymName)> callback);

/**
 * @brief Lookup a symbol by its name.
 * @param symbolName: The Name of the symbol to look for.
 * @param outSymbolOff: (optional) A Pointer to variable where resulting relative displacement of the symbol will be saved if found.
 * @returns true if the symbol was found, false otherwise.
 * @note Symbol lookup may fail for various reasons, such as the absence of a symbol table or the symbol not being present in the symbol table.
*/
bool ElfLookupSymbol(ElfPack libMap, const std::string& symbolName, uint64_t* outSymbolOff = nullptr);