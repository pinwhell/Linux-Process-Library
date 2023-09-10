#include <sys/stat.h>
#include <sys/mman.h>
#include "ElfUtils.h"
#include <fcntl.h>
#include <unistd.h>

bool ElfOpen(const std::string& fullModulePath, std::function<void(ElfPack libMap)> callback)
{
    int libFd = open(fullModulePath.c_str(), O_RDONLY);

    if(libFd < 0)
        return false;

    struct stat libStats;

    if(fstat(libFd, &libStats) != 0)
    {
        close(libFd);
        return false;
    } 

    ElfPack libMap;
    
    libMap.baseV = mmap(NULL, libStats.st_size, PROT_READ, MAP_SHARED, libFd, 0 );

    if(libMap.res == -1)
    {
        close(libFd);
        return false;
    }   

    callback(libMap);

    munmap(libMap.baseV, libStats.st_size);

    close(libFd);
    return true;
}

Elf32_Shdr* ElfSectionByIndex(ElfPack libMap, unsigned int sectionIdx)
{
    if((sectionIdx < libMap.header->e_shnum) == false)
        return nullptr;

    Elf32_Shdr* libElfSections = (Elf32_Shdr*)(libMap.base + libMap.header->e_shoff);

    return libElfSections + sectionIdx;
}

void ElfForEachSection(ElfPack libMap, std::function<bool(Elf32_Shdr* pCurrentSection)> callback)
{
    Elf32_Shdr* libElfSections = (Elf32_Shdr*)(libMap.base + libMap.header->e_shoff);

    for(int i = 0; i < libMap.header->e_shnum; i++)
    {
        if(callback(libElfSections + i) == false)
            break;
    }
}

Elf32_Shdr* ElfLookupSection(ElfPack libMap, uint32_t sectionType)
{
    Elf32_Shdr* secHeader = nullptr;

    ElfForEachSection(libMap, [&](Elf32_Shdr* currSection){
        if(currSection->sh_type != sectionType)
            return true;
        
        secHeader = currSection;

        return false;        
    });

    return secHeader;
}

Elf32_Shdr* ElfGetSymbolSection(ElfPack libMap)
{
    Elf32_Shdr* result = nullptr;
    
    result = ElfLookupSection(libMap, SHT_SYMTAB);

    if(result)
        return result;

    result = ElfLookupSection(libMap, SHT_DYNSYM);

    if(result)
        return result;

    return result;
}

bool ElfForEachSymbol(ElfPack libMap, std::function<bool(Elf32_Sym* pCurrentSym, const char* pCurrSymName)> callback)
{
    Elf32_Shdr* symTable = ElfGetSymbolSection(libMap);

    if(symTable == nullptr)
        return false;

    Elf32_Shdr* strTable = ElfSectionByIndex(libMap, symTable->sh_link);

    if(strTable == nullptr)
        return false;

    const char* elfStrBlob = (const char*)(libMap.base + strTable->sh_offset);

    int nSyms = symTable->sh_size / sizeof(Elf32_Sym);
    Elf32_Sym* symEntry = (Elf32_Sym*)(libMap.base + symTable->sh_offset);
    Elf32_Sym* symEnd = symEntry + nSyms;

    for(Elf32_Sym* sym = symEntry; sym < symEnd;  sym++)
    {
        if((ELF32_ST_BIND(sym->st_info) & (STT_FUNC | STB_GLOBAL)) == 0)
            continue;

        if(callback(sym, elfStrBlob + sym->st_name) == false)
            break;
    }

    return true;
}

bool ElfLookupSymbol(ElfPack libMap, const std::string& symbolName, uint64_t* outSymbolOff)
{
    Elf32_Sym* result = nullptr;
    if(ElfForEachSymbol(libMap, [&](Elf32_Sym* currSym, const char* currSymName){
        if(strcmp(currSymName, symbolName.c_str()))
            return true;

        result = currSym;

        return false;
    }) == false)
        return false;

    if(outSymbolOff && result)
        *outSymbolOff = result->st_value;

    return result != nullptr;
}