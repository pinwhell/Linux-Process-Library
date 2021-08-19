#include "ProcessManager.h"
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <dlfcn.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

const unsigned char popmask[] = "\xBD\xE8";
const unsigned char bxlrmask[] = "\x1E\xFF\x2F\xE1";
const unsigned char parammask[] = "\xCC\xCC\xCC\xCC";

#define GetBite(buff, pos) (((buff) & (0x1 << (pos)))) ? true : false

/**
 * @brief definig DEBUG will cause, all the function logging its call.
 * 
 */
#define DEBUG

#define ZeroMemory(dst, size) memset((void*)(dst), 0x0, (size))

void LOG(const char* msg)
{
    fprintf(stdout, "%s\n", msg);
    quick_exit(1);
}

int ProcessManager::FindPid(const char* procName){
    #ifdef DEBUG
        printf("FindPid(%s)",procName);
    #endif
    int pid = -1;
    struct dirent* pDirent;
    DIR* dir;

    if(!procName)
        LOG("ProcessManager : not valid process name.\n");

    dir = opendir("/proc/");
    if(!dir)
        LOG("ProcessManager : cant open proc");

    for(int currPid = 0;(pDirent = readdir(dir)) != NULL;)
    {
        if((currPid = atoi(pDirent->d_name)) == 0)
            continue;

        char currCmdLinePath[128];
        sprintf(currCmdLinePath, "/proc/%d/cmdline", currPid);

        int currcmdLineFd = open((const char*)currCmdLinePath, O_RDONLY);
        if(currcmdLineFd == -1)
           continue;

        char currProcName[128];

        memset(currProcName, NULL, 128);
        
        if(!read(currcmdLineFd, currProcName ,128))
            continue;

        if(!strcmp(currProcName, procName))
        {
            pid = currPid;
            break;
        }
    }

    #ifdef DEBUG
        printf(" = %d\n",pid);
    #endif
    closedir(dir);
    return pid;
}

ProcessManager::ProcessManager(const char* procName)
{
    #ifdef DEBUG
        printf("ProcessManager(%s)\n",procName);
    #endif

    char ProcessMemoryPath[128];
    char ProcessMapsPath[128];

    if((pid = FindPid(procName)) == -1)
        LOG("ProcessManager : Could not found the process");

    sprintf(ProcessMemoryPath, "/proc/%d/mem", pid);
    memfd = open(ProcessMemoryPath, O_RDWR);
    sprintf(ProcessMapsPath, "/proc/%d/maps", pid);
    mapsfd = open(ProcessMapsPath, O_RDONLY);

    if(memfd == -1)
        LOG("ProcessManager : Could not open process memory");

    if(mapsfd == -1)
        LOG("ProcessManager : Could not open process maps");

	return;
}

bool GetMapsBuffer(int fd, std::string & result)
{
    #ifdef DEBUG
    printf("GetMapsBuffer(%d)\n",fd);
    #endif

    lseek(fd, 0, SEEK_SET);
    FILE* tmpf = fdopen(fd, "r");
    if(!tmpf)
        return false;

    uintptr_t maxLineSize = 2048;
    char* line = (char*)malloc(maxLineSize);
    memset(line, 0, maxLineSize);
    if(!line)
        return false;

    while(getline(&line, &maxLineSize, tmpf) >= 0)
        result += std::string(line);

    free(line);

    return true;
}

void ParseMapLineSegment(char* lineStartSegment, SegmentInfo* buff)
{
    uintptr_t unk1;
    char* tempName = (char*)malloc(256);
    char* tempProt = (char*)malloc(256);

    sscanf(lineStartSegment, "%08X-%08X %s %08X %02X:%02X %d %s\n", &buff->start, &buff->end, tempProt, &unk1, &unk1, &unk1, &unk1, tempName);
    
    buff->name = std::string(tempName);
    buff->prot = std::string(tempProt);
    buff->size = buff->end - buff->start;

    free(tempProt);
    free(tempName);
    return;
}

char* GetStartOfLine(char* minLimit, char* currLinePos)
{
    char* result = currLinePos;

    if(currLinePos < minLimit)
        return minLimit;

    while(*result != '\n' && result > minLimit) result--;

    return result;
}

bool GetLineSegmentFromName(int fd, const char* modName, SegmentInfo * result)
{
    std::string fullMaps;
    char* fullMapsPtr, *targetLine = nullptr;

    if(!GetMapsBuffer(fd, fullMaps))
        return false;

    fullMapsPtr = (char*)fullMaps.c_str();     
    if((targetLine = strstr(fullMapsPtr, modName)) == nullptr)
        return false;

    targetLine = GetStartOfLine(fullMapsPtr, targetLine);
    ParseMapLineSegment(targetLine, result);

    return true;
}

uintptr_t ProcessManager::GetModBaseAddr(const char* modName)
{
    #ifdef DEBUG
    printf("ProcessManager::GetModBaseAddr(%s)\n",modName);
    #endif

    SegmentInfo tSegment;

    if(!GetLineSegmentFromName(mapsfd, modName, &tSegment))
        return 0;

    return tSegment.start;
}

uintptr_t ProcessManager::FindDMAddy(uintptr_t base, std::vector<uintptr_t> offsets)
{
    uintptr_t result = base;

    for(int i = 0; i < offsets.size(); i++)
    {
        result = ReadProcessMemory<uintptr_t>(result);
        result += offsets[i];
    }

    return result;
}

uintptr_t ProcessManager::GetLocalModBaseAddr(const char* modName)
{
    #ifdef DEBUG
    printf("ProcessManager::GetLocalModBaseAdd(%s)\n",modName);
    #endif

    int localMapsfd = open("/proc/self/maps", O_RDONLY);
    SegmentInfo tSegment;
    ZeroMemory(&tSegment, sizeof(tSegment));

    if(!localMapsfd)
        return 0;

    GetLineSegmentFromName(localMapsfd, modName, &tSegment);
    close(localMapsfd);

    return tSegment.start;
}

bool ProcessManager::GetFullModulePath(const char* modName, std::string & result)
{
    #ifdef DEBUG
    printf("ProcessManager::GetFullModulePath(%s)\n",modName);
    #endif

    SegmentInfo tSegment;

    if(!GetLineSegmentFromName(mapsfd, modName, &tSegment))
        return 0;

    result = tSegment.name;

    return true;
}

uintptr_t ProcessManager::FindExternalSymbol(const char* modName, const char* symbolName)
{
    #ifdef DEBUG
    printf("ProcessManager::FindExternalSymbol(%s, %s)\n",modName, symbolName);
    #endif

    std::string fullModPath;
    int modfd;
    struct stat modstats;

    if(!GetFullModulePath(modName, fullModPath))
        return 0;

    modfd = open(fullModPath.c_str(), O_RDONLY);
    
    fstat(modfd, &modstats);
    uintptr_t modBase = (uintptr_t)mmap(NULL,modstats.st_size, PROT_READ, MAP_SHARED, modfd, 0 );

    Elf32_Ehdr* header = (Elf32_Ehdr*)modBase;
    Elf32_Shdr* sections = (Elf32_Shdr*)((Elf32_Off)modBase + header->e_shoff);

    for(int i = 0; i < header->e_shnum; i++)
    {
        if(sections[i].sh_type == SHT_SYMTAB)
        {
            uintptr_t stringSectionAddr = modBase + sections[sections[i].sh_link].sh_offset;
            Elf32_Sym* currSymbolSectionAddr = (Elf32_Sym*)(modBase + sections[i].sh_offset);

            for(int j = 0; j < (sections[i].sh_size / sizeof(Elf32_Sym));  j++)
            {
                if(ELF32_ST_BIND(currSymbolSectionAddr[j].st_info) & (STT_FUNC | STB_GLOBAL))
                {
                    char* currSymbolName = (char*)(stringSectionAddr + currSymbolSectionAddr[j].st_name);
                    if(!strcmp(currSymbolName, symbolName)){
                        return  GetModBaseAddr(modName) + currSymbolSectionAddr[j].st_value;
                    }
                }
            }
        }
    }

    close(modfd);

    return 0;
}

void ProcessManager::memcpy(unsigned char* source, uintptr_t destination, int size)
{
    for(int i = 0 ; i < size; i++)
        WriteProcessMemory(destination + i, source[i]);
}

bool ProcessManager::memcpyBackwrd(uintptr_t source, unsigned char* destination, int size)
{
     for(int i = 0 ; i < size; i++)
        destination[i] = ReadProcessMemory<unsigned char>(source + i);

    return true;
}

bool ProcessManager::EnumSegments(std::vector<SegmentInfo> & segments, int prot)
{
    #ifdef DEBUG
    printf("ProcessManager::EnumSegments(&)\n");
    #endif

    std::string fullMaps;
    if(!GetMapsBuffer(mapsfd, fullMaps))
        return false;

    char mask[5];

    switch (prot)
    {
    case READ:
        strcpy(mask, "r--p");
    break;

    case READ_WRITE:
        strcpy(mask, "rw-p");
    break;

    case EXECUTE_READ:
        strcpy(mask, "r-xp");
    break;

    case EXECUTE_READ_WRITE:
        strcpy(mask, "rwxp");
    break;

    default:
        return false;
    break;
    }
    
    char* fullMapsPtr = (char*)fullMaps.c_str();
    char* currLinePos = (char*)strstr(fullMapsPtr, (char*)mask);
    char* lastFoundMask = currLinePos;
    for(;currLinePos != nullptr;currLinePos = strstr(lastFoundMask, (char*)mask))
    {
        SegmentInfo currSegment;

        lastFoundMask = currLinePos + 1;
        currLinePos = GetStartOfLine(fullMapsPtr, currLinePos);
        ParseMapLineSegment(currLinePos, &currSegment);
        segments.push_back(currSegment);
    }

    return true;
}

void ProcessManager::DisablePtrace()
{
    #ifdef DEBUG
    printf("ProcessManager::DisablePtrace()\n");
    #endif
    uintptr_t ptraceAddr = ptraceAddr = FindExternalSymbol("libc.so", "ptrace");

    while(!ptraceAddr){
        printf("ProcessManager : ptrace not found\n");
        ptraceAddr = FindExternalSymbol("libc.so", "ptrace");
    };

    unsigned char buff[] = "\x00\x00\xA0\xE3\x1E\xFF\x2F\xE1"; // mov r0, 0
                                                               // bx lr
    memcpy(buff, ptraceAddr, sizeof(buff));
}

uintptr_t ProcessManager::FindCodeCave(uintptr_t size, uintptr_t prot)
{
    #ifdef DEBUG
    printf("ProcessManager::FindCodeCave(%08X, %d)\n", size, prot);
    #endif

    std::vector<SegmentInfo> segments;
    if(!EnumSegments(segments, prot))
        return 0;
    
    size = ((size / 4) + 1) * 4;
    for(int i = 0; i < segments.size(); i++)
    {
        uintptr_t lastMatchIndex = 0;
        for(uintptr_t currAddr = segments[i].start; currAddr + size < segments[i].end; currAddr += 1 + lastMatchIndex)
        {
            if(ReadProcessMemory<unsigned char>(currAddr) == 0x0)
            {
                bool found = true;
                for(int j = 1; j <= size; j++)
                {
                    if(ReadProcessMemory<unsigned char>(currAddr + j) != 0x0)
                    {
                        found = false;
                        break;
                    } else 
                        lastMatchIndex = j;
                }

                if(found)
                    return ((currAddr / 4) + 1) * 4;
            }
        }
    }

    return 0;
}

bool ProcessManager::Hook(uintptr_t src, uintptr_t dst, uintptr_t size)
{
    #ifdef DEBUG
    printf("ProcessManager::Hook(%08X, %08X, %08X)\n", src, dst, size);
    #endif
     unsigned char* detourPtr;
     uintptr_t tSize = size;
    #ifdef __arm__
        if(tSize < 8)
                return false;

        unsigned char detour[] = {0x04, 0xF0, 0x1F, 0xE5, 0x0, 0x0, 0x0, 0x0};
        *(uintptr_t*)(detour + 4) = dst;
        detourPtr = ( unsigned char*)detour;
    #elif defined(__i386__)
        if(tSize < 5)
            return false;

        unsigned char detour[] = {0xE9, 0x0, 0x0, 0x0, 0x0};
        uintptr_t relativeAddr = src - dst - 5;
        *(uintptr_t*)(detour + 1) = relativeAddr;
    #endif

    memcpy(detourPtr, src, tSize);

    return true;
}

bool RelatedReturn(void* _chunk)
{
	bool found = false;
	if (!memcmp(popmask, (unsigned char*)_chunk + 2, 2))
	{															
		int8_t chunk = *(int8_t*)((unsigned char*)_chunk + 1);
		if(GetBite(chunk, 7))
			found = true;
	}

	if (!memcmp(bxlrmask, _chunk, 4))
		found = true;

	return found;
}

uintptr_t GetFuncSizeArm(void* Func)
{
	if (!Func)
		return 0;

	for (unsigned char* i = (unsigned char*)Func; ; i += 4)
		if (RelatedReturn(i))
		{
			uintptr_t size = (((uintptr_t)i - (uintptr_t)Func)) + 4;
			size += 4;
				
			return size;
		}

	return 0;
}

bool ProcessManager::LoadToMemoryAndHook(uintptr_t targetSrc, void* targetDst, uintptr_t targetLen)
{
    #ifdef DEBUG
    printf("ProcessManager::LoadToMemoryAndHook(%08X, %08X, %08X)\n", targetSrc, (uintptr_t)targetDst, targetLen);
    #endif
    uintptr_t DstAddrinTargetMemory;
    uintptr_t localDstSize = 1024;
    
     #ifdef __arm__
        if(targetLen < 8)
            return false;

        localDstSize = GetFuncSizeArm(targetDst);
        if(!localDstSize)
            return false;

        DstAddrinTargetMemory = FindCodeCave(localDstSize, EXECUTE_READ);
        if(!DstAddrinTargetMemory)
            return false;

    #elif defined(__i386__)
        if(targetLen < 5)
            return false;


    #endif

    memcpy((unsigned char*)targetDst, DstAddrinTargetMemory, localDstSize);
    return Hook(targetSrc, DstAddrinTargetMemory);

}