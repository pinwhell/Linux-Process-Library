#include "ProcessManager.h"
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <dlfcn.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "ElfUtils.h"

const unsigned char popmask[] = "\xBD\xE8";
const unsigned char bxlrmask[] = "\x1E\xFF\x2F\xE1";
const unsigned char parammask[] = "\xCC\xCC\xCC\xCC";

#define GetBit(buff, pos) (((buff) & (0x1 << (pos)))) ? true : false

/**
 * @brief definig DEBUG will cause, all the function logging its call.
 * 
 */
#define DEBUG

#define ZeroMemory(dst, size) memset((void*)(dst), 0x0, (size))

int ProcessManager::FindPid(const char* procName){
    #ifdef DEBUG
        printf("FindPid(%s)",procName);
    #endif
    int pid = -1;
    struct dirent* pDirent;
    DIR* dir;

    if(!procName)
        return -1;

    dir = opendir("/proc/");
    
    if(!dir)
        return -1;

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

        memset(currProcName, 0, sizeof(currProcName));
        
        if(!read(currcmdLineFd, currProcName , sizeof(currProcName)))
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
        throw("ProcessManager : Could not found the process");

    sprintf(ProcessMemoryPath, "/proc/%d/mem", pid);
    memfd = open(ProcessMemoryPath, O_RDWR);

    if(memfd < -1)
        throw("ProcessManager : Could not open the process memory");

    sprintf(ProcessMapsPath, "/proc/%d/maps", pid);
    mapsfd = open(ProcessMapsPath, O_RDONLY);

    if(mapsfd < -1)
        throw("ProcessManager : Could not open the process maps");
}

bool ForEachLine(int fd, std::function<bool(const std::string& line)> callback)
{
    lseek64(fd, 0, SEEK_SET);

    FILE* currFile = fdopen(fd, "r");

    if(!currFile)
        return false;

    rewind(currFile);

    char currLine[1024];

    while(fgets(currLine, sizeof(currLine), currFile) != NULL)
    {
        if(callback(std::string(currLine)) == false)
            break;
    }

    lseek64(fd, 0, SEEK_SET);

    return true;
}

void ParseMapLineSegment(const char* lineStartSegment, SegmentInfo& buff)
{
    uintptr_t unk1;
    char tempName[256] {};
    char tempProt[256] {};

    sscanf(lineStartSegment, "%08X-%08X %s %08X %02X:%02X %d %s\n", &buff.start, &buff.end, tempProt, &unk1, &unk1, &unk1, &unk1, tempName);
    
    buff.name = std::string(tempName);
    buff.prot = std::string(tempProt);
    buff.size = buff.end - buff.start;

    return;
}

bool GetLineSegmentFromName(int fd, const char* modName, SegmentInfo & result)
{
    std::string modMapsLine = "";

    if(ForEachLine(fd, [&](const std::string& currLine){
        if(strstr(currLine.c_str(), modName) == nullptr)
            return true;

        modMapsLine = currLine;

        return false;
    }) == false)
        return false;

    if(modMapsLine.empty())
        return false;

    ParseMapLineSegment(modMapsLine.c_str(), result);

    return true;
}

uintptr_t ProcessManager::GetModBaseAddr(const char* modName)
{
    #ifdef DEBUG
    printf("ProcessManager::GetModBaseAddr(%s)\n",modName);
    #endif

    SegmentInfo tSegment;

    if(!GetLineSegmentFromName(mapsfd, modName, tSegment))
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

    GetLineSegmentFromName(localMapsfd, modName, tSegment);
    close(localMapsfd);

    return tSegment.start;
}

bool ProcessManager::GetFullModulePath(const char* modName, std::string & result)
{
    #ifdef DEBUG
    printf("ProcessManager::GetFullModulePath(%s)\n",modName);
    #endif

    SegmentInfo tSegment;

    if(!GetLineSegmentFromName(mapsfd, modName, tSegment))
        return 0;

    result = tSegment.name;

    return true;
}

bool ProcessManager::FindExternalSymbol(const char* modName, const char* symbolName, uint64_t* outResult)
{
    #ifdef DEBUG
    printf("ProcessManager::FindExternalSymbol(%s, %s)\n",modName, symbolName);
    #endif

    std::string fullModPath = "";

    if(!GetFullModulePath(modName, fullModPath))
        return false;

    bool symbolFound = false;

    bool libElfEnumRes = ElfOpen(fullModPath, [&](ElfPack libMap){
         symbolFound = ElfLookupSymbol(libMap, symbolName, outResult); 
         });

    if(symbolFound && outResult)
        (*outResult) += GetModBaseAddr(modName);
 
    return symbolFound;
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

    if(ForEachLine(mapsfd, [&](const std::string currLine){
        if(strstr(currLine.c_str(), mask) == nullptr)
            return true;

        SegmentInfo currSegment;

        ParseMapLineSegment(currLine.c_str(), currSegment);
        segments.push_back(currSegment);

        return true;
    }) == false)
        return false;

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
		if(GetBit(chunk, 7))
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