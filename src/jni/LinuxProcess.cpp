#include "LinuxProcess.h"
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

const char* pattern_scan(const char* pattern, const char* mask, const char* data, size_t data_len) {
    size_t mask_len = strlen(mask) - 1; // Subtract 1 to exclude the null terminator

    for (size_t i = 0; i <= data_len - mask_len; i++) {
        int match = 1;
        for (size_t j = 0; j < mask_len; j++) {
            if (mask[j] == '?') {
                continue;
            }
            if (data[i + j] != pattern[j]) {
                match = 0;
                break;
            }
        }
        if (match) {
            return &data[i]; // Return the address where the pattern is found
        }
    }

    return nullptr; // Pattern not found
}

#define GetBit(buff, pos) (((buff) & (0x1 << (pos)))) ? true : false

/**
 * @brief definig DEBUG will cause, all the function logging its call.
 * 
 */
#define DEBUG

#define ZeroMemory(dst, size) memset((void*)(dst), 0x0, (size))

int LinuxProcess::FindPid(const char* procName){
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

LinuxProcess::LinuxProcess(const char* procName)
{
    #ifdef DEBUG
        printf("LinuxProcess(%s)\n",procName);
    #endif

    char ProcessMemoryPath[128];
    char ProcessMapsPath[128];

    if((pid = FindPid(procName)) == -1)
        throw("LinuxProcess : Could not found the process");

    sprintf(ProcessMemoryPath, "/proc/%d/mem", pid);
    memfd = open(ProcessMemoryPath, O_RDWR);

    if(memfd < -1)
        throw("LinuxProcess : Could not open the process memory");

    sprintf(ProcessMapsPath, "/proc/%d/maps", pid);
    mapsfd = open(ProcessMapsPath, O_RDONLY);

    if(mapsfd < -1)
        throw("LinuxProcess : Could not open the process maps");
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

uintptr_t LinuxProcess::GetModBaseAddr(const char* modName)
{
    #ifdef DEBUG
    printf("LinuxProcess::GetModBaseAddr(%s)\n",modName);
    #endif

    SegmentInfo tSegment;

    if(!GetLineSegmentFromName(mapsfd, modName, tSegment))
        return 0;

    return tSegment.start;
}

uintptr_t LinuxProcess::FindDMAddy(uintptr_t base, std::vector<uintptr_t> offsets)
{
    uintptr_t result = base;

    for(int i = 0; i < offsets.size(); i++)
    {
        result = ReadMemoryWrapper<uintptr_t>(result);
        result += offsets[i];
    }

    return result;
}

uintptr_t LinuxProcess::GetLocalModBaseAddr(const char* modName)
{
    #ifdef DEBUG
    printf("LinuxProcess::GetLocalModBaseAdd(%s)\n",modName);
    #endif

    int localMapsfd = open("/proc/self/maps", O_RDONLY);

    if(localMapsfd < 0)
        return 0;

    SegmentInfo tSegment;
    ZeroMemory(&tSegment, sizeof(tSegment));

    if(GetLineSegmentFromName(localMapsfd, modName, tSegment) == false)
    {
        close(localMapsfd);
        return 0;
    }

    close(localMapsfd);

    return tSegment.start;
}

bool LinuxProcess::GetFullModulePath(const char* modName, std::string & result)
{
    #ifdef DEBUG
    printf("LinuxProcess::GetFullModulePath(%s)\n",modName);
    #endif

    SegmentInfo tSegment;

    if(!GetLineSegmentFromName(mapsfd, modName, tSegment))
        return 0;

    result = tSegment.name;

    return true;
}

bool LinuxProcess::FindExternalSymbol(const char* modName, const char* symbolName, uint64_t* outResult)
{
    #ifdef DEBUG
    printf("LinuxProcess::FindExternalSymbol(%s, %s)\n",modName, symbolName);
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

bool LinuxProcess::WriteMemory(const void* source, uintptr_t destination, int size)
{
    if(lseek64(memfd, destination, SEEK_SET) < 0)
        return false;

    write(memfd, source, size);

    return  true;
}

bool LinuxProcess::ReadMemory(uintptr_t source, void* destination, int size)
{
    if(lseek64(memfd, source, SEEK_SET) < 0)
        return false;

    read(memfd, destination, size);

    return true;
}

bool LinuxProcess::EnumSegments(std::vector<SegmentInfo> & segments, int protection)
{
    #ifdef DEBUG
    printf("LinuxProcess::EnumSegments(&)\n");
    #endif

    char protectionBuff[] = "---p";

    if(protection & PROT_READ)
        protectionBuff[0] = 'r';

    if(protection & PROT_WRITE)
        protectionBuff[1] = 'w';

    if(protection & PROT_EXEC)
        protectionBuff[2] = 'x';

    if(ForEachLine(mapsfd, [&](const std::string currLine){
        if(strstr(currLine.c_str(), protectionBuff) == nullptr)
            return true;

        segments.push_back({});

        SegmentInfo& segmentInfo = segments[segments.size() - 1];

        ParseMapLineSegment(currLine.c_str(), segmentInfo);

        return true;
    }) == false)
        return false;

    return true;
}

// void LinuxProcess::DisablePtrace()
// {
//     #ifdef DEBUG
//     printf("LinuxProcess::DisablePtrace()\n");
//     #endif
//     uintptr_t ptraceAddr = FindExternalSymbol("libc.so", "ptrace");

//     while(!ptraceAddr){
//         printf("LinuxProcess : ptrace not found\n");
//         ptraceAddr = FindExternalSymbol("libc.so", "ptrace");
//     };

//     unsigned char buff[] = "\x00\x00\xA0\xE3\x1E\xFF\x2F\xE1"; // mov r0, 0
//                                                                // bx lr
//     WriteMemory(buff, ptraceAddr, sizeof(buff));
// }

uintptr_t LinuxProcess::FindCodeCave(uintptr_t size, uintptr_t prot)
{
    #ifdef DEBUG
    printf("LinuxProcess::FindCodeCave(%08X, %d)\n", size, prot);
    #endif

    int exp = 1;
    void* tmpBuff = malloc(exp * exp);

    if(tmpBuff == nullptr)
        return 0;

    std::vector<SegmentInfo> segments;

    if(!EnumSegments(segments, prot))
    {
        free(tmpBuff);
        return 0;
    }
    
    size = ((size / 4) + 1) * 4; // Aligning the size

    std::vector<unsigned char> pattern;
    std::string mask = "";

    for(int i = 0; i < size; i++)
    {
        pattern.push_back(0x0);
        mask.push_back('x');
    }

    uintptr_t result = 0;

    for(int i = 0; i < segments.size(); i++)
    {
        while(exp * exp < segments[i].size)
        {
            free(tmpBuff);
            exp++; tmpBuff = malloc(exp * exp);

            if(tmpBuff == nullptr)
                return 0;
        }
        // At this point we have enought memory to store the entire current segment

        if(ReadMemory(segments[i].start, tmpBuff, segments[i].size) == false)
            continue;

        // We sucessfully Readed the current segment
        const char* codeCave = pattern_scan((const char*) pattern.data(), mask.c_str(), (const char*)tmpBuff, segments[i].size );
        
        if(codeCave == nullptr)
            continue;

        // At this point, we have found a codecaves
        // Lets calculate its position in the remote area

        size_t offset = (uintptr_t)codeCave - (uintptr_t)tmpBuff;

        result = segments[i].start + offset;
        break;       
    }

    free(tmpBuff);

    return ((result / 4) + 1) * 4;
}

bool LinuxProcess::Hook(uintptr_t src, uintptr_t dst, uintptr_t size)
{
    #ifdef DEBUG
    printf("LinuxProcess::Hook(%08X, %08X, %08X)\n", src, dst, size);
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

    WriteMemory(detourPtr, src, tSize);

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

bool LinuxProcess::LoadToMemoryAndHook(uintptr_t targetSrc, void* targetDst, uintptr_t targetLen)
{
    #ifdef DEBUG
    printf("LinuxProcess::LoadToMemoryAndHook(%08X, %08X, %08X)\n", targetSrc, (uintptr_t)targetDst, targetLen);
    #endif
    uintptr_t DstAddrinTargetMemory;
    uintptr_t localDstSize = 1024;
    
     #ifdef __arm__
        if(targetLen < 8)
            return false;

        localDstSize = GetFuncSizeArm(targetDst);
        if(!localDstSize)
            return false;

        DstAddrinTargetMemory = FindCodeCave(localDstSize, PROT_READ);
        if(!DstAddrinTargetMemory)
            return false;

    #elif defined(__i386__)
        if(targetLen < 5)
            return false;


    #endif

    WriteMemory((unsigned char*)targetDst, DstAddrinTargetMemory, localDstSize);
    return Hook(targetSrc, DstAddrinTargetMemory);

}