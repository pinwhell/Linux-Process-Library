#include "ProcessManager.h"

int main()
{
    ProcessManager p("com.madfingergames.deadtrigger2");
    
    uintptr_t libil2cppAddr = p.GetModBaseAddr("libil2cpp.so");
    uintptr_t entityListAddr = p.FindDMAddy(libil2cppAddr + 0x1978C60, {0x5C, 0x0, 0x3C, 0x14, 0x8, 0x0});

    int entityListMaxItem = p.ReadProcessMemory<int>(entityListAddr + 0xC);
    printf("Entity List Max items ==> [%d]\n", entityListMaxItem);

    for(int i = 0; i < entityListMaxItem; i++)
    {
        uintptr_t currEntity = p.ReadProcessMemory<uintptr_t>(entityListAddr + i * 4 + 0x10); // curr index
        if(!currEntity)
            continue;

        printf("Entity at index %d ===> [%08X]\n", i, currEntity);
    }

    return 0;
}
