# Emulator-Android-External-Memory-Hacking
android process/memory library root

Library Features:

* LoadToMemoryAndHook (will a passed function(should be simple function or shellcode))
* Hook
* DisablePtrace
* GetFuncSizeArm
* FindCodeCave
* EnumSegments
* FindExternalSymbol (parse the elf header and find for symbols)
* memcpyBackwrd (target to local)
* memcpy (local to target)
* GetFullModulePath
* GetLocalModBaseAddr
* GetModBaseAddr
* WriteProcessMemory
* ReadProcessMemory
* FindDMAddy
* FindPid

how to build:

* clone this repo
* explore src in command line.
* run ndk-build

inplementation: https://www.youtube.com/watch?v=O4B3t2-67jc&t=7s
