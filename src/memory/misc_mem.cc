#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"
#include <Windows.h>

Bit8u* BX_MEM_C::get_host_address(BX_CPU_C *cpu, bx_phy_address addr, unsigned rw)
{
    return (Bit8u*)addr;
}

bx_address BX_MEM_C::allocate_host_memory(bx_address addr, unsigned len, unsigned rw)
{
	bx_address mem;
#ifdef _WIN32
    DWORD prot = (rw & 1) ? PAGE_READWRITE : PAGE_READONLY;
    mem = (bx_address)VirtualAlloc((void*)addr, len, MEM_COMMIT, prot);
#else
    int prot = PROT_READ;
    if (rw & 1) {
        prot |= PROT_WRITE;
    }
    mem = (bx_address)mmap((void*)addr, 4096, prot, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem == -1)
        mem = 0;
#endif
    return mem;
}

void BX_MEM_C::free_host_memory(bx_address addr, unsigned len)
{
#ifdef _WIN32
    VirtualFree((void*)addr, len, MEM_COMMIT);
#else
    munmap((void*)addr, len);
#endif
}

bool BX_MEM_C::query_host_memory(bx_address addr)
{
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery((void*)addr, &info, sizeof(info))) {
        if (info.State == MEM_COMMIT) {
            return true;
        }
    }
    return false;
}

