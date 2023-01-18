#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"
#include <Windows.h>

#define LOG_THIS this->

BX_MEM_C::BX_MEM_C()
{
}

BX_MEM_C::~BX_MEM_C()
{
}

void BX_MEM_C::init_memory(BX_CPU_C *cpu)
{
    // Allocate PML4 memory page.
    cpu->cr3 = allocate_physical_page(0, 1);
    // Load all pages from physical process.
}

void BX_MEM_C::cleanup_memory(void)
{
}

Bit8u* BX_MEM_C::get_host_address(BX_CPU_C *cpu, bx_phy_address addr, unsigned rw)
{
    return (Bit8u*)addr;
}

bx_address BX_MEM_C::allocate_host_memory(bx_address addr, unsigned len)
{
	bx_address mem;
#ifdef _WIN32
    mem = (bx_address)VirtualAlloc((void*)addr, len, MEM_COMMIT, PAGE_READWRITE);
#else
    mem = (bx_address)mmap((void*)addr, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem == -1)
        mem = 0;
#endif
    return mem;
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

