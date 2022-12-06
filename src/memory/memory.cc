#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"
#define LOG_THIS BX_MEM_THIS

void BX_MEM_C::writePhysicalPage(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, void *data)
{
	if (addr + len > get_memory_len()) {
		BX_PANIC(("Volatile physical memory access: %p\n", (void*)addr));
	}
	memcpy(vector + addr, data, len);
}

void BX_MEM_C::readPhysicalPage(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, void *data)
{
	if (addr + len > get_memory_len()) {
		BX_PANIC(("Volatile physical memory access: %p\n", (void*)addr));
	}
    memcpy(data, vector + addr, len);
}

bx_address BX_MEM_C::allocate_page(bx_address addr, unsigned rw)
{
	BX_PANIC(("Allocate page at %p\n", (void*)addr));
}