#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"
#include "memory/memory_map.h"
#ifndef _WIN32
#include <sys/mman.h>
#endif

#define LOG_THIS BX_MEM_THIS

void BX_MEM_C::write_physical_page(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, void *data)
{
	/*
	if (addr + len > get_memory_len()) {
		BX_PANIC(("Volatile physical memory access: %p\n", (void*)addr));
	}
	*/
	memcpy(vector + addr, data, len);
}

void BX_MEM_C::read_physical_page(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, void *data)
{
	/*
	if (addr + len > get_memory_len()) {
		BX_PANIC(("Volatile physical memory access: %p\n", (void*)addr));
	}
	*/
    memcpy(data, vector + addr, len);
}

bx_address BX_MEM_C::allocate_physical_page(bx_address addr, unsigned rw)
{
	return allocate_physical_pages(addr, 1, rw);
}

bx_address BX_MEM_C::allocate_physical_pages(bx_address addr, Bit32u npages, unsigned rw)
{
	return allocate_host_memory(addr, npages * 4096);
}

bool BX_MEM_C::dbg_fetch_mem(BX_CPU_C* cpu, bx_phy_address addr, unsigned len, Bit8u* buf)
{
	return false;
}