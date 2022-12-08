#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"
#include "memory/memory_map.h"

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

bx_address BX_MEM_C::allocate_page(BX_CPU_C* cpu, bx_address addr, unsigned rw)
{
	auto* area = tum::mem_map.find_memory_area(addr);
	if (!area) {
		BX_PANIC(("Access denied at %p\n", (void*)addr));
	}

	int leaf;

    Bit64u curr_entry = cpu->cr3;
	for (leaf = 3; leaf >= 0; --leaf) {
	}

	BX_PANIC(("Allocate page at %p\n", (void*)addr));
	return 0;
}
