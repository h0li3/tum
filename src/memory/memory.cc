#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"
#ifndef _WIN32
#include <sys/mman.h>
#endif

#define LOG_THIS BX_MEM_THIS

BX_MEM_C::BX_MEM_C()
	: page_table_base(0)
{
}

BX_MEM_C::~BX_MEM_C()
{
	cleanup_memory();
}

bx_address BX_MEM_C::get_page_table() const
{
    return page_table_base;
}

void BX_MEM_C::init_memory()
{
    // Allocate PML4 memory page.
    page_table_base = allocate_physical_page(0, 1);
}

const Bit64u BX_PAGING_MASK = BX_CONST64(0xfffffffffffff000);

void BX_MEM_C::cleanup_memory()
{
    bx_phy_address table = page_table_base & BX_PAGING_MASK;

	bx_address* px = reinterpret_cast<bx_address*>(table);
	for (int i = 0; i < 512; ++i) {
		if (px[i] & 1) {
			bx_address* pd = reinterpret_cast<bx_address*>(px[i] & BX_PAGING_MASK);
			for (int i = 0; i < 512; ++i) {
				if (pd[i] & 1) {
					bx_address* pt = reinterpret_cast<bx_address*>(pd[i] & BX_PAGING_MASK);
					for (int i = 0; i < 512; ++i) {
						if (pt[i] & 1) {
							free_physical_page(pt[i] & BX_PAGING_MASK);
						}
					}
				}
			}
		}
	}
}

bx_address BX_MEM_C::allocate_stack(Bit32u len)
{
	return allocate_host_memory(0, len, 1);
}

void BX_MEM_C::free_stack(bx_address addr, Bit32u len)
{
	free_host_memory(addr, len);
}

void BX_MEM_C::write_physical_page(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, void *data)
{
	memcpy((void*)addr, data, len);
}

void BX_MEM_C::read_physical_page(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, void *data)
{
    memcpy(data, (void*)addr, len);
}

bx_address BX_MEM_C::allocate_physical_page(bx_address addr, unsigned rw)
{
	return allocate_physical_pages(addr, 1, rw);
}

bx_address BX_MEM_C::allocate_physical_pages(bx_address addr, Bit32u npages, unsigned rw)
{
	return allocate_host_memory(addr, npages * 4096, rw);
}

void BX_MEM_C::free_physical_page(bx_address addr)
{
	free_physical_pages(addr, 1);
}

void BX_MEM_C::free_physical_pages(bx_address addr, Bit32u npages)
{
	free_host_memory(addr, npages * 4096);
}

bool BX_MEM_C::dbg_fetch_mem(BX_CPU_C* cpu, bx_phy_address addr, unsigned len, Bit8u* buf)
{
	return false;
}