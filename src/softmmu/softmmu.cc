#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "softmmu.h"

namespace tum
{

PageTable* PageTable::allocate_table(uint16_t index)
{
	auto* entry = get_entry(index);
	if (entry->P == 0)
	{
		return (PageTable*)entry->set_laddr((address_t)softmmu.allocate_physical_page(1));
		entry->P = 1;
	}
	return (PageTable*)entry->get_laddr();
}

void* SoftMMU::allocate_physical_page(uint32_t npages)
{
	if (npages > MAX_PAGES) {
		return nullptr;
	}
	auto prot = PROT_READ | PROT_WRITE;
	auto flags = MAP_PRIVATE | MAP_ANONYMOUS;
	void* addr = mmap(0, npages * TUM_PAGE_SIZE, prot, flags, -1, 0);
	if (!addr) {
		printf("ERROR - Failed to allocate memory page");
		// THROW("ERROR - Failed to allocate memory page");
	}
	return addr;
}

void SoftMMU::release_physical_page(address_t base, uint32_t npages)
{
	if (!base || npages == 0 || npages > MAX_PAGES)
		return;
	munmap((void*)base, npages * TUM_PAGE_SIZE);
}

address_t SoftMMU::translate_linear_addr(address_t laddr, bool write_check)
{
	uint16_t pml4e_index,
			 pdpe_index,
			 pde_index,
			 pte_index,
			 page_offset;
	READ_LADDR(laddr, pml4e_index, pdpe_index, pde_index, pte_index, page_offset);

	auto* pdp = map_.get_table(pml4e_index);
	if (pdp) {
		auto* pd = pdp->get_table(pdpe_index);
		if (pd) {
			auto* pt = pd->get_table(pde_index);
			if (pt) {
				auto* entry = pt->get_entry(pte_index);
				if (entry->V && entry->P) {
					auto page = pt->get_base(pte_index);
					return page + page_offset;
				}
			}
		}
	}

	// page_fault();
	return 0;
}

PageEntry* SoftMMU::allocate_page(address_t addr, address_t size, bool writable)
{
	uint16_t pml4e_index,
			 pdpe_index,
			 pde_index,
			 pte_index,
			 phy_offset;
	bool need_allocate;

	if (addr == 0) {
		addr = (address_t)allocate_physical_page(1);
		need_allocate = true;
	}

	READ_LADDR(addr, pml4e_index, pdpe_index, pde_index, pte_index, phy_offset);

	// Get entry of PML4 (PML4E) (Page Map Level 4)
	auto* pdp = map_.allocate_table(pml4e_index);
	// Get entry of PDP (PDPE) (Page Directory Pointer)
	auto* pd = pdp->allocate_table(pdpe_index);
	// Get entry (PDE) of PD (Page Directory)
	auto* pt = pd->allocate_table(pde_index);
	// Get entry (PTE) of PT (Page Table)
	auto* page_entry = pt->get_entry(pte_index);
	page_entry->V = 1;
	page_entry->RW = writable;
	return page_entry;
}

void SoftMMU::map_host_memory(address_t phy_addr, address_t size)
{
	uint16_t pml4e_index,
			 pdpe_index,
			 pde_index,
			 pte_index,
			 phy_offset;
	READ_LADDR(phy_addr, pml4e_index, pdpe_index, pde_index, pte_index, phy_offset);
	auto base = phy_addr & ~4095;

	if (size < 4096) {
		size = 4096;
	}
	auto t = size & 4095;
	size &= ~4095;
	if (t) {
		size += 4096;
	}

	auto pages = (size >> 12) & 0x1FF;
	auto pts   = (size >> 21) & 0x1FF;
}

}
