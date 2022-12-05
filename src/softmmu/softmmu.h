#ifndef MU_PG_H_
#define MU_PG_H_

#include <stdint.h>
#include <stddef.h>

namespace tum
{

using address_t = size_t;

constexpr size_t TUM_PAGE_SIZE = 4096;

#define READ_LADDR(addr, pml4e, pdpe, pde, pte, phy)\
	(pml4e) = (uint16_t)((addr) >> 39) & 0x1FF;\
	(pdpe) = (uint16_t)((addr) >> 30) & 0x1FF;\
	(pde) = (uint16_t)((addr) >> 21) & 0x1FF;\
	(pte) = (uint16_t)((addr) >> 12) & 0x1FF;\
	(phy) = (uint16_t)((addr) & 0xFFF)

#define MU_LADDR(addr) ((address_t)(addr) << 12)
#define MU_RADDR(addr) ((address_t)(addr) >> 12)

union PageEntry
{
	address_t data;
	struct
	{
		address_t P : 1;
		address_t V : 1;
		address_t RW : 1;
		address_t MP : 1;
		address_t RE : 8;
		address_t A : 52;
	};

	inline address_t get_laddr()
	{
		return A << 12;
	}

	inline address_t set_laddr(address_t addr)
	{
		A = addr >> 12;
		return addr;
	}
};

class PageTable
{
	static constexpr uint32_t MMU_NUMBER_OF_TABLE_ENTRIES = TUM_PAGE_SIZE / 8;

public:
	inline PageEntry* get_entry(uint16_t index)
	{
		return &table[index];
	}

	inline PageTable* get_table(uint16_t index)
	{
		return (PageTable*)table[index].get_laddr();
	}

    inline address_t get_base(uint16_t index)
    {
        auto* e = &table[index];
        if (e->P) {
            return MU_LADDR(e->A);
        }
        return 0;
    }

	PageTable* allocate_table(uint16_t index);

private:
	PageEntry table[MMU_NUMBER_OF_TABLE_ENTRIES];
};

class SoftMMU
{
public:
	static constexpr uint32_t MAX_PAGES = 1024 * 1024;

	SoftMMU()
	: map_{}
	{
	}

    void* allocate_physical_page(uint32_t npages);
    void  release_physical_page(address_t base, uint32_t npages);
	PageEntry* allocate_page(address_t addr, address_t size, bool writable);
	address_t translate_linear_addr(address_t laddr, bool write_check);
    void map_host_memory(address_t phy_addr, address_t size);

private:
	PageTable map_;
};

}

extern tum::SoftMMU softmmu;

#endif // MU_PG_H_
