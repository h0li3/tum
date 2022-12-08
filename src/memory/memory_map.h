#ifndef TUM_MEMORY_MAP_H
#define TUM_MEMORY_MAP_H

#include <stdint.h>

namespace tum
{

using address_t = uint64_t;

struct memory_area_t
{
    address_t base;
    uint32_t pages;
    int protection;
    memory_area_t* next;
    memory_area_t* prev;

    uint64_t get_size()
    {
        return pages << 12;
    }

    void set_size(uint64_t size)
    {
        pages = (size >> 12) + ((size & 4095) != 0);
    }
};

class MemoryMap
{
public:
    MemoryMap();
    ~MemoryMap();
    memory_area_t* find_memory_area(address_t address);
    bool insert_memory_area(memory_area_t* area);
    bool delete_memory_area(address_t base, uint32_t pages);
    bool resize_memory_area(address_t base, uint32_t pages);
    bool protect_memory_area(address_t base, uint32_t pagese);
    bool check_conflict(address_t base, uint32_t pages);
    void clean();

private:
    memory_area_t head_;
    int num_of_areas_;
};

extern MemoryMap mem_map;

}

#endif // TUM_MEMORY_MAP_H
