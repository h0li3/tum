#ifndef TUM_MEMORY_MAP_H
#define TUM_MEMORY_MAP_H

#include "memory/memory-bochs.h"
#include "softmmu/softmmu.h"

namespace tum
{

struct memory_area_t
{
    memory_area_t* next;
    memory_area_t* prev;
    address_t base;
    uint32_t pages;
    int protection;
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
    bool protect_memory_area(address_t base, uint32_t pages);

private:
    memory_area_t head_;
    int num_of_areas_;
};

}

#endif // TUM_MEMORY_MAP_H
