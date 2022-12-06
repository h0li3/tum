#include "memory/memory_map.h"

namespace tum
{

MemoryMap::MemoryMap()
: head_{}, num_of_areas_(0)
{
    head_.next = &head_;
    head_.prev = &head_;
}

MemoryMap::~MemoryMap()
{
    clean();
}

void MemoryMap::clean()
{
    if (num_of_areas_ == 0)
        return;
    auto* p = head_.next;
    while (p != &head_) {
        auto* t = p;
        p = p->next;
        delete t;
    }
}

bool MemoryMap::check_conflict(address_t base, uint32_t pages)
{
    if (num_of_areas_ == 0)
        return false;
    auto* p = head_.next;
    address_t ending_addr = base + (pages << 12);
    while (p != &head_) {
        if (!(ending_addr <= p->base || base >= p->base + p->get_size())) {
            return true;
        }
    }
    return false;
}

memory_area_t* MemoryMap::find_memory_area(address_t address)
{
    if (num_of_areas_ == 0)
        return nullptr;

    auto* p = head_.next;
    while (p != &head_) {
        if (p->base <= address && p->base + p->get_size() > address) {
            return p;
        }
        p = p->next;
    }
    return nullptr;
}

bool MemoryMap::insert_memory_area(memory_area_t* area)
{
    address_t ending_addr = area->base + area->get_size();
    auto* p = head_.next;
    while (p != &head_) {
        if (ending_addr <= p->base) {
            break;
        }
        p = p->next;
    }
    p->prev->next = area;
    area->next = p;
    num_of_areas_++;
    return true;
}

}