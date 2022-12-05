#include "bochs.h"
#include "memory/memory-bochs.h"

#define LOG_THIS this->

void BX_MEM_C::init_memory(Bit64u guest, Bit64u host, Bit32u block_size)
{
    if (block_size != 4096) {
        BX_PANIC(("Block size %d is not 4096", block_size));
    }

    if (host & 4095) {
        BX_PANIC(("Host memory size %d is not power of 4095", host));
    }

    vector = new Bit8u[host];
    this->block_size = block_size;
    len = host;
    Bit32u num_blocks = len / block_size;
    blocks = new Bit8u*[num_blocks];
    for (unsigned i = 0; i < num_blocks; ++i) {
        blocks[i] = &vector[i * block_size];
    }
    bogus = &vector[host];
}

Bit8u* BX_MEM_C::getHostMemAddr(BX_CPU_C *cpu, bx_phy_address addr, unsigned rw)
{
    if ((Bit8u*)addr >= this->bogus) {
        return nullptr;
    }
    return get_vector(addr);
}

Bit8u* BX_MEM_C::get_vector(bx_phy_address addr)
{
    auto block_index = addr >> 12;
    return blocks[block_index];
}

BX_MEM_C::BX_MEM_C()
{
}

BX_MEM_C::~BX_MEM_C()
{
}

bool BX_MEM_C::dbg_fetch_mem(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, Bit8u *buf)
{
	return false;
}
