#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"
#include <Windows.h>

Bit8u* BX_MEM_C::get_host_address(BX_CPU_C *cpu, bx_phy_address addr, unsigned rw)
{
    return (Bit8u*)addr;
}

bx_address BX_MEM_C::allocate_host_memory(bx_address addr, unsigned len, unsigned rw)
{
	bx_address mem;
#ifdef _WIN32
    DWORD prot = (rw & 1) ? PAGE_READWRITE : PAGE_READONLY;
    mem = (bx_address)VirtualAlloc((void*)addr, len, MEM_COMMIT, prot);
#else
    int prot = PROT_READ;
    if (rw & 1) {
        prot |= PROT_WRITE;
    }
    mem = (bx_address)mmap((void*)addr, 4096, prot, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem == -1)
        mem = 0;
#endif
    return mem;
}

void BX_MEM_C::free_host_memory(bx_address addr, unsigned len)
{
#ifdef _WIN32
    VirtualFree((void*)addr, len, MEM_COMMIT);
#else
    munmap((void*)addr, len);
#endif
}

bool BX_MEM_C::query_host_memory(bx_address addr)
{
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery((void*)addr, &info, sizeof(info))) {
        if (info.State == MEM_COMMIT) {
            return true;
        }
    }
    return false;
}

#if BX_GDBSTUB
bool BX_MEM_C::dbg_set_mem(BX_CPU_C* cpu, bx_phy_address addr, unsigned len, Bit8u* buf)
{
    __try {
        memcpy((void*)addr, buf, len);
        return true;
    }
    _except(1) {
        return false;
    }
}

bool BX_MEM_C::dbg_fetch_mem(BX_CPU_C* cpu, bx_phy_address addr, unsigned len, Bit8u* buf)
{
    _try{
		memcpy(buf, (void*)addr, len);
		return true;
    }
    _except (1) {
	    return false;
    }
}

bool BX_MEM_C::dbg_crc32(bx_phy_address addr1, bx_phy_address addr2, Bit32u* crc)
{
    *crc = 0;
    if (addr1 > addr2)
        return(0);

    unsigned len = 1 + (Bit32u)(addr2 - addr1);

    // do not cross 4K boundary
    while (1) {
        unsigned remainsInPage = 0x1000 - (addr1 & 0xfff);
        unsigned access_length = (len < remainsInPage) ? len : remainsInPage;
        //*crc = crc32((const Bit8u*)addr1, access_length);
        addr1 += access_length;
        len -= access_length;
    }

    return 1;
}
#endif
