#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"
#define LOG_THIS BX_MEM_THIS

void BX_MEM_C::writePhysicalPage(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, void *data)
{
}

void BX_MEM_C::readPhysicalPage(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, void *data)
{
}
