#pragma once
#include "bochs.h"
#include "cpu/cpu.h"


class BxSystemService
{
public:

    static bx_address CallSystemService(BX_CPU_C* cpu);
    static bx_address CallSystemService64(BX_CPU_C* cpu);

private:
    static Bit32u services_[512];
    static int services_count_;
};