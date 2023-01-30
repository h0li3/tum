#pragma once
#include "bochs.h"
#include "cpu/cpu.h"


class InterruptHandlers
{
public:
	static void PageFaultHandler(BX_CPU_C* cpu);

	static bx_address handlers[32];
};
