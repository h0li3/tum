#pragma once
#include "bochs.h"
#include "cpu/cpu.h"


class InterruptHandlers
{
	static constexpr int MAX_HANDLERS = 32;

public:
	static void init_cpu(BX_CPU_C* cpu);

private:
	static void undefined_handler(BX_CPU_C* cpu);
	static void page_fault_handler(BX_CPU_C* cpu);
	static void general_purpose_handler(BX_CPU_C* cpu);

	static bx_address handlers[MAX_HANDLERS];
};
