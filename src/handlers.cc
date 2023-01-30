#include "handlers.h"
#include "memory/memory-bochs.h"

void InterruptHandlers::PageFaultHandler(BX_CPU_C* cpu)
{
	bx_address laddr = cpu->cr2;
	if (!bx_mem.query_host_memory(laddr)) {
		printf("#PF: the requested page @%p dose not exist in the host process\n", (void*)laddr);
		exit(-1);
	}
	else {
		cpu->map_physical_page(laddr, 1);
		printf("Virtual page @%p resolved!\n", (void*)laddr);
	}
}

bx_address InterruptHandlers::handlers[32] =
{
	0,  // DE
	0,  // DB
	0,
	0,  // BP
	0,  // OF
	0,  // BR
	0,  // UD
	0,  // NM
	0,  // DF
	0,
	0,  // TS
	0,  // NP
	0,  // SS
	0,  // GP
	(bx_address)PageFaultHandler,
	0,
	0,  // MF
	0,  // AC
	0,  // XM
	0,  // VE
	0,  // CP
};
