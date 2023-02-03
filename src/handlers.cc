#include "handlers.h"
#include "memory/memory-bochs.h"

void InterruptHandlers::init_cpu(BX_CPU_C* cpu)
{
	cpu->idtr.limit = MAX_HANDLERS * sizeof(void*);
	cpu->idtr.base = (bx_address)InterruptHandlers::handlers;
}

void InterruptHandlers::undefined_handler(BX_CPU_C* cpu)
{
#if BX_GDBSTUB
	puts("#UD");
	bx_dbg.exceptions = true;
#else
	BX_FATAL(("#UD"));
#endif
}

void InterruptHandlers::page_fault_handler(BX_CPU_C* cpu)
{
	bx_address laddr = cpu->cr2;
	if (!bx_mem.query_host_memory(laddr)) {
		//printf("#PF: the requested page @%p dose not exist in the host process\n", (void*)laddr);
		exit(-1);
	}
	else {
		cpu->map_physical_page(laddr, 1);
		//printf("Virtual page @%p resolved!\n", (void*)laddr);
	}
}

void InterruptHandlers::general_purpose_handler(BX_CPU_C* cpu)
{
	BX_PANIC(("#GP"));
}

bx_address InterruptHandlers::handlers[32] =
{
	0,  // DE
	0,  // DB
	0,
	0,  // BP
	0,  // OF
	0,  // BR
	(bx_address)undefined_handler,  // UD
	0,  // NM
	0,  // DF
	0,
	0,  // TS
	0,  // NP
	0,  // SS
	(bx_address)general_purpose_handler,
	(bx_address)page_fault_handler,
	0,
	0,  // MF
	0,  // AC
	0,  // XM
	0,  // VE
	0,  // CP
};
