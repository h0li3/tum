#include <stdio.h>
#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"
#include "softmmu/softmmu.h"

tum::SoftMMU softmmu;

BX_MEM_C bx_mem;
BX_CPU_C bx_cpu;

int main(int argc, char** argv)
{
    int mem = 32;
    softmmu.map_host_memory((uint64_t)&mem, sizeof(mem));

    auto* page = softmmu.allocate_page(0, 4096, true);
    printf("[+] page base is %p\n", (void*)page->get_laddr());
    uint64_t addr = softmmu.translate_linear_addr(page->get_laddr(), false);
    printf("[+] physical address = %p\n", (void*)addr);

    bx_mem.init_memory(0, 4096000, 4096);
	bx_cpu.initialize();
	bx_cpu.cpu_mode = 4;
	bx_cpu.gen_reg[BX_64BIT_REG_RIP].rrx = 0x1000;
	auto* ib = (Bit8u*)bx_cpu.getHostMemAddr(0x1000, 1);
	printf("host mem addr is %p\n", ib);
	unsigned char insb[] = { 0x48, 0x8b, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44 };
	memcpy(ib, insb, sizeof(insb));
	auto* cache = bx_cpu.getICacheEntry();
	auto* i = cache->i;
    printf("tlen = %d\n", cache->tlen);
	printf("ilen = %d\n", i->ilen());
	printf("%x\n", i->getIaOpcode());
  	BX_CPU_CALL_METHOD(i->execute1, (i));
	printf("rax = %llx\n", bx_cpu.gen_reg[BX_64BIT_REG_RAX].rrx);
}

int bx_atexit()
{
	return 0;
}
