#include <stdio.h>
#include "softmmu.h"

tum::SoftMMU softmmu;

int main()
{
    int mem = 32;
	softmmu.map_host_memory((uint64_t)&mem, sizeof(mem));

	auto* page = softmmu.allocate_page(0, 4096, true);
	printf("[+] page base is %p\n", (void*)page->get_laddr());
	uint64_t addr = softmmu.translate_linear_addr(page->get_laddr(), false);
	printf("[+] physical address = %p\n", (void*)addr);
}
