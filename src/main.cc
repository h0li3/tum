#include <stdio.h>
#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"

BX_MEM_C bx_mem;
BX_CPU_C bx_cpu;

/*

�ڴ沿�ֹؼ��ļ���
cpu/paging.cc ��ҳ�ļ�
cpu/access2.cc ָ��������Ե�ַʱ������ͨ�� translate_linear_long_mode ����Ϊ�����ַ���ٷ��������ַ
memory/memory-bochs.h �����ڴ������ض����ͷ�ļ�
memory/memory_map.cc  �����ڴ��������
memory/memory.cc      �����ڴ��д������Ҳ�������ڴ�ҳӳ��

*/

/*
Bochs������ģ����һ̨x86��������ܶ๦�����Ƕ��ò�������������CPU���ܱ����жϱ������ŵȣ�����ֱ��ȥ��

���ܣ�
BX_MEM_C ���ڴ��������࣬����Ϊģ�������������ڴ沢ӳ�䵽CR3�Ĵ���ָ���ҳ����
ӳ��������̵������ڴ棺
	����һ��������ʱ��memory_map��ͨ��VirtualQuery��ѯ��ǰ���̵������ڴ沼�ֲ����뵽�����У�memory_map�������ģ�����е��ڴ沼�֣�����ģ������ʼִ��ʱ����������в��������߳�ִ�У����ж�������̵��ڴ�ӳ��ֻ��Ҫ����һ�Ρ�

Ϊģ���������ڴ棺
	1. �����ڴ�ʹ��VirtualAllocate���䣬�ڴ�����ͳһΪRW
	2. ģ����ҳ�����п���ָ����flag�У�
		P(Present ����)
		M(Mapped �������ڴ�ӳ��)
		X(eXecutable ��ִ��)
		W(Writable ��д��)
		V(Valid ��Ч��V == 0 && P == 1��ʾ�ڴ�ҳ��Ҫ����������п����������ڴ�)
		E(Encrypted �ڴ澭���򵥼��ܣ���дʱ��鵽�����־������Ҫ�ӽ����ڴ�)
	3. �����ڴ�ʹ��һ��Ƚ�С����ʱ�����Ƕ�̬�ͷ�ҳ��
	4. M �� E��ͻ��Ϊ�ڴ�ҳ����Eʱ���뽫M�ڴ�ҳ��������ҳ�沢���ܣ�ԭҳ�治��ʹ��

ͨ��ϵͳ����ӳ���ļ�Ϊ�����ڴ棺
	syscallָ�� �ҹ� ZwMapViewOfSection�����ڴ������ӳ����ɺ��ٽ������ڴ�ӳ�䵽ģ������ҳ���У��Ӷ�ʵ����ģ�����м���DLL������EXE

ͨ��ϵͳ���������ڴ棺
	syscallָ�� �ҹ� ZwAllocateVirtualMemory�����ڴ�����������ڴ��ӳ�䵽ģ����ҳ����

BX_CPU_C ��cpuģ���࣬��ǰ�׶�ģ����Ϊÿ��ģ���̷߳���һ����ʵ�̣߳��൱��ÿ��ģ���̶߳�ӵ���Լ���cpu�����ġ�TEB����ʵ�߳��еĶ�������������ʵ�ֶ�ͼ����ϵͳ�ķ���
ģ����߳�˼·��
	�ҹ�ZwCreateThread(Ex)������Ҫ�����߳�ʱ������һ��ģ��cpu�����ģ�������ʵ�߳�Ȼ��ʼģ��ִ�ж�ӦIP

*/

void PageFaultHandler()
{
	bx_address laddr = bx_cpu.cr2;
	if (!bx_mem.query_host_memory(laddr)) {
		printf("#PF: the requested page @%p dose not exist in the host process\n", (void*)laddr);
		exit(-1);
	}
	else {
		bx_cpu.map_physical_page(laddr, 1);
		printf("Virtual page @%p resolved!\n", (void*)laddr);
	}
}

int main(int argc, char** argv)
{
	bx_cpu.initialize(); // ������ģʽ
	bx_cpu.cr0.set_PG(1); // ������ҳģʽ�������ڴ���ʻ��Ⱦ���MMU�����Ե�ַ����Ϊ�����ַ��������ʵ�4kҳ�治���ڣ��ͻ����#PF(page fault)�쳣���ڴ�����������ж����4kҳ���Ƿ����Ѿ�������ڴ棬������ҳ�������߽���ִ�б����ڴ����
	bx_cpu.idtr.limit = 16 * 8;
	auto* handlers = new bx_address [16]{};
	handlers[BX_PF_EXCEPTION] = (bx_address)PageFaultHandler;
	bx_cpu.idtr.base = (bx_address)handlers;
    bx_mem.init_memory(&bx_cpu);

	auto* ib = (Bit8u*)bx_mem.allocate_physical_page(0, 1);
	bx_cpu.gen_reg[BX_64BIT_REG_RIP].rrx = (Bit64u)ib;

	unsigned char instdata[] = {
		0x48, 0x8b, 0x0d, 0x00, 0x00, 0x00, 0x00, // mov rcx, [rip]
		0x89, 0x0c, 0x25, 0x00, 0x40, 0x00, 0x00, // mov [0x4000], rcx
		0x48, 0x8b, 0x04, 0x25, 0x00, 0x40, 0x00, 0x00, // mov rax, [0x4000]
		0xf4, // hlt
	};
	memcpy(ib, instdata, sizeof(instdata));	// д����ԵĻ�����

	printf("Startup address is %p\n", (void*)ib);
	printf("shellcode is:\n  mov rcx, [rip]\n  mov [0x4000], rcx\n  mov rax, [0x4000]\n  hlt\n");
	// �����������ڴ���䲿�֣�������Ѿ������ܼ򵥵Ĵ�����
	bx_cpu.cpu_loop();
}

int bx_atexit()
{
	printf("[*] bx_atexit() called.\n");
	return 0;
}
