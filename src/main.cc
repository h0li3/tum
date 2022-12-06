#include <stdio.h>
#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"
#include "memory/memory_map.h"

BX_MEM_C bx_mem;
BX_CPU_C bx_cpu;

/*

内存部分关键文件：
cpu/paging.cc 分页文件
cpu/access2.cc 指令访问线性地址时，会先通过 translate_linear_long_mode 翻译为物理地址，再访问物理地址
memory/memory-bochs.h 物理内存访问相关定义的头文件
memory/memory_map.cc  虚拟内存管理链表
memory/memory.cc      物理内存读写函数，也将负责内存页映射

*/

/*
Bochs完整地模拟了一台x86计算机，很多功能我们都用不到，包括正常CPU功能比如中断表、任务门等，可以直接去掉

介绍：
BX_MEM_C 是内存分配管理类，负责为模拟器分配物理内存并映射到CR3寄存器指向的页表中
映射物理进程的虚拟内存：
	定义一个链表（暂时）memory_map，通过VirtualQuery查询当前进程的虚拟内存布局并加入到链表中，memory_map负责管理模拟器中的内存布局，由于模拟器开始执行时，物理进程中不会再有线程执行，所有对物理进程的内存映射只需要进行一次。

为模拟器分配内存：
	1. 物理内存使用VirtualAllocate分配，内存属性统一为RW
	2. 模拟器页表项中可以指定的flag有：
		P(Present 存在)
		M(Mapped 从物理内存映射)
		X(eXecutable 可执行)
		W(Writable 可写入)
		V(Valid 有效，V == 0 && P == 1表示内存页需要从物理进程中拷贝到虚拟内存)
		E(Encrypted 内存经过简单加密，读写时检查到这个标志开启则要加解密内存)
	3. 由于内存使用一般比较小，暂时不考虑动态释放页表
	4. M 和 E冲突，为内存页设置E时必须将M内存页拷贝到新页面并加密，原页面不再使用

通过系统调用映射文件为虚拟内存：
	syscall指令 挂钩 ZwMapViewOfSection，由内存管理器映射完成后再将物理内存映射到模拟器的页表中，从而实现在模拟器中加载DLL、加载EXE

通过系统调用申请内存：
	syscall指令 挂钩 ZwAllocateVirtualMemory，由内存管理器分配内存后映射到模拟器页表中

BX_CPU_C 是cpu模拟类，当前阶段模拟器采用物理单线程->模拟器多线程
模拟多线程思路：
	为模拟器多线程建立队列，每个线程拥有固定的时间片，执行完放到队列末尾重新排队获取时间片
	时间片为在cpu设置计数器icounter，每执行一条指令icounter -= 1，当icounter == 0时表示线程时间片使用完毕，重新回到等待队列

模拟定时器思路：
	暂时没有想到方法，可以创建一个计时器线程，时间到时通过信号通知当前线程

模拟器创建线程：
	syscall指令 挂钩 ZwCreateThread，由任务管理器创建虚拟线程结构，并插入等待执行队列

模拟器创建线程：
	不需要

模拟器调用WaitForSingleObject等阻塞API：
	暂时没有方案

模拟器使用完成端口等IO阻塞API：
	暂时没有方案

*/

int main(int argc, char** argv)
{
	bx_cpu.initialize(); // 开启长模式，设置64位模式
	bx_cpu.gen_reg[BX_64BIT_REG_RIP].rrx = 0x8000;

    bx_mem.init_memory(0, 1024 * 1024 * 64, 4096);	// 早期开发测试用，分配64MB大块物理内存

	bx_cpu.cr0.set_PG(1);	// 开启分页模式后，所有内存访问会先经过MMU将线性地址翻译为物理地址，如果访问的4k页面不存在，就会产生#PF(page fault)异常，内存管理器负责判断这个4k页面是否是已经分配的内存，并进行页面分配或者结束执行报告内存错误
	// 测试时不开启分页模式，我们还没有设置#PG异常的处理中断

	auto* ib = (Bit8u*)bx_cpu.getHostMemAddr(0x8000, 1);	// 直接获取模拟器的0x1000地址对应的物理内存地址

	unsigned char instdata[] = {
		0xb9, 0x22, 0x33, 0x00, 0x00, // mov ecx, 0x3322
		0x89, 0x0c, 0x25, 0x00, 0x40, 0x00, 0x00, // mov [0x4000], ecx
		0x48, 0x8b, 0x04, 0x25, 0x00, 0x40, 0x00, 0x00 // mov rax, [0x4000]
	};
	memcpy(ib, instdata, sizeof(instdata));	// 写入测试的机器码

	// 如果我们完成内存分配部分，这里就已经可以跑简单的代码了
	for (int n = 0; n < 3; ++n) {
		auto* cache = bx_cpu.getICacheEntry();	// 获取指令缓存
		auto* i = cache->i;
		bx_cpu.gen_reg[BX_64BIT_REG_RIP].rrx += i->ilen();	// 修改PC
  		BX_CPU_CALL_METHOD(i->execute1, (i));	// 执行指令
		// RAX应该等于0x3322
		printf("rax = %lx\n", bx_cpu.gen_reg[BX_64BIT_REG_RAX].rrx);
	}

	tum::MemoryMap memmap;
	memmap.insert_memory_area(new tum::memory_area_t {0x2471000, 2, 1});
	auto* area = memmap.find_memory_area(0x2471000 + 4096);
	if (area)
		printf("base = 0x%lx, size = 0x%lx\n", area->base, area->get_size());
}

int bx_atexit()
{
	printf("[*] bx_atexit() called.\n");
	return 0;
}
