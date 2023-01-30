#include <stdio.h>
#include <Windows.h>
#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"

BX_MEM_C bx_mem;
logfunctions logger;

class BxThread
{
public:
	static constexpr Bit32u BX_STACK_LENGTH = 1024 * 64;

	BxThread();
	~BxThread();
	void enable_paging(bx_address pt_base);
	void start(bx_address code_base);

	static DWORD __stdcall thread_entry(BxThread* self);

private:
	BX_CPU_C cpu_;
	bx_address stack_;
};

int main(int argc, char** argv)
{
    bx_mem.init_memory();

	unsigned char code[] = {
		"\xb8\x2c\x00\x00\x00"			// mov eax, 0x2c	NtTerminateProcess
		"\x49\xc7\xc2\xff\xff\xff\xff"  // mov r10, -1      ProcessHandle
		"\x48\xc7\xc2\x20\x00\x00\x00"  // mov rdx, 32      ExitCode
		"\x0f\x05"                      // syscall
	};

	unsigned char code1[] = {
		"\xb9\x80\x00\x00\x00" // mov ecx, 128
		"\x48\xb8\xcd\xab\xcd\xab\x00\x00\x00\x00" // mov rax, 0xabcdabcd
		"\xff\xd0" // call rax
	};
	void* a = exit;
	memcpy(code1 + 7, &a, 8);

	printf("exit proc: %p\n", exit);
	printf("Startup address is %p\n", (void*)code1);
	printf("shellcode is:\n"
		" mov eax, 0x2c  // NtTerminateProcess\n"
		" mov r10, -1    // ProcessHandle\n"
		" mov rdx, 32    // ExitCode\n"
		" syscall\n"
	);
	// 如果我们完成内存分配部分，这里就已经可以跑简单的代码了
	//bx_cpu.cpu_loop();

	auto bxt = new BxThread;
	bxt->enable_paging(bx_mem.get_page_table());
	bxt->start((bx_address)code1);
	auto c = getchar();
}

int bx_atexit()
{
	return 0;
}

BxThread::BxThread()
{
	cpu_.reset(BX_RESET_HARDWARE);
	cpu_.initialize();
	stack_ = bx_mem.allocate_stack(BX_STACK_LENGTH);
}

BxThread::~BxThread()
{
	bx_mem.free_stack(stack_, BX_STACK_LENGTH);
}

void BxThread::enable_paging(bx_address pt_base)
{
	cpu_.cr0.set_PG(1);
	cpu_.cr3 = pt_base & 0xFFFFFFFFFFFFF000;
}

void BxThread::start(bx_address code_base)
{
	DWORD tid;
	cpu_.gen_reg[BX_64BIT_REG_RSP].rrx = stack_ + BX_STACK_LENGTH - 256;
	cpu_.gen_reg[BX_64BIT_REG_RIP].rrx = code_base;
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)thread_entry, this, 0, &tid);
}

DWORD __stdcall BxThread::thread_entry(BxThread* self)
{
	self->cpu_.cpu_loop();
	return 0;
}
