#include <stdio.h>
#include <Windows.h>
#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"

bx_debug_t bx_dbg;
logfunctions logger;
BX_MEM_C bx_mem;
BX_CPU_C bx_cpu;	 // master cpu

class BxThread
{
public:
	static constexpr Bit32u BX_STACK_LENGTH = 1024 * 64;

	BxThread();
	BxThread(BX_CPU_C* cpu);
	~BxThread();
	void init_context(bx_address code_base);
	void run();
	void run_new_thread();

	static DWORD __stdcall thread_entry(BxThread* self);

private:
	BX_CPU_C* cpu_;
	bx_address stack_;
	bool cpu_owned_;
};

int main(int argc, char** argv)
{
	bx_mem.init_memory();

	unsigned char exit_code[] = {
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

	unsigned char code2[] = {
		"\x48\xb8\x68\x65\x6c\x6c\x6f\x21\x0a\x00"
		"\x48\x89\x04\x24"
		"\x48\x89\xe1"
		"\x48\xb8\xaa\xaa\xaa\xaa\xaa\x00\x00\x00"
		"\xff\xd0"
		"\x31\xc0"
		"\x48\x89\x18"
	};

	unsigned char msgbox_code[] = {
		"\x48\xb8\x68\x65\x6c\x6c\x6f\x21\x0a\x00"
		"\x48\x89\x04\x24"
		"\x31\xc9"
		"\x48\x89\xe2"
		"\x49\x89\xe0"
		"\x45\x31\xc9"
		"\x48\x83\xec\x10"
		"\x48\xb8\xab\xab\xab\xab\xab\x00\x00\x00"
		"\xff\xd0\x31\xc0\x89\x00"
	};

	printf("shellcode:\n"
		"movabs rax, 0xa216f6c6c6568  ; \"hello!\\n\"\n"
		"mov    qword ptr [rsp], rax\n"
		"xor    ecx, ecx  ; arg0\n"
		"mov    rdx, rsp  ; arg1\n"
		"mov    r8, rsp   ; arg2\n"
		"xor    r9d, r9d  ; arg3\n"
		"sub    rsp, 0x10\n"
		"movabs rax, 0xababababab  ; 0xababababab is MessageBoxA\n"
		"call   rax\n"
		"xor    eax, eax\n"
		"mov    dword ptr [rax], eax  ; write to null address to trigger an exception\n"
	);

	auto* code = msgbox_code;
	void* a = MessageBoxA;
	memcpy(code + 31, &a, 8);

	BxThread bxt(&bx_cpu);
	bxt.init_context((bx_address)code);

#if BX_GDBSTUB
	if (argc > 1 && stricmp(argv[1], "-d") == 0) {
		bx_dbg.gdbstub_enabled = 1;
		bx_gdbstub_init();
	}
	else {
#else
	{
#endif
		bxt.run();
	}
}

int bx_atexit()
{
	return 0;
}

BxThread::BxThread()
	: cpu_owned_(true)
{
	cpu_ = new BX_CPU_C;
	stack_ = bx_mem.allocate_stack(BX_STACK_LENGTH);
}

BxThread::BxThread(BX_CPU_C* cpu)
	: cpu_owned_(false)
{
	cpu_ = cpu;
	stack_ = bx_mem.allocate_stack(BX_STACK_LENGTH);
}

BxThread::~BxThread()
{
	bx_mem.free_stack(stack_, BX_STACK_LENGTH);
	if (cpu_owned_) {
		delete cpu_;
	}
}

void BxThread::init_context(bx_address code_base)
{
	cpu_->initialize();
	cpu_->enable_paging(bx_mem.get_page_table());
	cpu_->gen_reg[BX_64BIT_REG_RSP].rrx = stack_ + BX_STACK_LENGTH - 256;
	cpu_->gen_reg[BX_64BIT_REG_RIP].rrx = code_base;
}

void BxThread::run()
{
	cpu_->cpu_loop();
}

void BxThread::run_new_thread()
{
	DWORD tid;
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)thread_entry, this, 0, &tid);
}

DWORD __stdcall BxThread::thread_entry(BxThread* self)
{
	self->cpu_->cpu_loop();
	return 0;
}
