all: libcpu.a

libcpu.a: cpu.o init.o crregs.o proc_ctrl.o\
		bcd.o soft_int.o protect_ctrl.o\
		bit.o bit16.o bit32.o bit64.o\
		crc32.o cpuid.o generic_cpuid.o\
		ctrl_xfer16.o ctrl_xfer32.o ctrl_xfer64.o \
		flag_ctrl_pro.o exception.o access2.o flag_ctrl.o\
		paging.o call_far.o ctrl_xfer_pro.o icache.o\
		event.o access.o stack.o debugstuff.o segment_ctrl_pro.o\
		xsave.o decoder/fetchdecode32.o decoder/fetchdecode64.o\
		arith8.o arith16.o arith32.o arith64.o bmi32.o bmi64.o\
		iret.o vm8086.o jmp_far.o ret_far.o wide_int.o\
		logical8.o  logical16.o logical32.o logical64.o\
		shift8.o shift16.o shift32.o shift64.o\
		stack16.o stack32.o stack64.o\
		mmx.o segment_ctrl.o mult8.o mult16.o mult32.o mult64.o\
		sse.o sse_move.o sse_rcp.o sse_pfp.o sse_string.o \
		stack64.o sse_pfp.o mult64.o ctrl_xfer64.o\
		logical64.o data_xfer8.o data_xfer16.o data_xfer32.o data_xfer64.o\
		rdrand.o shift64.o load.o string.o\
		msr.o aes.o sha.o smm.o mwait.o\
		io.o fpu_emu.o gf2.o decoder/disasm.o
	ar -crs $@ $^

%.o: %.cc
	g++ $(CFLAGS) -c $^ -o $@
