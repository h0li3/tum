#define NEED_CPU_REG_SHORTCUTS 1
#include "bochs.h"
#include "cpu.h"

#include "cpustats.h"

#include "handlers.h"

#include <stdlib.h>

BX_CPU_C::BX_CPU_C(unsigned id)
    : bx_cpuid(id),
    eflags(0),
    idtr(),
    eipPageBias(0),
    last_exception_type(0)
{
    // in case of SMF, you cannot reference any member data
    // in the constructor because the only access to it is via
    // global variables which aren't initialized quite yet.
    char name[16], logname[16];
    sprintf(name, "CPU%x", bx_cpuid);
    sprintf(logname, "cpu%x", bx_cpuid);
    logger.put(logname, name);

    for (unsigned n=0;n<BX_ISA_EXTENSIONS_ARRAY_SIZE;n++)
      ia_extensions_bitmask[n] = 0;

    ia_extensions_bitmask[0] = (1 << BX_ISA_386);
    if (BX_SUPPORT_FPU)
      ia_extensions_bitmask[0] |= (1 << BX_ISA_X87);

    stats = NULL;

    srand((unsigned)time(NULL)); // initialize random generator for RDRAND/RDSEED
}

static bx_cpuid_t *cpuid_factory(BX_CPU_C *cpu)
{
	return 0;
}

// BX_CPU_C constructor
void BX_CPU_C::initialize(void)
{
    efer.set_NXE(0);
	efer.set_LME(1); // Enable long mode
    efer.set_LMA(1); // Activate long mode
    cpu_mode = BX_MODE_LONG_64; // default mode is long64

    init_FetchDecodeTables(); // must be called after init_isa_features_bitmask()

	idtr.limit = 32 * 8;
	idtr.base = (bx_address)InterruptHandlers::handlers;

#if BX_CPU_LEVEL >= 6
    xsave_xrestor_init();
#endif
}

BX_CPU_C::~BX_CPU_C()
{
    BX_DEBUG(("Exit."));
}

void BX_CPU_C::reset(unsigned source)
{
    unsigned n;

    if (source == BX_RESET_HARDWARE)
      BX_INFO(("cpu hardware reset"));
    else if (source == BX_RESET_SOFTWARE)
      BX_INFO(("cpu software reset"));
    else
      BX_INFO(("cpu reset"));

    for (n=0;n<BX_GENERAL_REGISTERS;n++)
      BX_WRITE_32BIT_REGZ(n, 0);

//BX_WRITE_32BIT_REGZ(BX_32BIT_REG_EDX, get_cpu_version_information());

    // initialize NIL register
    BX_WRITE_32BIT_REGZ(BX_NIL_REGISTER, 0);

    BX_CPU_THIS_PTR eflags = 0x2; // Bit1 is always set
    // clear lazy flags state to satisfy Valgrind uninitialized variables checker
    memset(&BX_CPU_THIS_PTR oszapc, 0, sizeof(BX_CPU_THIS_PTR oszapc));
    clearEFlagsOSZAPC();	        // update lazy flags state

    if (source == BX_RESET_HARDWARE)
      BX_CPU_THIS_PTR icount = 0;
    BX_CPU_THIS_PTR icount_last_sync = BX_CPU_THIS_PTR icount;

    BX_CPU_THIS_PTR inhibit_mask = 0;
    BX_CPU_THIS_PTR inhibit_icount = 0;

    BX_CPU_THIS_PTR activity_state = BX_ACTIVITY_STATE_ACTIVE;
    BX_CPU_THIS_PTR debug_trap = 0;

    /* instruction pointer */
#if BX_CPU_LEVEL < 2
    BX_CPU_THIS_PTR prev_rip = EIP = 0x00000000;
#else /* from 286 up */
    BX_CPU_THIS_PTR prev_rip = RIP = 0x0000FFF0;
#endif

    /* CS (Code Segment) and descriptor cache */
    /* Note: on a real cpu, CS initially points to upper memory.  After
     * the 1st jump, the descriptor base is zero'd out.  Since I'm just
     * going to jump to my BIOS, I don't need to do this.
     * For future reference:
     *   processor  cs.selector   cs.base    cs.limit    EIP
     *        8086    FFFF          FFFF0        FFFF   0000
     *        286     F000         FF0000        FFFF   FFF0
     *        386+    F000       FFFF0000        FFFF   FFF0
     */
    parse_selector(0xf000,
            &BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector);

    BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.valid    = SegValidCache | SegAccessROK | SegAccessWOK;
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.p        = 1;
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.dpl      = 0;
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.segment  = 1;  /* data/code segment */
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.type     = BX_DATA_READ_WRITE_ACCESSED;

    BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.u.segment.base         = 0xFFFF0000;
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.u.segment.limit_scaled = 0xFFFF;

#if BX_CPU_LEVEL >= 3
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.u.segment.g   = 0; /* byte granular */
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.u.segment.d_b = 0; /* 16bit default size */
#if BX_SUPPORT_X86_64
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.u.segment.l   = 0; /* 16bit default size */
#endif
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.u.segment.avl = 0;
#endif

    flushICaches();

    /* DS (Data Segment) and descriptor cache */
    parse_selector(0x0000,
            &BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS].selector);

    BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS].cache.valid    = SegValidCache | SegAccessROK | SegAccessWOK;
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS].cache.p        = 1;
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS].cache.dpl      = 0;
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS].cache.segment  = 1; /* data/code segment */
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS].cache.type     = BX_DATA_READ_WRITE_ACCESSED;

    BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS].cache.u.segment.base         = 0x00000000;
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS].cache.u.segment.limit_scaled = 0xFFFF;
#if BX_CPU_LEVEL >= 3
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS].cache.u.segment.avl = 0;
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS].cache.u.segment.g   = 0; /* byte granular */
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS].cache.u.segment.d_b = 0; /* 16bit default size */
#if BX_SUPPORT_X86_64
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS].cache.u.segment.l   = 0; /* 16bit default size */
#endif
#endif

    // use DS segment as template for the others
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS] = BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS];
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_ES] = BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS];
#if BX_CPU_LEVEL >= 3
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_FS] = BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS];
    BX_CPU_THIS_PTR sregs[BX_SEG_REG_GS] = BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS];
#endif

    /* GDTR (Global Descriptor Table Register) */
    BX_CPU_THIS_PTR gdtr.base  = 0x00000000;
    BX_CPU_THIS_PTR gdtr.limit =     0xFFFF;

    /* IDTR (Interrupt Descriptor Table Register) */
    BX_CPU_THIS_PTR idtr.base  = 0x00000000;
    BX_CPU_THIS_PTR idtr.limit =     0xFFFF; /* always byte granular */

    /* LDTR (Local Descriptor Table Register) */
    BX_CPU_THIS_PTR ldtr.selector.value = 0x0000;
    BX_CPU_THIS_PTR ldtr.selector.index = 0x0000;
    BX_CPU_THIS_PTR ldtr.selector.ti    = 0;
    BX_CPU_THIS_PTR ldtr.selector.rpl   = 0;

    BX_CPU_THIS_PTR ldtr.cache.valid    = SegValidCache; /* valid */
    BX_CPU_THIS_PTR ldtr.cache.p        = 1; /* present */
    BX_CPU_THIS_PTR ldtr.cache.dpl      = 0; /* field not used */
    BX_CPU_THIS_PTR ldtr.cache.segment  = 0; /* system segment */
    BX_CPU_THIS_PTR ldtr.cache.type     = BX_SYS_SEGMENT_LDT;
    BX_CPU_THIS_PTR ldtr.cache.u.segment.base       = 0x00000000;
    BX_CPU_THIS_PTR ldtr.cache.u.segment.limit_scaled =   0xFFFF;
    BX_CPU_THIS_PTR ldtr.cache.u.segment.avl = 0;
    BX_CPU_THIS_PTR ldtr.cache.u.segment.g   = 0;  /* byte granular */

    /* TR (Task Register) */
    BX_CPU_THIS_PTR tr.selector.value = 0x0000;
    BX_CPU_THIS_PTR tr.selector.index = 0x0000; /* undefined */
    BX_CPU_THIS_PTR tr.selector.ti    = 0;
    BX_CPU_THIS_PTR tr.selector.rpl   = 0;

    BX_CPU_THIS_PTR tr.cache.valid    = SegValidCache; /* valid */
    BX_CPU_THIS_PTR tr.cache.p        = 1; /* present */
    BX_CPU_THIS_PTR tr.cache.dpl      = 0; /* field not used */
    BX_CPU_THIS_PTR tr.cache.segment  = 0; /* system segment */
    BX_CPU_THIS_PTR tr.cache.type     = BX_SYS_SEGMENT_BUSY_386_TSS;
    BX_CPU_THIS_PTR tr.cache.u.segment.base         = 0x00000000;
    BX_CPU_THIS_PTR tr.cache.u.segment.limit_scaled =     0xFFFF;
    BX_CPU_THIS_PTR tr.cache.u.segment.avl = 0;
    BX_CPU_THIS_PTR tr.cache.u.segment.g   = 0;  /* byte granular */

    BX_CPU_THIS_PTR cpu_mode = BX_MODE_IA32_REAL;

    // DR0 - DR7 (Debug Registers)
#if BX_CPU_LEVEL >= 3
    for (n=0; n<4; n++)
      BX_CPU_THIS_PTR dr[n] = 0;
#endif

#if BX_CPU_LEVEL >= 5
    BX_CPU_THIS_PTR dr6.val32 = 0xFFFF0FF0;
#else
    BX_CPU_THIS_PTR dr6.val32 = 0xFFFF1FF0;
#endif
    BX_CPU_THIS_PTR dr7.val32 = 0x00000400;

#if BX_X86_DEBUGGER
    BX_CPU_THIS_PTR in_repeat = false;
#endif
    BX_CPU_THIS_PTR in_smm = false;

    BX_CPU_THIS_PTR pending_event = 0;
    BX_CPU_THIS_PTR event_mask = 0;

    if (source == BX_RESET_HARDWARE) {
      BX_CPU_THIS_PTR smbase = 0x30000; // do not change SMBASE on INIT
    }

    BX_CPU_THIS_PTR cr0.set32(0x60000010);
    // handle reserved bits
#if BX_CPU_LEVEL == 3
    // reserved bits all set to 1 on 386
    BX_CPU_THIS_PTR cr0.val32 |= 0x7ffffff0;
#endif

#if BX_CPU_LEVEL >= 3
    BX_CPU_THIS_PTR cr2 = 0;
    BX_CPU_THIS_PTR cr3 = 0;
#endif

#if BX_CPU_LEVEL >= 5
    BX_CPU_THIS_PTR cr4.set32(0);
    BX_CPU_THIS_PTR cr4_suppmask = get_cr4_allow_mask();
#endif

#if BX_CPU_LEVEL >= 6
    if (source == BX_RESET_HARDWARE) {
      BX_CPU_THIS_PTR xcr0.set32(0x1);
    }
    BX_CPU_THIS_PTR xcr0_suppmask = get_xcr0_allow_mask();

    BX_CPU_THIS_PTR msr.ia32_xss = 0;

#if BX_SUPPORT_CET
    BX_CPU_THIS_PTR msr.ia32_interrupt_ssp_table = 0;
    BX_CPU_THIS_PTR msr.ia32_cet_control[0] = BX_CPU_THIS_PTR msr.ia32_cet_control[1] = 0;
    for (n=0;n<4;n++)
      BX_CPU_THIS_PTR msr.ia32_pl_ssp[n] = 0;
    SSP = 0;
#endif
#endif // BX_CPU_LEVEL >= 6

#if BX_CPU_LEVEL >= 5
    BX_CPU_THIS_PTR msr.ia32_spec_ctrl = 0;

    BX_CPU_THIS_PTR efer.set32(0);
    BX_CPU_THIS_PTR efer_suppmask = 0;
    if (BX_CPUID_SUPPORT_ISA_EXTENSION(BX_ISA_NX))
      BX_CPU_THIS_PTR efer_suppmask |= BX_EFER_NXE_MASK;
    if (BX_CPUID_SUPPORT_ISA_EXTENSION(BX_ISA_SYSCALL_SYSRET_LEGACY))
      BX_CPU_THIS_PTR efer_suppmask |= BX_EFER_SCE_MASK;
#if BX_SUPPORT_X86_64
    if (BX_CPUID_SUPPORT_ISA_EXTENSION(BX_ISA_LONG_MODE)) {
      BX_CPU_THIS_PTR efer_suppmask |= (BX_EFER_SCE_MASK | BX_EFER_LME_MASK | BX_EFER_LMA_MASK);
      if (BX_CPUID_SUPPORT_ISA_EXTENSION(BX_ISA_FFXSR))
        BX_CPU_THIS_PTR efer_suppmask |= BX_EFER_FFXSR_MASK;
    }
#endif

    BX_CPU_THIS_PTR msr.star = 0;
#if BX_SUPPORT_X86_64
    if (BX_CPUID_SUPPORT_ISA_EXTENSION(BX_ISA_LONG_MODE)) {
      if (source == BX_RESET_HARDWARE) {
        BX_CPU_THIS_PTR msr.lstar = 0;
        BX_CPU_THIS_PTR msr.cstar = 0;
      }
      BX_CPU_THIS_PTR msr.fmask = 0x00020200;
      BX_CPU_THIS_PTR msr.kernelgsbase = 0;
      if (source == BX_RESET_HARDWARE) {
        BX_CPU_THIS_PTR msr.tsc_aux = 0;
      }
    }
#endif

    if (source == BX_RESET_HARDWARE) {
      BX_CPU_THIS_PTR set_TSC(0); // do not change TSC on INIT
    }
#endif // BX_CPU_LEVEL >= 5

    if (source == BX_RESET_HARDWARE) {

#if BX_SUPPORT_PKEYS
      BX_CPU_THIS_PTR set_PKeys(0, 0);
#endif

#if BX_CPU_LEVEL >= 6
      BX_CPU_THIS_PTR msr.sysenter_cs_msr  = 0;
      BX_CPU_THIS_PTR msr.sysenter_esp_msr = 0;
      BX_CPU_THIS_PTR msr.sysenter_eip_msr = 0;
#endif

    // Do not change MTRR on INIT
#if BX_CPU_LEVEL >= 6
      for (n=0; n<16; n++)
        BX_CPU_THIS_PTR msr.mtrrphys[n] = 0;

      BX_CPU_THIS_PTR msr.mtrrfix64k = (Bit64u) 0; // all fix range MTRRs undefined according to manual
      BX_CPU_THIS_PTR msr.mtrrfix16k[0] = (Bit64u) 0;
      BX_CPU_THIS_PTR msr.mtrrfix16k[1] = (Bit64u) 0;
      for (n=0; n<8; n++)
        BX_CPU_THIS_PTR msr.mtrrfix4k[n] = (Bit64u) 0;

      BX_CPU_THIS_PTR msr.pat = (Bit64u) BX_CONST64(0x0007040600070406);
      BX_CPU_THIS_PTR msr.mtrr_deftype = 0;
#endif
    }

    BX_CPU_THIS_PTR EXT = 0;
    BX_CPU_THIS_PTR last_exception_type = 0;

    // invalidate the code prefetch queue
    BX_CPU_THIS_PTR eipPageBias = 0;
    BX_CPU_THIS_PTR eipPageWindowSize = 0;
    BX_CPU_THIS_PTR eipFetchPtr = NULL;

    // invalidate current stack page
    BX_CPU_THIS_PTR espPageBias = 0;
    BX_CPU_THIS_PTR espPageWindowSize = 0;
    BX_CPU_THIS_PTR espHostPtr = NULL;
#if BX_SUPPORT_SMP == 0
    BX_CPU_THIS_PTR espPageFineGranularityMapping = 0;
#endif

#if BX_DEBUGGER
    BX_CPU_THIS_PTR stop_reason = STOP_NO_REASON;
    BX_CPU_THIS_PTR magic_break = 0;
    BX_CPU_THIS_PTR trace = 0;
    BX_CPU_THIS_PTR trace_reg = 0;
    BX_CPU_THIS_PTR trace_mem = 0;
    BX_CPU_THIS_PTR mode_break = 0;
#endif

    // Reset the Floating Point Unit
#if BX_SUPPORT_FPU
    if (source == BX_RESET_HARDWARE) {
      BX_CPU_THIS_PTR the_i387.reset();
    }
#endif

#if BX_CPU_LEVEL >= 6
    BX_CPU_THIS_PTR sse_ok = 0;
#if BX_SUPPORT_AVX
    BX_CPU_THIS_PTR avx_ok = 0;
#endif

#if BX_SUPPORT_EVEX
    BX_CPU_THIS_PTR opmask_ok = BX_CPU_THIS_PTR evex_ok = 0;

    if (source == BX_RESET_HARDWARE) {
      for (n=0; n<8; n++) BX_WRITE_OPMASK(n, 0);
    }
#endif

    // Reset XMM state - unchanged on #INIT
    if (source == BX_RESET_HARDWARE) {
      for(n=0; n<BX_XMM_REGISTERS; n++) {
        BX_CLEAR_AVX_REG(n);
      }

      BX_CPU_THIS_PTR mxcsr.mxcsr = MXCSR_RESET;
      BX_CPU_THIS_PTR mxcsr_mask = 0x0000ffbf;
      if (BX_CPUID_SUPPORT_ISA_EXTENSION(BX_ISA_SSE2))
        BX_CPU_THIS_PTR mxcsr_mask |= MXCSR_DAZ;
      if (BX_CPUID_SUPPORT_ISA_EXTENSION(BX_ISA_MISALIGNED_SSE))
        BX_CPU_THIS_PTR mxcsr_mask |= MXCSR_MISALIGNED_EXCEPTION_MASK;
    }
#endif

#if BX_SUPPORT_SMP
    // notice if I'm the bootstrap processor.  If not, do the equivalent of
    // a HALT instruction.
    int apic_id = lapic.get_id();
    if (BX_BOOTSTRAP_PROCESSOR == apic_id) {
      // boot normally
      BX_CPU_THIS_PTR msr.apicbase |=  0x100; /* set bit 8 BSP */
      BX_INFO(("CPU[%d] is the bootstrap processor", apic_id));
    } else {
      // it's an application processor, halt until IPI is heard.
      BX_CPU_THIS_PTR msr.apicbase &= ~0x100; /* clear bit 8 BSP */
      BX_INFO(("CPU[%d] is an application processor. Halting until SIPI.", apic_id));
      enter_sleep_state(BX_ACTIVITY_STATE_WAIT_FOR_SIPI);
    }
#endif

    handleCpuContextChange();
}

void BX_CPU_C::sanity_checks(void)
{
    Bit32u eax = EAX, ecx = ECX, edx = EDX, ebx = EBX, esp = ESP, ebp = EBP, esi = ESI, edi = EDI;

    EAX = 0xFFEEDDCC;
    ECX = 0xBBAA9988;
    EDX = 0x77665544;
    EBX = 0x332211FF;
    ESP = 0xEEDDCCBB;
    EBP = 0xAA998877;
    ESI = 0x66554433;
    EDI = 0x2211FFEE;

    Bit8u al, cl, dl, bl, ah, ch, dh, bh;

    al = AL;
    cl = CL;
    dl = DL;
    bl = BL;
    ah = AH;
    ch = CH;
    dh = DH;
    bh = BH;

    if ( al != (EAX & 0xFF) ||
         cl != (ECX & 0xFF) ||
         dl != (EDX & 0xFF) ||
         bl != (EBX & 0xFF) ||
         ah != ((EAX >> 8) & 0xFF) ||
         ch != ((ECX >> 8) & 0xFF) ||
         dh != ((EDX >> 8) & 0xFF) ||
         bh != ((EBX >> 8) & 0xFF) )
    {
      BX_PANIC(("problems using BX_READ_8BIT_REGx()!"));
    }

    Bit16u ax, cx, dx, bx, sp, bp, si, di;

    ax = AX;
    cx = CX;
    dx = DX;
    bx = BX;
    sp = SP;
    bp = BP;
    si = SI;
    di = DI;

    if ( ax != (EAX & 0xFFFF) ||
         cx != (ECX & 0xFFFF) ||
         dx != (EDX & 0xFFFF) ||
         bx != (EBX & 0xFFFF) ||
         sp != (ESP & 0xFFFF) ||
         bp != (EBP & 0xFFFF) ||
         si != (ESI & 0xFFFF) ||
         di != (EDI & 0xFFFF) )
    {
      BX_PANIC(("problems using BX_READ_16BIT_REG()!"));
    }

    EAX = eax; /* restore registers */
    ECX = ecx;
    EDX = edx;
    EBX = ebx;
    ESP = esp;
    EBP = ebp;
    ESI = esi;
    EDI = edi;

    if (sizeof(Bit8u) != 1)
      BX_PANIC(("data type Bit8u or Bit8s is not of length 1 byte!"));
    if (sizeof(Bit16u) != 2)
      BX_PANIC(("data type Bit16u or Bit16s is not of length 2 bytes!"));
    if (sizeof(Bit32u) != 4)
      BX_PANIC(("data type Bit32u or Bit32s is not of length 4 bytes!"));
    if (sizeof(Bit64u) != 8)
      BX_PANIC(("data type Bit64u or Bit64u is not of length 8 bytes!"));

    if (sizeof(void*) != sizeof(bx_ptr_equiv_t))
      BX_PANIC(("data type bx_ptr_equiv_t is not equivalent to 'void*' pointer"));

    if (sizeof(int) < 4)
      BX_PANIC(("Bochs assumes that 'int' type is at least 4 bytes wide!"));

    BX_DEBUG(("#(%u)all sanity checks passed!", BX_CPU_ID));
}

void BX_CPU_C::assert_checks(void)
{
    // check CPU mode consistency
#if BX_SUPPORT_X86_64
    if (BX_CPU_THIS_PTR efer.get_LMA()) {
      if (! BX_CPU_THIS_PTR cr0.get_PE()) {
        BX_PANIC(("assert_checks: EFER.LMA is set when CR0.PE=0 !"));
      }
      if (BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.u.segment.l) {
        if (BX_CPU_THIS_PTR cpu_mode != BX_MODE_LONG_64)
          BX_PANIC(("assert_checks: unconsistent cpu_mode BX_MODE_LONG_64 !"));
      }
      else {
        if (BX_CPU_THIS_PTR cpu_mode != BX_MODE_LONG_COMPAT)
          BX_PANIC(("assert_checks: unconsistent cpu_mode BX_MODE_LONG_COMPAT !"));
      }
    }
    else
#endif
    {
      if (BX_CPU_THIS_PTR cr0.get_PE()) {
        if (BX_CPU_THIS_PTR get_VM()) {
          if (BX_CPU_THIS_PTR cpu_mode != BX_MODE_IA32_V8086)
            BX_PANIC(("assert_checks: unconsistent cpu_mode BX_MODE_IA32_V8086 !"));
        }
        else {
          if (BX_CPU_THIS_PTR cpu_mode != BX_MODE_IA32_PROTECTED)
            BX_PANIC(("assert_checks: unconsistent cpu_mode BX_MODE_IA32_PROTECTED !"));
        }
      }
      else {
        if (BX_CPU_THIS_PTR cpu_mode != BX_MODE_IA32_REAL)
          BX_PANIC(("assert_checks: unconsistent cpu_mode BX_MODE_IA32_REAL !"));
      }
    }

    // check CR0 consistency
    if (! check_CR0(BX_CPU_THIS_PTR cr0.val32))
      BX_PANIC(("assert_checks: CR0 consistency checks failed !"));

#if BX_CPU_LEVEL >= 5
    // check CR4 consistency
    if (! check_CR4(BX_CPU_THIS_PTR cr4.val32))
      BX_PANIC(("assert_checks: CR4 consistency checks failed !"));
#endif

#if BX_SUPPORT_X86_64
    // VM should be OFF in long mode
    if (long_mode()) {
      if (BX_CPU_THIS_PTR get_VM()) BX_PANIC(("assert_checks: VM is set in long mode !"));
    }

    // CS.L and CS.D_B are mutualy exclusive
    if (BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.u.segment.l &&
        BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.u.segment.d_b)
    {
      BX_PANIC(("assert_checks: CS.l and CS.d_b set together !"));
    }
#endif

    // check LDTR type
    if (BX_CPU_THIS_PTR ldtr.cache.valid)
    {
      if (BX_CPU_THIS_PTR ldtr.cache.type != BX_SYS_SEGMENT_LDT)
      {
        BX_PANIC(("assert_checks: LDTR is not LDT type !"));
      }
    }

    // check Task Register type
    if(BX_CPU_THIS_PTR tr.cache.valid)
    {
      switch(BX_CPU_THIS_PTR tr.cache.type)
      {
        case BX_SYS_SEGMENT_BUSY_286_TSS:
        case BX_SYS_SEGMENT_AVAIL_286_TSS:
#if BX_CPU_LEVEL >= 3
          if (BX_CPU_THIS_PTR tr.cache.u.segment.g != 0)
            BX_PANIC(("assert_checks: tss286.g != 0 !"));
          if (BX_CPU_THIS_PTR tr.cache.u.segment.avl != 0)
            BX_PANIC(("assert_checks: tss286.avl != 0 !"));
#endif
          break;
        case BX_SYS_SEGMENT_BUSY_386_TSS:
        case BX_SYS_SEGMENT_AVAIL_386_TSS:
          break;
        default:
          BX_PANIC(("assert_checks: TR is not TSS type !"));
      }
    }

#if BX_SUPPORT_X86_64 == 0 && BX_CPU_LEVEL >= 5
    if (BX_CPU_THIS_PTR efer_suppmask & (BX_EFER_SCE_MASK |
                      BX_EFER_LME_MASK | BX_EFER_LMA_MASK | BX_EFER_FFXSR_MASK))
    {
      BX_PANIC(("assert_checks: EFER supports x86-64 specific bits !"));
    }
#endif
}
