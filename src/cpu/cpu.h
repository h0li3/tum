#ifndef BX_CPU_H
#define BX_CPU_H

#include <setjmp.h>

#include "bx_debug/debug.h"
#include "instrument.h"
#include "decoder/decoder.h"

const Bit64u BX_PHY_ADDRESS_MASK = ((((Bit64u)(1)) << BX_PHY_ADDRESS_WIDTH) - 1);

const Bit64u BX_PHY_ADDRESS_RESERVED_BITS = (~BX_PHY_ADDRESS_MASK);

#if defined(NEED_CPU_REG_SHORTCUTS)

/* WARNING:
   Only BX_CPU_C member functions can use these shortcuts safely!
   Functions that use the shortcuts outside of BX_CPU_C might work
   when BX_USE_CPU_SMF=1 but will fail when BX_USE_CPU_SMF=0
   (for example in SMP mode).
*/

// access to 8 bit general registers
#define AL (BX_CPU_THIS_PTR gen_reg[0].word.byte.rl)
#define CL (BX_CPU_THIS_PTR gen_reg[1].word.byte.rl)
#define DL (BX_CPU_THIS_PTR gen_reg[2].word.byte.rl)
#define BL (BX_CPU_THIS_PTR gen_reg[3].word.byte.rl)
#define AH (BX_CPU_THIS_PTR gen_reg[0].word.byte.rh)
#define CH (BX_CPU_THIS_PTR gen_reg[1].word.byte.rh)
#define DH (BX_CPU_THIS_PTR gen_reg[2].word.byte.rh)
#define BH (BX_CPU_THIS_PTR gen_reg[3].word.byte.rh)

#define TMP8L (BX_CPU_THIS_PTR gen_reg[BX_TMP_REGISTER].word.byte.rl)

// access to 16 bit general registers
#define AX (BX_CPU_THIS_PTR gen_reg[0].word.rx)
#define CX (BX_CPU_THIS_PTR gen_reg[1].word.rx)
#define DX (BX_CPU_THIS_PTR gen_reg[2].word.rx)
#define BX (BX_CPU_THIS_PTR gen_reg[3].word.rx)
#define SP (BX_CPU_THIS_PTR gen_reg[4].word.rx)
#define BP (BX_CPU_THIS_PTR gen_reg[5].word.rx)
#define SI (BX_CPU_THIS_PTR gen_reg[6].word.rx)
#define DI (BX_CPU_THIS_PTR gen_reg[7].word.rx)

// access to 16 bit instruction pointer
#define IP (BX_CPU_THIS_PTR gen_reg[BX_16BIT_REG_IP].word.rx)

#define TMP16 (BX_CPU_THIS_PTR gen_reg[BX_TMP_REGISTER].word.rx)

// accesss to 32 bit general registers
#define EAX (BX_CPU_THIS_PTR gen_reg[0].dword.erx)
#define ECX (BX_CPU_THIS_PTR gen_reg[1].dword.erx)
#define EDX (BX_CPU_THIS_PTR gen_reg[2].dword.erx)
#define EBX (BX_CPU_THIS_PTR gen_reg[3].dword.erx)
#define ESP (BX_CPU_THIS_PTR gen_reg[4].dword.erx)
#define EBP (BX_CPU_THIS_PTR gen_reg[5].dword.erx)
#define ESI (BX_CPU_THIS_PTR gen_reg[6].dword.erx)
#define EDI (BX_CPU_THIS_PTR gen_reg[7].dword.erx)

// access to 32 bit instruction pointer
#define EIP (BX_CPU_THIS_PTR gen_reg[BX_32BIT_REG_EIP].dword.erx)

#define TMP32 (BX_CPU_THIS_PTR gen_reg[BX_TMP_REGISTER].dword.erx)

#if BX_SUPPORT_X86_64

// accesss to 64 bit general registers
#define RAX (BX_CPU_THIS_PTR gen_reg[0].rrx)
#define RCX (BX_CPU_THIS_PTR gen_reg[1].rrx)
#define RDX (BX_CPU_THIS_PTR gen_reg[2].rrx)
#define RBX (BX_CPU_THIS_PTR gen_reg[3].rrx)
#define RSP (BX_CPU_THIS_PTR gen_reg[4].rrx)
#define RBP (BX_CPU_THIS_PTR gen_reg[5].rrx)
#define RSI (BX_CPU_THIS_PTR gen_reg[6].rrx)
#define RDI (BX_CPU_THIS_PTR gen_reg[7].rrx)
#define R8  (BX_CPU_THIS_PTR gen_reg[8].rrx)
#define R9  (BX_CPU_THIS_PTR gen_reg[9].rrx)
#define R10 (BX_CPU_THIS_PTR gen_reg[10].rrx)
#define R11 (BX_CPU_THIS_PTR gen_reg[11].rrx)
#define R12 (BX_CPU_THIS_PTR gen_reg[12].rrx)
#define R13 (BX_CPU_THIS_PTR gen_reg[13].rrx)
#define R14 (BX_CPU_THIS_PTR gen_reg[14].rrx)
#define R15 (BX_CPU_THIS_PTR gen_reg[15].rrx)

// access to 64 bit instruction pointer
#define RIP (BX_CPU_THIS_PTR gen_reg[BX_64BIT_REG_RIP].rrx)

#define SSP (BX_CPU_THIS_PTR gen_reg[BX_64BIT_REG_SSP].rrx)

#define TMP64 (BX_CPU_THIS_PTR gen_reg[BX_TMP_REGISTER].rrx)

// access to 64 bit MSR registers
#define MSR_FSBASE  (BX_CPU_THIS_PTR sregs[BX_SEG_REG_FS].cache.u.segment.base)
#define MSR_GSBASE  (BX_CPU_THIS_PTR sregs[BX_SEG_REG_GS].cache.u.segment.base)

#else // simplify merge between 32-bit and 64-bit mode

#define RAX EAX
#define RCX ECX
#define RDX EDX
#define RBX EBX
#define RSP ESP
#define RBP EBP
#define RSI ESI
#define RDI EDI
#define RIP EIP

#endif // BX_SUPPORT_X86_64 == 0

#define PREV_RIP (BX_CPU_THIS_PTR prev_rip)

#if BX_SUPPORT_X86_64
#define BX_READ_8BIT_REGx(index,extended)  ((((index) & 4) == 0 || (extended)) ? \
  (BX_CPU_THIS_PTR gen_reg[index].word.byte.rl) : \
  (BX_CPU_THIS_PTR gen_reg[(index)-4].word.byte.rh))
#define BX_READ_64BIT_REG(index) (BX_CPU_THIS_PTR gen_reg[index].rrx)
#define BX_READ_64BIT_REG_HIGH(index) (BX_CPU_THIS_PTR gen_reg[index].dword.hrx)
#else
#define BX_READ_8BIT_REG(index)  (((index) & 4) ? \
  (BX_CPU_THIS_PTR gen_reg[(index)-4].word.byte.rh) : \
  (BX_CPU_THIS_PTR gen_reg[index].word.byte.rl))
#define BX_READ_8BIT_REGx(index,ext) BX_READ_8BIT_REG(index)
#endif

#define BX_READ_8BIT_REGL(index) (BX_CPU_THIS_PTR gen_reg[index].word.byte.rl)
#define BX_READ_16BIT_REG(index) (BX_CPU_THIS_PTR gen_reg[index].word.rx)
#define BX_READ_32BIT_REG(index) (BX_CPU_THIS_PTR gen_reg[index].dword.erx)

#define BX_WRITE_8BIT_REGH(index, val) {\
  BX_CPU_THIS_PTR gen_reg[index].word.byte.rh = val; \
}

#define BX_WRITE_16BIT_REG(index, val) {\
  BX_CPU_THIS_PTR gen_reg[index].word.rx = val; \
}

#if BX_SUPPORT_X86_64

#define BX_WRITE_8BIT_REGx(index, extended, val) {\
  if (((index) & 4) == 0 || (extended)) \
    BX_CPU_THIS_PTR gen_reg[index].word.byte.rl = val; \
  else \
    BX_CPU_THIS_PTR gen_reg[(index)-4].word.byte.rh = val; \
}

#define BX_WRITE_32BIT_REGZ(index, val) {\
  BX_CPU_THIS_PTR gen_reg[index].rrx = (Bit32u) val; \
}

#define BX_WRITE_64BIT_REG(index, val) {\
  BX_CPU_THIS_PTR gen_reg[index].rrx = val; \
}
#define BX_CLEAR_64BIT_HIGH(index) {\
  BX_CPU_THIS_PTR gen_reg[index].dword.hrx = 0; \
}

#else

#define BX_WRITE_8BIT_REG(index, val) {\
  if ((index) & 4) \
    BX_CPU_THIS_PTR gen_reg[(index)-4].word.byte.rh = val; \
  else \
    BX_CPU_THIS_PTR gen_reg[index].word.byte.rl = val; \
}
#define BX_WRITE_8BIT_REGx(index, ext, val) BX_WRITE_8BIT_REG(index, val)

// For x86-32, I just pretend this one is like the macro above,
// so common code can be used.
#define BX_WRITE_32BIT_REGZ(index, val) {\
  BX_CPU_THIS_PTR gen_reg[index].dword.erx = (Bit32u) val; \
}

#define BX_CLEAR_64BIT_HIGH(index)

#endif

#define CPL       (BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.rpl)

#define USER_PL   (BX_CPU_THIS_PTR user_pl) /* CPL == 3 */

#if BX_SUPPORT_SMP
#define BX_CPU_ID (BX_CPU_THIS_PTR bx_cpuid)
#else
#define BX_CPU_ID (0)
#endif

#if BX_SUPPORT_AVX

#define BX_READ_8BIT_OPMASK(index)  (BX_CPU_THIS_PTR opmask[index].word.byte.rl)
#define BX_READ_16BIT_OPMASK(index) (BX_CPU_THIS_PTR opmask[index].word.rx)
#define BX_READ_32BIT_OPMASK(index) (BX_CPU_THIS_PTR opmask[index].dword.erx)
#define BX_READ_OPMASK(index)       (BX_CPU_THIS_PTR opmask[index].rrx)

#define BX_SCALAR_ELEMENT_MASK(index) ((index) == 0 || (BX_READ_32BIT_OPMASK(index) & 0x1))

#define BX_WRITE_OPMASK(index, val_64) { \
  BX_CPU_THIS_PTR opmask[index].rrx = val_64; \
}

inline Bit64u CUT_OPMASK_TO(unsigned nelements) { return (BX_CONST64(1) << (nelements)) - 1; }

#endif

#endif  // defined(NEED_CPU_REG_SHORTCUTS)

// <TAG-INSTRUMENTATION_COMMON-BEGIN>

// possible types passed to BX_INSTR_TLB_CNTRL()
enum BX_Instr_TLBControl {
    BX_INSTR_MOV_CR0 = 10,
    BX_INSTR_MOV_CR3 = 11,
    BX_INSTR_MOV_CR4 = 12,
    BX_INSTR_TASK_SWITCH = 13,
    BX_INSTR_CONTEXT_SWITCH = 14,
    BX_INSTR_INVLPG = 15,
    BX_INSTR_INVEPT = 16,
    BX_INSTR_INVVPID = 17,
    BX_INSTR_INVPCID = 18
};

// possible types passed to BX_INSTR_CACHE_CNTRL()
enum BX_Instr_CacheControl {
    BX_INSTR_INVD = 10,
    BX_INSTR_WBINVD = 11
};

// possible types passed to BX_INSTR_FAR_BRANCH() and BX_INSTR_UCNEAR_BRANCH()
enum BX_Instr_Branch {
    BX_INSTR_IS_JMP = 10,
    BX_INSTR_IS_JMP_INDIRECT = 11,
    BX_INSTR_IS_CALL = 12,
    BX_INSTR_IS_CALL_INDIRECT = 13,
    BX_INSTR_IS_RET = 14,
    BX_INSTR_IS_IRET = 15,
    BX_INSTR_IS_INT = 16,
    BX_INSTR_IS_SYSCALL = 17,
    BX_INSTR_IS_SYSRET = 18,
    BX_INSTR_IS_SYSENTER = 19,
    BX_INSTR_IS_SYSEXIT = 20
};

// possible types passed to BX_INSTR_PREFETCH_HINT()
enum BX_Instr_PrefetchHINT {
    BX_INSTR_PREFETCH_NTA = 0,
    BX_INSTR_PREFETCH_T0 = 1,
    BX_INSTR_PREFETCH_T1 = 2,
    BX_INSTR_PREFETCH_T2 = 3
};

// <TAG-INSTRUMENTATION_COMMON-END>

// passed to internal debugger together with BX_READ/BX_WRITE/BX_EXECUTE/BX_RW
enum {
    BX_PDPTR0_ACCESS = 1,
    BX_PDPTR1_ACCESS,
    BX_PDPTR2_ACCESS,
    BX_PDPTR3_ACCESS,
    BX_PTE_ACCESS,
    BX_PDE_ACCESS,
    BX_PDTE_ACCESS,
    BX_PML4E_ACCESS,
    BX_EPT_PTE_ACCESS,
    BX_EPT_PDE_ACCESS,
    BX_EPT_PDTE_ACCESS,
    BX_EPT_PML4E_ACCESS,
    BX_EPT_SPP_PTE_ACCESS,
    BX_EPT_SPP_PDE_ACCESS,
    BX_EPT_SPP_PDTE_ACCESS,
    BX_EPT_SPP_PML4E_ACCESS,
    BX_VMCS_ACCESS,
    BX_SHADOW_VMCS_ACCESS,
    BX_MSR_BITMAP_ACCESS,
    BX_IO_BITMAP_ACCESS,
    BX_VMREAD_BITMAP_ACCESS,
    BX_VMWRITE_BITMAP_ACCESS,
    BX_SMRAM_ACCESS
};

struct BxExceptionInfo {
    unsigned exception_type;
    unsigned exception_class;
    bool push_error;
};

enum BX_Exception {
    BX_DE_EXCEPTION = 0, // Divide Error (fault)
    BX_DB_EXCEPTION = 1, // Debug (fault/trap)
    BX_BP_EXCEPTION = 3, // Breakpoint (trap)
    BX_OF_EXCEPTION = 4, // Overflow (trap)
    BX_BR_EXCEPTION = 5, // BOUND (fault)
    BX_UD_EXCEPTION = 6,
    BX_NM_EXCEPTION = 7,
    BX_DF_EXCEPTION = 8,
    BX_TS_EXCEPTION = 10,
    BX_NP_EXCEPTION = 11,
    BX_SS_EXCEPTION = 12,
    BX_GP_EXCEPTION = 13,
    BX_PF_EXCEPTION = 14,
    BX_MF_EXCEPTION = 16,
    BX_AC_EXCEPTION = 17,
    BX_MC_EXCEPTION = 18,
    BX_XM_EXCEPTION = 19,
    BX_VE_EXCEPTION = 20,
    BX_CP_EXCEPTION = 21  // Control Protection (fault)
};

enum CP_Exception_Error_Code {
    BX_CP_NEAR_RET = 1,
    BX_CP_FAR_RET_IRET = 2,
    BX_CP_ENDBRANCH = 3,
    BX_CP_RSTORSSP = 4,
    BX_CP_SETSSBSY = 5
};

const unsigned BX_CPU_HANDLED_EXCEPTIONS = 32;

enum BxCpuMode {
    BX_MODE_IA32_REAL = 0,        // CR0.PE=0                |
    BX_MODE_IA32_V8086 = 1,       // CR0.PE=1, EFLAGS.VM=1   | EFER.LMA=0
    BX_MODE_IA32_PROTECTED = 2,   // CR0.PE=1, EFLAGS.VM=0   |
    BX_MODE_LONG_COMPAT = 3,      // EFER.LMA = 1, CR0.PE=1, CS.L=0
    BX_MODE_LONG_64 = 4           // EFER.LMA = 1, CR0.PE=1, CS.L=1
};

const unsigned BX_MSR_MAX_INDEX = 0x1000;

extern const char* cpu_mode_string(unsigned cpu_mode);

#if BX_SUPPORT_X86_64
inline bool IsCanonical(bx_address offset)
{
    return ((Bit64u)((((Bit64s)(offset)) >> (BX_LIN_ADDRESS_WIDTH - 1)) + 1) < 2);
}
#endif

inline bool IsValidPhyAddr(bx_phy_address addr)
{
    return ((addr & BX_PHY_ADDRESS_RESERVED_BITS) == 0);
}

inline bool IsValidPageAlignedPhyAddr(bx_phy_address addr)
{
    return ((addr & (BX_PHY_ADDRESS_RESERVED_BITS | 0xfff)) == 0);
}

const Bit32u CACHE_LINE_SIZE = 64;

class BX_CPU_C;
class BX_MEM_C;
class bxInstruction_c;

// <TAG-TYPE-EXECUTEPTR-START>
#if BX_USE_CPU_SMF
typedef void (BX_CPP_AttrRegparmN(1)* BxRepIterationPtr_tR)(bxInstruction_c*);
#else
typedef void (BX_CPU_C::* BxRepIterationPtr_tR)(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif
// <TAG-TYPE-EXECUTEPTR-END>

#if BX_USE_CPU_SMF == 0
// normal member functions.  This can ONLY be used within BX_CPU_C classes.
// Anyone on the outside should use the BX_CPU macro (defined in bochs.h)
// instead.
#  define BX_CPU_THIS_PTR  this->
#  define BX_CPU_THIS      this
#  define BX_SMF
// with normal member functions, calling a member fn pointer looks like
// object->*(fnptr)(arg, ...);
// Since this is different from when SMF=1, encapsulate it in a macro.
#  define BX_CPU_CALL_METHOD(func, args) \
            (this->*((BxExecutePtr_tR) (func))) args
#  define BX_CPU_CALL_REP_ITERATION(func, args) \
            (this->*((BxRepIterationPtr_tR) (func))) args
#else
// static member functions.  With SMF, there is only one CPU by definition.
#  define BX_CPU_THIS_PTR  BX_CPU(0)->
#  define BX_CPU_THIS      BX_CPU(0)
#  define BX_SMF           static
#  define BX_CPU_CALL_METHOD(func, args) \
            ((BxExecutePtr_tR) (func)) args
#  define BX_CPU_CALL_REP_ITERATION(func, args) \
            ((BxRepIterationPtr_tR) (func)) args
#endif

//
// BX_CPU_RESOLVE_ADDR:
// Resolve virtual address of the instruction's memory reference without any
// assumptions about instruction's operand size, address size or execution
// mode
//
// BX_CPU_RESOLVE_ADDR_64:
// Resolve virtual address of the instruction memory reference assuming
// the instruction is executed in 64-bit long mode with possible 64-bit
// or 32-bit address size.
//
// BX_CPU_RESOLVE_ADDR_32:
// Resolve virtual address of the instruction memory reference assuming
// the instruction is executed in legacy or compatibility mode with
// possible 32-bit or 16-bit address size.
//
//
#if BX_SUPPORT_X86_64
#  define BX_CPU_RESOLVE_ADDR(i) \
            ((i)->as64L() ? BxResolve64(i) : BxResolve32(i))
#  define BX_CPU_RESOLVE_ADDR_64(i) \
            ((i)->as64L() ? BxResolve64(i) : BxResolve32(i))
#else
#  define BX_CPU_RESOLVE_ADDR(i) \
            (BxResolve32(i))
#endif
#  define BX_CPU_RESOLVE_ADDR_32(i) \
            (BxResolve32(i))


#if BX_SUPPORT_SMP
// multiprocessor simulation, we need an array of cpus and memories
BOCHSAPI extern BX_CPU_C** bx_cpu_array;
#else
// single processor simulation, so there's one of everything
BOCHSAPI extern BX_CPU_C   bx_cpu;
#endif

// notify internal debugger/instrumentation about memory access
#define BX_NOTIFY_LIN_MEMORY_ACCESS(laddr, paddr, size, memtype, rw, dataptr) {              \
  BX_INSTR_LIN_ACCESS(BX_CPU_ID, (laddr), (paddr), (size), (memtype), (rw));                 \
  BX_DBG_LIN_MEMORY_ACCESS(BX_CPU_ID, (laddr), (paddr), (size), (memtype), (rw), (dataptr)); \
}

#define BX_NOTIFY_PHY_MEMORY_ACCESS(paddr, size, memtype, rw, why, dataptr) {              \
  BX_INSTR_PHY_ACCESS(BX_CPU_ID, (paddr), (size), (memtype), (rw));                        \
  BX_DBG_PHY_MEMORY_ACCESS(BX_CPU_ID, (paddr), (size), (memtype), (rw), (why), (dataptr)); \
}

// accessors for all eflags in bx_flags_reg_t
// The macro is used once for each flag bit
// Do not use for arithmetic flags !
#define DECLARE_EFLAG_ACCESSOR(name,bitnum)                     \
  inline unsigned  get_##name ();                 \
  inline unsigned getB_##name ();                 \
  inline void assert_##name ();                   \
  inline void clear_##name ();                    \
  inline void set_##name (bool val);

#define IMPLEMENT_EFLAG_ACCESSOR(name,bitnum)                   \
  inline unsigned BX_CPU_C::getB_##name () {             \
    return 1 & (BX_CPU_THIS_PTR eflags >> bitnum);              \
  }                                                             \
  inline unsigned BX_CPU_C::get_##name () {              \
    return BX_CPU_THIS_PTR eflags & (1 << bitnum);              \
  }

#define IMPLEMENT_EFLAG_SET_ACCESSOR(name,bitnum)                   \
  inline void BX_CPU_C::assert_##name () {                   \
    BX_CPU_THIS_PTR eflags |= (1<<bitnum);                          \
  }                                                                 \
  inline void BX_CPU_C::clear_##name () {                    \
    BX_CPU_THIS_PTR eflags &= ~(1<<bitnum);                         \
  }                                                                 \
  inline void BX_CPU_C::set_##name (bool val) {              \
    BX_CPU_THIS_PTR eflags =                                        \
      (BX_CPU_THIS_PTR eflags&~(1<<bitnum))|(Bit32u(val)<<bitnum);   \
  }

#if BX_CPU_LEVEL >= 4

#define IMPLEMENT_EFLAG_SET_ACCESSOR_AC(bitnum)                 \
  inline void BX_CPU_C::assert_AC() {                    \
    BX_CPU_THIS_PTR eflags |= (1<<bitnum);                      \
    handleAlignmentCheck();                                     \
  }                                                             \
  inline void BX_CPU_C::clear_AC() {                     \
    BX_CPU_THIS_PTR eflags &= ~(1<<bitnum);                     \
    handleAlignmentCheck();                                     \
  }                                                             \
  inline void BX_CPU_C::set_AC(bool val) {                   \
    BX_CPU_THIS_PTR eflags =                                        \
      (BX_CPU_THIS_PTR eflags&~(1<<bitnum))|(Bit32u(val)<<bitnum);  \
    handleAlignmentCheck();                                         \
  }

#endif

#define IMPLEMENT_EFLAG_SET_ACCESSOR_VM(bitnum)                 \
  inline void BX_CPU_C::assert_VM() {                    \
    set_VM(1);                                                  \
  }                                                             \
  inline void BX_CPU_C::clear_VM() {                     \
    set_VM(0);                                                  \
  }                                                             \
  inline void BX_CPU_C::set_VM(bool val) {               \
    if (!long_mode()) {                                         \
      BX_CPU_THIS_PTR eflags =                                  \
        (BX_CPU_THIS_PTR eflags&~(1<<bitnum))|(Bit32u(val)<<bitnum);  \
      handleCpuModeChange();                                    \
    }                                                           \
  }

// need special handling when IF is set
#define IMPLEMENT_EFLAG_SET_ACCESSOR_IF(bitnum)                 \
  inline void BX_CPU_C::assert_IF() {                    \
    BX_CPU_THIS_PTR eflags |= (1<<bitnum);                      \
    handleInterruptMaskChange();                                \
  }                                                             \
  inline void BX_CPU_C::clear_IF() {                     \
    BX_CPU_THIS_PTR eflags &= ~(1<<bitnum);                     \
    handleInterruptMaskChange();                                \
  }                                                             \
  inline void BX_CPU_C::set_IF(bool val) {               \
    if (val) assert_IF();                                       \
    else clear_IF();                                            \
  }

// assert async_event when TF is set
#define IMPLEMENT_EFLAG_SET_ACCESSOR_TF(bitnum)                 \
  inline void BX_CPU_C::assert_TF() {                    \
    BX_CPU_THIS_PTR async_event = 1;                            \
    BX_CPU_THIS_PTR eflags |= (1<<bitnum);                      \
  }                                                             \
  inline void BX_CPU_C::clear_TF() {                     \
    BX_CPU_THIS_PTR eflags &= ~(1<<bitnum);                     \
  }                                                             \
  inline void BX_CPU_C::set_TF(bool val) {                   \
    if (val) BX_CPU_THIS_PTR async_event = 1;                       \
    BX_CPU_THIS_PTR eflags =                                        \
      (BX_CPU_THIS_PTR eflags&~(1<<bitnum))|(Bit32u(val)<<bitnum);  \
  }

// invalidate prefetch queue and call prefetch() when RF is set
#define IMPLEMENT_EFLAG_SET_ACCESSOR_RF(bitnum)                 \
  inline void BX_CPU_C::assert_RF() {                    \
    invalidate_prefetch_q();                                    \
    BX_CPU_THIS_PTR eflags |= (1<<bitnum);                      \
  }                                                             \
  inline void BX_CPU_C::clear_RF() {                     \
    BX_CPU_THIS_PTR eflags &= ~(1<<bitnum);                     \
  }                                                             \
  inline void BX_CPU_C::set_RF(bool val) {                   \
    if (val) invalidate_prefetch_q();                               \
    BX_CPU_THIS_PTR eflags =                                        \
      (BX_CPU_THIS_PTR eflags&~(1<<bitnum))|(Bit32u(val)<<bitnum);  \
  }

#define DECLARE_EFLAG_ACCESSOR_IOPL(bitnum)                     \
  inline void set_IOPL(Bit32u val);               \
  inline Bit32u  get_IOPL(void);

#define IMPLEMENT_EFLAG_ACCESSOR_IOPL(bitnum)                   \
  inline void BX_CPU_C::set_IOPL(Bit32u val) {           \
    BX_CPU_THIS_PTR eflags &= ~(3<<bitnum);                     \
    BX_CPU_THIS_PTR eflags |= ((3&val) << bitnum);              \
  }                                                             \
  inline Bit32u BX_CPU_C::get_IOPL() {                   \
    return 3 & (BX_CPU_THIS_PTR eflags >> bitnum);              \
  }

const Bit32u EFlagsCFMask = (1 << 0);
const Bit32u EFlagsPFMask = (1 << 2);
const Bit32u EFlagsAFMask = (1 << 4);
const Bit32u EFlagsZFMask = (1 << 6);
const Bit32u EFlagsSFMask = (1 << 7);
const Bit32u EFlagsTFMask = (1 << 8);
const Bit32u EFlagsIFMask = (1 << 9);
const Bit32u EFlagsDFMask = (1 << 10);
const Bit32u EFlagsOFMask = (1 << 11);
const Bit32u EFlagsIOPLMask = (3 << 12);
const Bit32u EFlagsNTMask = (1 << 14);
const Bit32u EFlagsRFMask = (1 << 16);
const Bit32u EFlagsVMMask = (1 << 17);
const Bit32u EFlagsACMask = (1 << 18);
const Bit32u EFlagsVIFMask = (1 << 19);
const Bit32u EFlagsVIPMask = (1 << 20);
const Bit32u EFlagsIDMask = (1 << 21);

const Bit32u EFlagsOSZAPCMask = \
(EFlagsCFMask | EFlagsPFMask | EFlagsAFMask | EFlagsZFMask | EFlagsSFMask | EFlagsOFMask);

const Bit32u EFlagsOSZAPMask = \
(EFlagsPFMask | EFlagsAFMask | EFlagsZFMask | EFlagsSFMask | EFlagsOFMask);

const Bit32u EFlagsValidMask = 0x003f7fd5; // only supported bits for EFLAGS

#if BX_SUPPORT_FPU
#include "i387.h"
#endif

#if BX_CPU_LEVEL >= 5
typedef struct
{
#if BX_SUPPORT_APIC
    bx_phy_address apicbase;
#endif

    // SYSCALL/SYSRET instruction msr's
    Bit64u star;
#if BX_SUPPORT_X86_64
    Bit64u lstar;
    Bit64u cstar;
    Bit32u fmask;
    Bit64u kernelgsbase;
    Bit32u tsc_aux;
#endif

#if BX_CPU_LEVEL >= 6
    // SYSENTER/SYSEXIT instruction msr's
    Bit32u sysenter_cs_msr;
    bx_address sysenter_esp_msr;
    bx_address sysenter_eip_msr;

    BxPackedRegister pat;
    Bit64u mtrrphys[16];
    BxPackedRegister mtrrfix64k;
    BxPackedRegister mtrrfix16k[2];
    BxPackedRegister mtrrfix4k[8];
    Bit32u mtrr_deftype;
#endif

#if BX_CPU_LEVEL >= 6
    Bit64u ia32_xss;
#endif

    // CET
#if BX_SUPPORT_CET
    Bit64u ia32_cet_control[2]; // indexed by CPL==3
    Bit64u ia32_pl_ssp[4];
    Bit64u ia32_interrupt_ssp_table;
#endif

    Bit32u ia32_spec_ctrl; // SCA

    /* TODO finish of the others */
} bx_regs_msr_t;
#endif

#include "crregs.h"
#include "descriptor.h"
#include "decoder/instr.h"
#include "lazy_flags.h"
#include "tlb.h"
#include "icache.h"

// general purpose register
#if BX_SUPPORT_X86_64

#ifdef BX_BIG_ENDIAN
typedef struct {
    union {
        struct {
            Bit32u dword_filler;
            Bit16u  word_filler;
            union {
                Bit16u rx;
                struct {
                    Bit8u rh;
                    Bit8u rl;
                } byte;
            };
        } word;
        Bit64u rrx;
        struct {
            Bit32u hrx;  // hi 32 bits
            Bit32u erx;  // lo 32 bits
        } dword;
    };
} bx_gen_reg_t;
#else
typedef struct {
    union {
        struct {
            union {
                Bit16u rx;
                struct {
                    Bit8u rl;
                    Bit8u rh;
                } byte;
            };
            Bit16u  word_filler;
            Bit32u dword_filler;
        } word;
        Bit64u rrx;
        struct {
            Bit32u erx;  // lo 32 bits
            Bit32u hrx;  // hi 32 bits
        } dword;
    };
} bx_gen_reg_t;

#endif

#else  // #if BX_SUPPORT_X86_64

#ifdef BX_BIG_ENDIAN
typedef struct {
    union {
        struct {
            Bit32u erx;
        } dword;
        struct {
            Bit16u word_filler;
            union {
                Bit16u rx;
                struct {
                    Bit8u rh;
                    Bit8u rl;
                } byte;
            };
        } word;
    };
} bx_gen_reg_t;
#else
typedef struct {
    union {
        struct {
            Bit32u erx;
        } dword;
        struct {
            union {
                Bit16u rx;
                struct {
                    Bit8u rl;
                    Bit8u rh;
                } byte;
            };
            Bit16u word_filler;
        } word;
    };
} bx_gen_reg_t;
#endif

#endif  // #if BX_SUPPORT_X86_64

#if BX_SUPPORT_APIC
#include "apic.h"
#endif

#if BX_SUPPORT_FPU
#include "xmm.h"
#endif

#if BX_SUPPORT_MONITOR_MWAIT
struct monitor_addr_t {

    bx_phy_address monitor_addr;
    bool armed;

    monitor_addr_t() : monitor_addr(0xffffffff), armed(false) {}

    inline void arm(bx_phy_address addr) {
        // align to cache line
        monitor_addr = addr & ~((bx_phy_address)(CACHE_LINE_SIZE - 1));
        armed = true;
    }

    inline void reset_monitor(void) { armed = false; }
};
#endif

struct BX_SMM_State;
struct BxOpcodeInfo_t;
struct bx_cpu_statistics;

#include "cpuid.h"

class BOCHSAPI BX_CPU_C {

public:

    unsigned bx_cpuid;

#if BX_CPU_LEVEL >= 4
    bx_cpuid_t* cpuid;
#endif

    Bit32u ia_extensions_bitmask[BX_ISA_EXTENSIONS_ARRAY_SIZE];

#define BX_CPUID_SUPPORT_ISA_EXTENSION(feature) \
   (BX_CPU_THIS_PTR ia_extensions_bitmask[feature/32] & (1<<(feature%32)))

    // General register set
    // rax: accumulator
    // rbx: base
    // rcx: count
    // rdx: data
    // rbp: base pointer
    // rsi: source index
    // rdi: destination index
    // esp: stack pointer
    // r8..r15 x86-64 extended registers
    // rip: instruction pointer
    // ssp: shadow stack pointer
    // tmp: temp register
    // nil: null register
    bx_gen_reg_t gen_reg[BX_GENERAL_REGISTERS + 4];

    /* 31|30|29|28| 27|26|25|24| 23|22|21|20| 19|18|17|16
     * ==|==|=====| ==|==|==|==| ==|==|==|==| ==|==|==|==
     *  0| 0| 0| 0|  0| 0| 0| 0|  0| 0|ID|VP| VF|AC|VM|RF
     *
     * 15|14|13|12| 11|10| 9| 8|  7| 6| 5| 4|  3| 2| 1| 0
     * ==|==|=====| ==|==|==|==| ==|==|==|==| ==|==|==|==
     *  0|NT| IOPL| OF|DF|IF|TF| SF|ZF| 0|AF|  0|PF| 1|CF
     */
    Bit32u eflags; // Raw 32-bit value in x86 bit position.

    // lazy arithmetic flags state
    bx_lazyflags_entry oszapc;

    // so that we can back up when handling faults, exceptions, etc.
    // we need to store the value of the instruction pointer, before
    // each fetch/execute cycle.
    bx_address prev_rip;
    bx_address prev_rsp;
    bool    speculative_rsp;

    Bit64u icount;
    Bit64u icount_last_sync;

#define BX_INHIBIT_INTERRUPTS        0x01
#define BX_INHIBIT_DEBUG             0x02

#define BX_INHIBIT_INTERRUPTS_BY_MOVSS        \
    (BX_INHIBIT_INTERRUPTS | BX_INHIBIT_DEBUG)

    // What events to inhibit at any given time.  Certain instructions
    // inhibit interrupts, some debug exceptions and single-step traps.
    unsigned inhibit_mask;
    Bit64u inhibit_icount;

    /* user segment register set */
    bx_segment_reg_t  sregs[6];

    /* system segment registers */
    bx_global_segment_reg_t gdtr; /* global descriptor table register */
    bx_global_segment_reg_t idtr; /* interrupt descriptor table register */
    bx_segment_reg_t        ldtr; /* local descriptor table register */
    bx_segment_reg_t        tr;   /* task register */

    /* debug registers DR0-DR7 */
    bx_address dr[4]; /* DR0-DR3 */
    bx_dr6_t   dr6;
    bx_dr7_t   dr7;

    Bit32u debug_trap; // holds DR6 value (16bit) to be set

    /* Control registers */
    bx_cr0_t   cr0;
    bx_address cr2;
    bx_address cr3;
#if BX_CPU_LEVEL >= 5
    bx_cr4_t   cr4;
    Bit32u cr4_suppmask;

    bx_efer_t efer;
    Bit32u efer_suppmask;
#endif

#if BX_CPU_LEVEL >= 5
    // TSC: Time Stamp Counter
    // Instead of storing a counter and incrementing it every instruction, we
    // remember the time in ticks that it was reset to zero.  With a little
    // algebra, we can also support setting it to something other than zero.
    // Don't read this directly; use get_TSC and set_TSC to access the TSC.
    Bit64s tsc_adjust;
#endif

#if BX_CPU_LEVEL >= 6
    xcr0_t xcr0;
    Bit32u xcr0_suppmask;
#endif

#if BX_SUPPORT_FPU
    i387_t the_i387;
#endif

#if BX_CPU_LEVEL >= 6

    // Vector register set
    // vmm0-vmmN: up to 32 vector registers
    // vtmp: temp register
#if BX_SUPPORT_EVEX
    bx_zmm_reg_t vmm[BX_XMM_REGISTERS + 1] BX_CPP_AlignN(64);
#else
#if BX_SUPPORT_AVX
    bx_ymm_reg_t vmm[BX_XMM_REGISTERS + 1] BX_CPP_AlignN(32);
#else
    bx_xmm_reg_t vmm[BX_XMM_REGISTERS + 1] BX_CPP_AlignN(16);
#endif
#endif

    bx_mxcsr_t mxcsr;
    Bit32u mxcsr_mask;

#if BX_SUPPORT_EVEX
    bx_gen_reg_t opmask[8];
#endif

#endif

#if BX_SUPPORT_MONITOR_MWAIT
    monitor_addr_t monitor;
#endif

    /* SMM base register */
    Bit32u smbase;

#if BX_CPU_LEVEL >= 5
    bx_regs_msr_t msr;
#endif

#if BX_CONFIGURE_MSRS
    MSR* msrs[BX_MSR_MAX_INDEX];
#endif

    bool EXT; /* 1 if processing external interrupt or exception
                  * or if not related to current instruction,
                  * 0 if current CS:IP caused exception */

    enum CPU_Activity_State {
        BX_ACTIVITY_STATE_ACTIVE = 0,
        BX_ACTIVITY_STATE_HLT,
        BX_ACTIVITY_STATE_SHUTDOWN,
        BX_ACTIVITY_STATE_WAIT_FOR_SIPI,
        BX_ACTIVITY_STATE_MWAIT,
        BX_ACTIVITY_STATE_MWAIT_IF
    };

    unsigned activity_state;

#define BX_EVENT_NMI                          (1 <<  0)
#define BX_EVENT_SMI                          (1 <<  1)
#define BX_EVENT_INIT                         (1 <<  2)
#define BX_EVENT_CODE_BREAKPOINT_ASSIST       (1 <<  3)
#define BX_EVENT_VMX_MONITOR_TRAP_FLAG        (1 <<  4)
#define BX_EVENT_VMX_PREEMPTION_TIMER_EXPIRED (1 <<  5)
#define BX_EVENT_VMX_INTERRUPT_WINDOW_EXITING (1 <<  6)
#define BX_EVENT_VMX_VIRTUAL_NMI              (1 <<  7)
#define BX_EVENT_SVM_VIRQ_PENDING             (1 <<  8)
#define BX_EVENT_PENDING_VMX_VIRTUAL_INTR     (1 <<  9)
#define BX_EVENT_PENDING_INTR                 (1 << 10)
#define BX_EVENT_PENDING_LAPIC_INTR           (1 << 11)
#define BX_EVENT_VMX_VTPR_UPDATE              (1 << 12)
#define BX_EVENT_VMX_VEOI_UPDATE              (1 << 13)
#define BX_EVENT_VMX_VIRTUAL_APIC_WRITE       (1 << 14)
    Bit32u  pending_event;
    Bit32u  event_mask;
    Bit32u  async_event; // keep 32-bit because of BX_ASYNC_EVENT_STOP_TRACE

    inline void signal_event(Bit32u event) {
        BX_CPU_THIS_PTR pending_event |= event;
        if (!is_masked_event(event)) BX_CPU_THIS_PTR async_event = 1;
    }

    inline void clear_event(Bit32u event) {
        BX_CPU_THIS_PTR pending_event &= ~event;
    }

    inline void mask_event(Bit32u event) {
        BX_CPU_THIS_PTR event_mask |= event;
    }
    inline void unmask_event(Bit32u event) {
        BX_CPU_THIS_PTR event_mask &= ~event;
        if (is_pending(event)) BX_CPU_THIS_PTR async_event = 1;
    }

    inline bool is_masked_event(Bit32u event) {
        return (BX_CPU_THIS_PTR event_mask & event) != 0;
    }

    inline bool is_pending(Bit32u event) {
        return (BX_CPU_THIS_PTR pending_event & event) != 0;
    }
    inline bool is_unmasked_event_pending(Bit32u event) {
        return (BX_CPU_THIS_PTR pending_event & ~BX_CPU_THIS_PTR event_mask & event) != 0;
    }

    inline Bit32u unmasked_events_pending(void) {
        return (BX_CPU_THIS_PTR pending_event & ~BX_CPU_THIS_PTR event_mask);
    }

#define BX_ASYNC_EVENT_STOP_TRACE (1<<31)

#if BX_X86_DEBUGGER
    bool  in_repeat;
#endif
    bool  in_smm;
    unsigned cpu_mode;
    bool  user_pl;
#if BX_CPU_LEVEL >= 5
    bool  ignore_bad_msrs;
#endif
#if BX_CPU_LEVEL >= 6
    unsigned sse_ok;
#if BX_SUPPORT_AVX
    unsigned avx_ok;
#endif
#if BX_SUPPORT_EVEX
    unsigned opmask_ok;
    unsigned evex_ok;
#endif
#endif

    // for exceptions
    static jmp_buf jmp_buf_env;
    unsigned last_exception_type;

    // Boundaries of current code page, based on EIP
    bx_address eipPageBias;
    Bit32u     eipPageWindowSize;
    const Bit8u* eipFetchPtr;
    bx_phy_address pAddrFetchPage; // Guest physical address of current instruction page

    // Boundaries of current stack page, based on ESP
    bx_address espPageBias;        // Linear address of current stack page
    Bit32u     espPageWindowSize;
    const Bit8u* espHostPtr;
    bx_phy_address pAddrStackPage; // Guest physical address of current stack page
#if BX_SUPPORT_MEMTYPE
    BxMemtype espPageMemtype;
#endif
#if BX_SUPPORT_SMP == 0
    Bit32u espPageFineGranularityMapping;
#endif

#if BX_CPU_LEVEL >= 4 && BX_SUPPORT_ALIGNMENT_CHECK
    unsigned alignment_check_mask;
#endif

    // statistics
    bx_cpu_statistics* stats;

#if BX_DEBUGGER
    bx_phy_address watchpoint;
    Bit8u break_point;
    Bit8u magic_break;
    Bit8u stop_reason;
    bool trace;
    bool trace_reg;
    bool trace_mem;
    bool mode_break;
    unsigned show_flag;
    bx_guard_found_t guard_found;
#endif

#if BX_INSTRUMENTATION
    // store far branch CS:EIP pair for instrumentation purposes
    // unfortunatelly prev_rip CPU field cannot be used as is because it
    // could be overwritten by task switch which could happen as result
    // of the far branch
    struct {
        Bit16u prev_cs;
        bx_address prev_rip;
    } far_branch;

#define FAR_BRANCH_PREV_CS (BX_CPU_THIS_PTR far_branch.prev_cs)
#define FAR_BRANCH_PREV_RIP (BX_CPU_THIS_PTR far_branch.prev_rip)

#define BX_INSTR_FAR_BRANCH_ORIGIN() { \
  BX_CPU_THIS_PTR far_branch.prev_cs = BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.value; \
  BX_CPU_THIS_PTR far_branch.prev_rip = PREV_RIP; \
}

#else
#define BX_INSTR_FAR_BRANCH_ORIGIN()
#endif

#define BX_DTLB_SIZE 2048
#define BX_ITLB_SIZE 1024
    TLB<BX_DTLB_SIZE> DTLB BX_CPP_AlignN(32);
    TLB<BX_ITLB_SIZE> ITLB BX_CPP_AlignN(32);

#if BX_CPU_LEVEL >= 6
    struct {
        Bit64u entry[4];
    } PDPTR_CACHE;
#endif

    // An instruction cache.  Each entry should be exactly 32 bytes, and
    // this structure should be aligned on a 32-byte boundary to be friendly
    // with the host cache lines.
    bxICache_c iCache BX_CPP_AlignN(32);
    Bit32u fetchModeMask;

    struct {
        bx_address rm_addr;       // The address offset after resolution
        bx_phy_address paddress1; // physical address after translation of 1st len1 bytes of data
        bx_phy_address paddress2; // physical address after translation of 2nd len2 bytes of data
        Bit32u len1;              // Number of bytes in page 1
        Bit32u len2;              // Number of bytes in page 2
        bx_ptr_equiv_t pages;     // Number of pages access spans (1 or 2).  Also used
                                  // for the case when a native host pointer is
                                  // available for the R-M-W instructions.  The host
                                  // pointer is stuffed here.  Since this field has
                                  // to be checked anyways (and thus cached), if it
                                  // is greated than 2 (the maximum possible for
                                  // normal cases) it is a native pointer and is used
                                  // for a direct write access.
#if BX_SUPPORT_MEMTYPE
        BxMemtype memtype1;       // memory type of the page 1
        BxMemtype memtype2;       // memory type of the page 2
#endif
    } address_xlation;

    void setEFlags(Bit32u val) BX_CPP_AttrRegparmN(1);

    inline void setEFlagsOSZAPC(Bit32u flags32) {
        set_OF(1 & ((flags32) >> 11));
        set_SF(1 & ((flags32) >> 7));
        set_ZF(1 & ((flags32) >> 6));
        set_AF(1 & ((flags32) >> 4));
        set_PF(1 & ((flags32) >> 2));
        set_CF(1 & ((flags32) >> 0));
    }

    inline void clearEFlagsOSZAPC(void) {
        SET_FLAGS_OSZAPC_LOGIC_32(1);
    }

    inline unsigned getB_OF(void) { return BX_CPU_THIS_PTR oszapc.getB_OF(); }
    inline unsigned get_OF(void) { return BX_CPU_THIS_PTR oszapc.get_OF(); }
    inline void set_OF(bool val) { BX_CPU_THIS_PTR oszapc.set_OF(val); }
    inline void clear_OF(void) { BX_CPU_THIS_PTR oszapc.clear_OF(); }
    inline void assert_OF(void) { BX_CPU_THIS_PTR oszapc.assert_OF(); }

    inline unsigned getB_SF(void) { return BX_CPU_THIS_PTR oszapc.getB_SF(); }
    inline unsigned get_SF(void) { return BX_CPU_THIS_PTR oszapc.get_SF(); }
    inline void set_SF(bool val) { BX_CPU_THIS_PTR oszapc.set_SF(val); }
    inline void clear_SF(void) { BX_CPU_THIS_PTR oszapc.clear_SF(); }
    inline void assert_SF(void) { BX_CPU_THIS_PTR oszapc.assert_SF(); }

    inline unsigned getB_ZF(void) { return BX_CPU_THIS_PTR oszapc.getB_ZF(); }
    inline unsigned get_ZF(void) { return BX_CPU_THIS_PTR oszapc.get_ZF(); }
    inline void set_ZF(bool val) { BX_CPU_THIS_PTR oszapc.set_ZF(val); }
    inline void clear_ZF(void) { BX_CPU_THIS_PTR oszapc.clear_ZF(); }
    inline void assert_ZF(void) { BX_CPU_THIS_PTR oszapc.assert_ZF(); }

    inline unsigned getB_AF(void) { return BX_CPU_THIS_PTR oszapc.getB_AF(); }
    inline unsigned get_AF(void) { return BX_CPU_THIS_PTR oszapc.get_AF(); }
    inline void set_AF(bool val) { BX_CPU_THIS_PTR oszapc.set_AF(val); }
    inline void clear_AF(void) { BX_CPU_THIS_PTR oszapc.clear_AF(); }
    inline void assert_AF(void) { BX_CPU_THIS_PTR oszapc.assert_AF(); }

    inline unsigned getB_PF(void) { return BX_CPU_THIS_PTR oszapc.getB_PF(); }
    inline unsigned get_PF(void) { return BX_CPU_THIS_PTR oszapc.get_PF(); }
    inline void set_PF(bool val) { BX_CPU_THIS_PTR oszapc.set_PF(val); }
    inline void clear_PF(void) { BX_CPU_THIS_PTR oszapc.clear_PF(); }
    inline void assert_PF(void) { BX_CPU_THIS_PTR oszapc.assert_PF(); }

    inline unsigned getB_CF(void) { return BX_CPU_THIS_PTR oszapc.getB_CF(); }
    inline unsigned get_CF(void) { return BX_CPU_THIS_PTR oszapc.get_CF(); }
    inline void set_CF(bool val) { BX_CPU_THIS_PTR oszapc.set_CF(val); }
    inline void clear_CF(void) { BX_CPU_THIS_PTR oszapc.clear_CF(); }
    inline void assert_CF(void) { BX_CPU_THIS_PTR oszapc.assert_CF(); }

    // constructors & destructors...
    BX_CPU_C(unsigned id = 0);
    ~BX_CPU_C();

    void initialize(void);
    void enable_paging(bx_phy_address page_table);

    // <TAG-CLASS-CPU-START>
      // prototypes for CPU instructions...
    void PUSH16_Sw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void POP16_Sw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUSH32_Sw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void POP32_Sw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void DAA(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DAS(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AAA(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AAS(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AAM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AAD(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void PUSHA32(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUSHA16(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void POPA32(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void POPA16(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ARPL_EwGw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUSH_Id(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUSH_Iw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void INSB32_YbDX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void INSB16_YbDX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void INSW32_YwDX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void INSW16_YwDX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void INSD32_YdDX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void INSD16_YdDX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OUTSB32_DXXb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OUTSB16_DXXb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OUTSW32_DXXw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OUTSW16_DXXw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OUTSD32_DXXd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OUTSD16_DXXd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void REP_INSB_YbDX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_INSW_YwDX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_INSD_YdDX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_OUTSB_DXXb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_OUTSW_DXXw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_OUTSD_DXXd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void BOUND_GwMa(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BOUND_GdMa(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void TEST_EbGbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void TEST_EwGwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void TEST_EdGdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void TEST_EbGbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void TEST_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void TEST_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void XCHG_EbGbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XCHG_EwGwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XCHG_EdGdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void XCHG_EbGbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XCHG_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XCHG_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOV_EbGbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_GbEbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_GbEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_GwEwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOV32_GdEdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV32_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOV32S_GdEdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV32S_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOV_EwSwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_EwSwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_SwEw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void LEA_GdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LEA_GwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void CBW(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CWD(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CALL32_Ap(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CALL16_Ap(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUSHF_Fw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void POPF_Fw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUSHF_Fd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void POPF_Fd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SAHF(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LAHF(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOV_ALOd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_EAXOd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_AXOd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_OdAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_OdEAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_OdAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    // repeatable instructions
    void REP_MOVSB_YbXb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_MOVSW_YwXw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_MOVSD_YdXd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_CMPSB_XbYb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_CMPSW_XwYw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_CMPSD_XdYd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_STOSB_YbAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_LODSB_ALXb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_SCASB_ALYb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_STOSW_YwAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_LODSW_AXXw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_SCASW_AXYw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_STOSD_YdEAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_LODSD_EAXXd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_SCASD_EAXYd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    // qualified by address size
    void CMPSB16_XbYb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPSW16_XwYw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPSD16_XdYd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPSB32_XbYb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPSW32_XwYw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPSD32_XdYd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void SCASB16_ALYb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SCASW16_AXYw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SCASD16_EAXYd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SCASB32_ALYb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SCASW32_AXYw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SCASD32_EAXYd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void LODSB16_ALXb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LODSW16_AXXw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LODSD16_EAXXd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LODSB32_ALXb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LODSW32_AXXw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LODSD32_EAXXd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void STOSB16_YbAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void STOSW16_YwAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void STOSD16_YdEAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void STOSB32_YbAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void STOSW32_YwAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void STOSD32_YdEAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOVSB16_YbXb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSW16_YwXw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSD16_YdXd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSB32_YbXb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSW32_YwXw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSD32_YdXd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOV_EdIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_EwIwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_EbIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ENTER16_IwIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ENTER32_IwIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LEAVE16(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LEAVE32(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void INT1(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void INT3(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void INT_Ib(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void INTO(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IRET32(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IRET16(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void SALC(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XLAT(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void LOOPNE16_Jb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOOPE16_Jb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOOP16_Jb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOOPNE32_Jb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOOPE32_Jb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOOP32_Jb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JCXZ_Jb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JECXZ_Jb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IN_ALIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IN_AXIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IN_EAXIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OUT_IbAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OUT_IbAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OUT_IbEAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CALL_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CALL_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JMP_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JMP_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JMP_Ap(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IN_ALDX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IN_AXDX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IN_EAXDX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OUT_DXAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OUT_DXAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OUT_DXEAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void HLT(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMC(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CLC(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void STC(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CLI(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void STI(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CLD(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void STD(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void LAR_GvEw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LSL_GvEw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CLTS(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void INVD(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void WBINVD(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CLFLUSH(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CLZERO(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOV_CR0Rd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_CR2Rd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_CR3Rd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_CR4Rd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_RdCR0(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_RdCR2(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_RdCR3(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_RdCR4(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_DdRd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_RdDd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void JO_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNO_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JB_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNB_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JZ_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNZ_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JBE_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNBE_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JS_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNS_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JP_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNP_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JL_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNL_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JLE_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNLE_Jw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void JO_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNO_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JB_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNB_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JZ_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNZ_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JBE_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNBE_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JS_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNS_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JP_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNP_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JL_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNL_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JLE_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNLE_Jd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void SETO_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETNO_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETB_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETNB_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETZ_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETNZ_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETBE_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETNBE_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETS_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETNS_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETP_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETNP_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETL_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETNL_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETLE_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETNLE_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void SETO_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETNO_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETB_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETNB_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETZ_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETNZ_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETBE_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETNBE_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETS_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETNS_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETP_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETNP_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETL_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETNL_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETLE_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SETNLE_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void CPUID(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void SHRD_EwGwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHRD_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHLD_EwGwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHLD_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHRD_EdGdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHRD_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHLD_EdGdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHLD_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void BSF_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BSF_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BSR_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BSR_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void BT_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BT_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTS_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTS_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTR_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTR_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTC_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTC_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void BT_EwGwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BT_EdGdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTS_EwGwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTS_EdGdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTR_EwGwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTR_EdGdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTC_EwGwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTC_EdGdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void BT_EwIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BT_EdIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTS_EwIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTS_EdIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTR_EwIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTR_EdIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTC_EwIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTC_EdIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void BT_EwIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BT_EdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTS_EwIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTS_EdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTR_EwIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTR_EdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTC_EwIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTC_EdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void LES_GwMp(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LDS_GwMp(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LSS_GwMp(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LFS_GwMp(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LGS_GwMp(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LES_GdMp(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LDS_GdMp(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LSS_GdMp(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LFS_GdMp(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LGS_GdMp(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOVZX_GwEbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVZX_GdEbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVZX_GdEwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSX_GwEbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSX_GdEbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSX_GdEwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOVZX_GwEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVZX_GdEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVZX_GdEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSX_GwEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSX_GdEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSX_GdEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void BSWAP_RX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BSWAP_ERX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ZERO_IDIOM_GwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ZERO_IDIOM_GdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_GbEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_GbEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_GbEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_GbEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_GbEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_GbEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_GbEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_GbEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_GbEbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_GbEbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_GbEbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_GbEbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_GbEbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_GbEbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_GbEbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_GbEbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_EbIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_EbIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_EbIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_EbIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_EbIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_EbIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_EbIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_EbIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_EbIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_EbIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_EbIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_EbIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_EbIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_EbIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_EbIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_EbIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_EbGbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_EbGbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_EbGbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_EbGbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_EbGbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_EbGbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_EbGbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_EbGbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_EwIwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_EwIwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_EwIwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_EwIwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_EwIwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_EwIwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_EwIwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_EwIwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_EwIwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_EwIwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_EwIwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_EwIwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_EwIwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_EwIwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_EwIwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_EwIwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_EdIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_EdIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_EdIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_EdIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_EdIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_EdIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_EdIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_EdIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_EdIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_EdIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_EdIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_EdIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_EdIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_EdIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_EdIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_EdIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_GwEwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_GwEwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_GwEwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_GwEwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_GwEwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_GwEwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_GwEwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_GwEwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_GdEdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_GdEdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_GdEdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_GdEdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_GdEdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_GdEdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_GdEdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_GdEdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void NOT_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void NOT_EwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void NOT_EdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void NOT_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void NOT_EwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void NOT_EdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void NEG_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void NEG_EwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void NEG_EdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void NEG_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void NEG_EwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void NEG_EdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ROL_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ROR_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCL_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCR_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHL_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHR_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SAR_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ROL_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ROR_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCL_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCR_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHL_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHR_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SAR_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ROL_EwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ROR_EwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCL_EwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCR_EwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHL_EwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHR_EwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SAR_EwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ROL_EwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ROR_EwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCL_EwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCR_EwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHL_EwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHR_EwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SAR_EwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ROL_EdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ROR_EdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCL_EdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCR_EdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHL_EdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHR_EdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SAR_EdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ROL_EdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ROR_EdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCL_EdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCR_EdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHL_EdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHR_EdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SAR_EdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void TEST_EbIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void TEST_EwIwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void TEST_EdIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void TEST_EbIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void TEST_EwIwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void TEST_EdIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void IMUL_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IMUL_GdEdIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MUL_ALEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IMUL_ALEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DIV_ALEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IDIV_ALEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MUL_EAXEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IMUL_EAXEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DIV_EAXEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IDIV_EAXEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void INC_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void INC_EwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void INC_EdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DEC_EbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DEC_EwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DEC_EdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void INC_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void INC_EwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void INC_EdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DEC_EbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DEC_EwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DEC_EdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void CALL_EdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CALL_EwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void CALL32_Ep(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CALL16_Ep(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JMP32_Ep(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JMP16_Ep(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void JMP_EdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JMP_EwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void SLDT_Ew(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void STR_Ew(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LLDT_Ew(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LTR_Ew(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VERR_Ew(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VERW_Ew(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void SGDT_Ms(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SIDT_Ms(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LGDT_Ms(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LIDT_Ms(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SMSW_EwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SMSW_EwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LMSW_Ew(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    // LOAD methods
    void LOAD_Eb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_Ew(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_Ed(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
    void LOAD_Eq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif
    void LOADU_Wdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_Wdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_Wss(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_Wsd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_Ww(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_Wb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_AVX
    void LOAD_Vector(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_Half_Vector(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_Quarter_Vector(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_Eighth_Vector(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif
#if BX_SUPPORT_EVEX
    void LOAD_MASK_Wss(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void LOAD_MASK_Wsd(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void LOAD_MASK_VectorB(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_MASK_VectorW(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_MASK_VectorD(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_MASK_VectorQ(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_BROADCAST_VectorD(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_BROADCAST_MASK_VectorD(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_BROADCAST_VectorQ(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_BROADCAST_MASK_VectorQ(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_BROADCAST_Half_VectorD(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOAD_BROADCAST_MASK_Half_VectorD(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif

#if BX_SUPPORT_FPU == 0	// if FPU is disabled
    void FPU_ESC(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif

    void FWAIT(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

#if BX_SUPPORT_FPU
    // load/store
    void FLD_STi(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FLD_SINGLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FLD_DOUBLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FLD_EXTENDED_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FILD_WORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FILD_DWORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FILD_QWORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FBLD_PACKED_BCD(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void FST_STi(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FST_SINGLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FST_DOUBLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FSTP_EXTENDED_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FIST_WORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FIST_DWORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FISTP_QWORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FBSTP_PACKED_BCD(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void FISTTP16(bxInstruction_c*) BX_CPP_AttrRegparmN(1); // SSE3
    void FISTTP32(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FISTTP64(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    // control
    void FNINIT(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FNCLEX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void FRSTOR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FNSAVE(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FLDENV(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FNSTENV(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void FLDCW(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FNSTCW(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FNSTSW(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FNSTSW_AX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    // const
    void FLD1(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FLDL2T(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FLDL2E(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FLDPI(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FLDLG2(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FLDLN2(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FLDZ(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    // add
    void FADD_ST0_STj(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FADD_STi_ST0(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FADD_SINGLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FADD_DOUBLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FIADD_WORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FIADD_DWORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    // mul
    void FMUL_ST0_STj(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FMUL_STi_ST0(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FMUL_SINGLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FMUL_DOUBLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FIMUL_WORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FIMUL_DWORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    // sub
    void FSUB_ST0_STj(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FSUBR_ST0_STj(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FSUB_STi_ST0(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FSUBR_STi_ST0(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FSUB_SINGLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FSUBR_SINGLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FSUB_DOUBLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FSUBR_DOUBLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void FISUB_WORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FISUBR_WORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FISUB_DWORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FISUBR_DWORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    // div
    void FDIV_ST0_STj(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FDIVR_ST0_STj(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FDIV_STi_ST0(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FDIVR_STi_ST0(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FDIV_SINGLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FDIVR_SINGLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FDIV_DOUBLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FDIVR_DOUBLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void FIDIV_WORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FIDIVR_WORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FIDIV_DWORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FIDIVR_DWORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    // compare
    void FCOM_STi(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FUCOM_STi(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FCOMI_ST0_STj(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FUCOMI_ST0_STj(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FCOM_SINGLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FCOM_DOUBLE_REAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FICOM_WORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FICOM_DWORD_INTEGER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void FCOMPP(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FUCOMPP(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void FCMOVB_ST0_STj(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FCMOVE_ST0_STj(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FCMOVBE_ST0_STj(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FCMOVU_ST0_STj(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FCMOVNB_ST0_STj(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FCMOVNE_ST0_STj(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FCMOVNBE_ST0_STj(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FCMOVNU_ST0_STj(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    // misc
    void FXCH_STi(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FNOP(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FPLEGACY(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FCHS(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FABS(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FTST(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FXAM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FDECSTP(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FINCSTP(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FFREE_STi(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FFREEP_STi(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void F2XM1(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FYL2X(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FPTAN(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FPATAN(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FXTRACT(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FPREM1(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FPREM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FYL2XP1(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FSQRT(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FSINCOS(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FRNDINT(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#undef FSCALE            // <sys/param.h> is #included on Mac OS X from bochs.h
    void FSCALE(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FSIN(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FCOS(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif

    /* MMX */
    void PUNPCKLBW_PqQd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUNPCKLWD_PqQd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUNPCKLDQ_PqQd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PACKSSWB_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCMPGTB_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCMPGTW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCMPGTD_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PACKUSWB_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUNPCKHBW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUNPCKHWD_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUNPCKHDQ_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PACKSSDW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVD_PqEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVD_PqEdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVQ_PqQqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVQ_PqQqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCMPEQB_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCMPEQW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCMPEQD_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void EMMS(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVD_EdPqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVD_EdPqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVQ_QqPqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRLW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRLD_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRLQ_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMULLW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSUBUSB_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSUBUSW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PAND_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PADDUSB_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PADDUSW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PANDN_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRAW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRAD_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMULHW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSUBSB_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSUBSW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void POR_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PADDSB_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PADDSW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PXOR_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSLLW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSLLD_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSLLQ_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMADDWD_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSUBB_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSUBW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSUBD_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PADDB_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PADDW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PADDD_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRLW_NqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRAW_NqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSLLW_NqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRLD_NqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRAD_NqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSLLD_NqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRLQ_NqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSLLQ_NqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* MMX */

#if BX_SUPPORT_3DNOW
    void PFPNACC_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PI2FW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PI2FD_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PF2IW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PF2ID_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PFNACC_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PFCMPGE_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PFMIN_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PFRCP_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PFRSQRT_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PFSUB_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PFADD_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PFCMPGT_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PFMAX_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PFRCPIT1_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PFRSQIT1_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PFSUBR_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PFACC_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PFCMPEQ_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PFMUL_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PFRCPIT2_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMULHRW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSWAPD_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif

    void SYSCALL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SYSRET(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    /* SSE */
    void FXSAVE(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void FXRSTOR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LDMXCSR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void STMXCSR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PREFETCH(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* SSE */

    /* SSE */
    void ANDPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ORPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XORPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ANDNPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVUPS_VpsWpsM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVUPS_WpsVpsM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSS_VssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSS_VssWssM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSS_WssVssM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSD_VsdWsdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSD_WsdVsdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVHLPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVLPS_VpsMq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVLHPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVHPS_VpsMq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVHPS_MqVps(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVAPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVAPS_VpsWpsM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVAPS_WpsVpsM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTPI2PS_VpsQqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTPI2PS_VpsQqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTSI2SS_VssEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTTPS2PI_PqWps(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTTSS2SI_GdWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTPS2PI_PqWps(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTSS2SI_GdWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void UCOMISS_VssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void COMISS_VssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVMSKPS_GdUps(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SQRTPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SQRTSS_VssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RSQRTPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RSQRTSS_VssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCPPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCPSS_VssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADDPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADDSS_VssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MULPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MULSS_VssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUBPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUBSS_VssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MINPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MINSS_VssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DIVPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DIVSS_VssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MAXPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MAXSS_VssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSHUFW_PqQqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSHUFLW_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPPS_VpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPSS_VssWssIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PINSRW_PqEwIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PEXTRW_GdNqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHUFPS_VpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMOVMSKB_GdNq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMINUB_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMAXUB_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PAVGB_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PAVGW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMULHUW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMINSW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMAXSW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSADBW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MASKMOVQ_PqNq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* SSE */

    /* SSE2 */
    void MOVSD_VsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTPI2PD_VpdQqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTPI2PD_VpdQqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTSI2SD_VsdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTTPD2PI_PqWpd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTTSD2SI_GdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTPD2PI_PqWpd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTSD2SI_GdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void UCOMISD_VsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void COMISD_VsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVMSKPD_GdUpd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SQRTPD_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SQRTSD_VsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADDPD_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADDSD_VsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MULPD_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MULSD_VsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUBPD_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUBSD_VsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTPS2PD_VpdWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTPD2PS_VpsWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTSD2SS_VssWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTSS2SD_VsdWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTDQ2PS_VpsWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTPS2DQ_VdqWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTTPS2DQ_VdqWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MINPD_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MINSD_VsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DIVPD_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DIVSD_VsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MAXPD_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MAXSD_VsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUNPCKLBW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUNPCKLWD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void UNPCKLPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PACKSSWB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCMPGTB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCMPGTW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCMPGTD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PACKUSWB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUNPCKHBW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUNPCKHWD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void UNPCKHPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PACKSSDW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUNPCKLQDQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUNPCKHQDQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVD_VdqEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSHUFD_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSHUFHW_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCMPEQB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCMPEQW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCMPEQD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVD_EdVdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVQ_VqWqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPPD_VpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPSD_VsdWsdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PINSRW_VdqEwIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PINSRW_VdqEwIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PEXTRW_GdUdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHUFPD_VpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRLW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRLD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRLQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PADDQ_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PADDQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMULLW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVDQ2Q_PqUdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVQ2DQ_VdqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMOVMSKB_GdUdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSUBUSB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSUBUSW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMINUB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PADDUSB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PADDUSW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMAXUB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PAVGB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRAW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRAD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PAVGW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMULHUW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMULHW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTTPD2DQ_VqWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTPD2DQ_VqWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTDQ2PD_VpdWqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSUBSB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSUBSW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMINSW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PADDSB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PADDSW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMAXSW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSLLW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSLLD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSLLQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMULUDQ_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMULUDQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMADDWD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSADBW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MASKMOVDQU_VdqUdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSUBB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSUBW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSUBD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSUBQ_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSUBQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PADDB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PADDW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PADDD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRLW_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRLD_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRLQ_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRAW_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRAD_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSLLW_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSLLD_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSLLQ_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSRLDQ_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSLLDQ_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* SSE2 */

    /* SSE3 */
    void MOVDDUP_VpdWqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSLDUP_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSHDUP_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void HADDPD_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void HADDPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void HSUBPD_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void HSUBPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADDSUBPD_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADDSUBPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* SSE3 */

#if BX_CPU_LEVEL >= 6
  /* SSSE3 */
    void PSHUFB_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PHADDW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PHADDD_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PHADDSW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMADDUBSW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PHSUBSW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PHSUBW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PHSUBD_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSIGNB_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSIGNW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSIGND_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMULHRSW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PABSB_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PABSW_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PABSD_PqQq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PALIGNR_PqQqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void PSHUFB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PHADDW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PHADDD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PHADDSW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMADDUBSW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PHSUBSW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PHSUBW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PHSUBD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSIGNB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSIGNW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PSIGND_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMULHRSW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PABSB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PABSW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PABSD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PALIGNR_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* SSSE3 */

    /* SSE4.1 */
    void PBLENDVB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLENDVPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLENDVPD_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PTEST_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMULDQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCMPEQQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PACKUSDW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMOVSXBW_VdqWqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMOVSXBD_VdqWdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMOVSXBQ_VdqWwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMOVSXWD_VdqWqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMOVSXWQ_VdqWdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMOVSXDQ_VdqWqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMOVZXBW_VdqWqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMOVZXBD_VdqWdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMOVZXBQ_VdqWwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMOVZXWD_VdqWqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMOVZXWQ_VdqWdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMOVZXDQ_VdqWqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMINSB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMINSD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMINUW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMINUD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMAXSB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMAXSD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMAXUW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMAXUD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PMULLD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PHMINPOSUW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ROUNDPS_VpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ROUNDPD_VpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ROUNDSS_VssWssIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ROUNDSD_VsdWsdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLENDPS_VpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLENDPD_VpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PBLENDW_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PEXTRB_EbdVdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PEXTRB_EbdVdqIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PEXTRW_EwdVdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PEXTRW_EwdVdqIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PEXTRD_EdVdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PEXTRD_EdVdqIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
    void PEXTRQ_EqVdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PEXTRQ_EqVdqIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif
    void PINSRB_VdqEbIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PINSRB_VdqEbIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PINSRD_VdqEdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PINSRD_VdqEdIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
    void PINSRQ_VdqEqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PINSRQ_VdqEqIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif
    void DPPS_VpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DPPD_VpdHpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MPSADBW_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void INSERTPS_VpsWssIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void INSERTPS_VpsWssIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* SSE4.1 */

    /* SSE4.2 */
    void CRC32_GdEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CRC32_GdEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CRC32_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
    void CRC32_GdEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif
    void PCMPGTQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCMPESTRM_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCMPESTRI_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCMPISTRM_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCMPISTRI_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* SSE4.2 */

    /* MOVBE Intel Atom(R) instruction */
    void MOVBE_GwMw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVBE_GdMd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVBE_MwGw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVBE_MdGd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
    void MOVBE_GqMq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVBE_MqGq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif
    /* MOVBE Intel Atom(R) instruction */
#endif

  /* XSAVE/XRSTOR extensions */
    void XSAVE(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XSAVEC(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XRSTOR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XGETBV(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XSETBV(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* XSAVE/XRSTOR extensions */

#if BX_CPU_LEVEL >= 6
  /* AES instructions */
    void AESIMC_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AESKEYGENASSIST_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AESENC_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AESENCLAST_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AESDEC_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AESDECLAST_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PCLMULQDQ_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* AES instructions */

    /* SHA instructions */
    void SHA1NEXTE_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHA1MSG1_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHA1MSG2_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHA256RNDS2_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHA256MSG1_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHA256MSG2_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHA1RNDS4_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* SHA instructions */

    /* GFNI instructions */
    void GF2P8AFFINEINVQB_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void GF2P8AFFINEQB_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void GF2P8MULB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* GFNI instructions */
#endif

  /* SMX instructions */
    void GETSEC(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* SMX instructions */

#if BX_SUPPORT_AVX
  /* AVX */
    void VZEROUPPER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VZEROALL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VMOVSS_VssHpsWssR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VMOVSD_VsdHpdWsdR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VMOVAPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVAPS_VpsWpsM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVUPS_VpsWpsM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVAPS_WpsVpsM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVUPS_WpsVpsM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVLPD_VpdHpdMq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVHPD_VpdHpdMq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVLHPS_VpsHpsWps(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVHLPS_VpsHpsWps(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVSHDUP_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVSLDUP_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVDDUP_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VUNPCKLPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VUNPCKHPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VUNPCKLPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VUNPCKHPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVMSKPS_GdUps(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVMSKPD_GdUpd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVMSKB_GdUdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSQRTPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSQRTPD_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSQRTSS_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSQRTSD_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VHADDPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VHADDPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VHSUBPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VHSUBPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VADDPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VADDPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VADDSS_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VADDSD_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMULPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMULPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMULSS_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMULSD_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSUBPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSUBPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSUBSS_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSUBSD_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTSS2SD_VsdWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTSD2SS_VssWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTDQ2PS_VpsWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTPS2DQ_VdqWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTTPS2DQ_VdqWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTPS2PD_VpdWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTPD2PS_VpsWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTPD2DQ_VdqWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTDQ2PD_VpdWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTTPD2DQ_VdqWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTSI2SD_VsdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTSI2SS_VssEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTSI2SD_VsdEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTSI2SS_VssEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMINPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMINPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMINSS_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMINSD_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VDIVPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VDIVPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VDIVSS_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VDIVSD_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMAXPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMAXPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMAXSS_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMAXSD_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCMPPS_VpsHpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCMPSS_VssHpsWssIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCMPPD_VpdHpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCMPSD_VsdHpdWsdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VADDSUBPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VADDSUBPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VROUNDPS_VpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VROUNDPD_VpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VROUNDSS_VssHpsWssIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VROUNDSD_VsdHpdWsdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VDPPS_VpsHpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VRSQRTPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VRSQRTSS_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VRCPPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VRCPSS_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSHUFPS_VpsHpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSHUFPD_VpdHpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VBLENDPS_VpsHpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VBLENDPD_VpdHpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBLENDVB_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPTEST_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VTESTPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VTESTPD_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VANDPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VANDNPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VORPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VXORPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VBROADCASTF128_VdqMdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VBLENDVPS_VpsHpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VBLENDVPD_VpdHpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VINSERTF128_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VEXTRACTF128_WdqVdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VEXTRACTF128_WdqVdqIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMILPS_VpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMILPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMILPD_VpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMILPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERM2F128_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMASKMOVPS_VpsHpsMps(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMASKMOVPD_VpdHpdMpd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMASKMOVPS_MpsHpsVps(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMASKMOVPD_MpdHpdVpd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPINSRB_VdqHdqEbIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPINSRB_VdqHdqEbIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPINSRW_VdqHdqEwIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPINSRW_VdqHdqEwIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPINSRD_VdqHdqEdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPINSRD_VdqHdqEdIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPINSRQ_VdqHdqEqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPINSRQ_VdqHdqEqIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VINSERTPS_VpsHpsWssIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VINSERTPS_VpsHpsWssIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VCVTPH2PS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTPS2PH_WpsVpsIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* AVX */

    /* AVX2 */
    void VPCMPEQB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPEQW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPEQD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPEQQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPGTB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPGTW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPGTD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPGTQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMINSB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMINSW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMINSD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMINSQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMINUB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMINUW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMINUD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMINUQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMAXSB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMAXSW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMAXSD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMAXSQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMAXUB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMAXUW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMAXUD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMAXUQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSIGNB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSIGNW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSIGND_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPADDB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPADDW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPADDD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPADDQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSUBB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSUBW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSUBD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSUBQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPABSB_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPABSW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPABSD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPABSQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSUBSB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSUBSW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSUBUSB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSUBUSW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPADDSB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPADDSW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPADDUSB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPADDUSW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPAVGB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPAVGW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHADDW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHADDD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHADDSW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHSUBW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHSUBD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHSUBSW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHUFHW_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHUFLW_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPACKUSWB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPACKSSWB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPACKUSDW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPACKSSDW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPUNPCKLBW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPUNPCKHBW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPUNPCKLWD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPUNPCKHWD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMULLQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMULLD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMULLW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMULHW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMULHUW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMULDQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMULUDQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMULHRSW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMADDUBSW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMADDWD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMPSADBW_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBLENDW_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSADBW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHUFB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRAW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRAD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRAQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLW_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLD_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLQ_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLW_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLD_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLQ_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRAW_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRAD_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRAQ_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPROLD_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPROLQ_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPRORD_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPRORQ_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLDQ_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLDQ_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPALIGNR_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMOVSXBW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSXBD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSXBQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSXWD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSXWQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSXDQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMOVZXBW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVZXBD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVZXBQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVZXWD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVZXWQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVZXDQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPERMD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMQ_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPSRAVW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRAVD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRAVQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLVW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLVD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLVQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLVW_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLVD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLVQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPROLVD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPROLVQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPRORVD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPRORVQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPBROADCASTB_VdqWbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTW_VdqWwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTD_VdqWdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTQ_VdqWqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VGATHERDPS_VpsHps(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VGATHERQPS_VpsHps(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VGATHERDPD_VpdHpd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VGATHERQPD_VpdHpd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* AVX2 */

    /* AVX2 FMA */
    void VFMADDPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMADDPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMADDSD_VpdHsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMADDSS_VpsHssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMADDSUBPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMADDSUBPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMSUBADDPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMSUBADDPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMSUBPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMSUBPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMSUBSD_VpdHsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMSUBSS_VpsHssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMADDPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMADDPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMADDSD_VpdHsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMADDSS_VpsHssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMSUBPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMSUBPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMSUBSD_VpdHsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMSUBSS_VpsHssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* AVX2 FMA */

    /* BMI */
    void ANDN_GdBdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MULX_GdBdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLSI_BdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLSMSK_BdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLSR_BdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RORX_GdEdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHLX_GdEdBdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHRX_GdEdBdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SARX_GdEdBdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BEXTR_GdEdBdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BZHI_GdEdBdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PEXT_GdBdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PDEP_GdBdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ANDN_GqBqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MULX_GqBqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLSI_BqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLSMSK_BqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLSR_BqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RORX_GqEqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHLX_GqEqBqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHRX_GqEqBqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SARX_GqEqBqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BEXTR_GqEqBqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BZHI_GqEqBqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PEXT_GqBqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PDEP_GqBqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* BMI */

    /* CMPccXADD */
    void CMPBEXADD_EdGdBd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPBEXADD_EqGqBq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPBXADD_EdGdBd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPBXADD_EqGqBq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPLEXADD_EdGdBd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPLEXADD_EqGqBq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPLXADD_EdGdBd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPLXADD_EqGqBq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPNBEXADD_EdGdBd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPNBEXADD_EqGqBq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPNBXADD_EdGdBd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPNBXADD_EqGqBq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPNLEXADD_EdGdBd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPNLEXADD_EqGqBq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPNLXADD_EdGdBd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPNLXADD_EqGqBq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPNOXADD_EdGdBd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPNOXADD_EqGqBq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPNPXADD_EdGdBd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPNPXADD_EqGqBq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPNSXADD_EdGdBd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPNSXADD_EqGqBq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPNZXADD_EdGdBd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPNZXADD_EqGqBq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPOXADD_EdGdBd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPOXADD_EqGqBq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPPXADD_EdGdBd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPPXADD_EqGqBq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPSXADD_EdGdBd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPSXADD_EqGqBq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPZXADD_EdGdBd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPZXADD_EqGqBq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* CMPccXADD */

    /* FMA4 specific handlers (AMD) */
    void VFMADDSS_VssHssWssVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMADDSD_VsdHsdWsdVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMSUBSS_VssHssWssVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMSUBSD_VsdHsdWsdVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMADDSS_VssHssWssVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMADDSD_VsdHsdWsdVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMSUBSS_VssHssWssVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMSUBSD_VsdHsdWsdVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* FMA4 specific handlers (AMD) */

    /* XOP (AMD) */
    void VPCMOV_VdqHdqWdqVIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPPERM_VdqHdqWdqVIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHAB_VdqWdqHdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHAW_VdqWdqHdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHAD_VdqWdqHdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHAQ_VdqWdqHdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPROTB_VdqWdqHdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPROTW_VdqWdqHdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPROTD_VdqWdqHdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPROTQ_VdqWdqHdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHLB_VdqWdqHdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHLW_VdqWdqHdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHLD_VdqWdqHdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHLQ_VdqWdqHdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMACSSWW_VdqHdqWdqVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMACSSWD_VdqHdqWdqVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMACSSDQL_VdqHdqWdqVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMACSSDD_VdqHdqWdqVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMACSSDQH_VdqHdqWdqVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMACSWW_VdqHdqWdqVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMACSWD_VdqHdqWdqVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMACSDQL_VdqHdqWdqVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMACSDD_VdqHdqWdqVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMACSDQH_VdqHdqWdqVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMADCSSWD_VdqHdqWdqVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMADCSWD_VdqHdqWdqVIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPROTB_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPROTW_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPROTD_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPROTQ_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCOMB_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCOMW_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCOMD_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCOMQ_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCOMUB_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCOMUW_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCOMUD_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCOMUQ_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFRCZPS_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFRCZPD_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFRCZSS_VssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFRCZSD_VsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHADDBW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHADDBD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHADDBQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHADDWD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHADDWQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHADDDQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHADDUBW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHADDUBD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHADDUBQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHADDUWD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHADDUWQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHADDUDQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHSUBBW_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHSUBWD_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPHSUBDQ_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMIL2PS_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMIL2PD_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* XOP (AMD) */

    /* TBM (AMD) */
    void BEXTR_GdEdIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLCFILL_BdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLCI_BdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLCIC_BdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLCMSK_BdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLCS_BdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLSFILL_BdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLSIC_BdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void T1MSKC_BdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void TZMSK_BdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void BEXTR_GqEqIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLCFILL_BqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLCI_BqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLCIC_BqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLCMSK_BqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLCS_BqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLSFILL_BqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BLSIC_BqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void T1MSKC_BqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void TZMSK_BqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    /* TBM (AMD) */
#endif

#if BX_SUPPORT_AVX
  // VAES: VEX extended AES instructions
    void VAESENC_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VAESENCLAST_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VAESDEC_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VAESDECLAST_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCLMULQDQ_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    /* GFNI instructions: VEX extended form */
    void VGF2P8AFFINEINVQB_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VGF2P8AFFINEQB_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VGF2P8MULB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    /* AVX encoded VNNI instructions */
    void VPDPBUSD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPDPBUSDS_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPDPWSSD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPDPWSSDS_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    /* AVX encoded IFMA instructions */
    void VPMADD52LUQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMADD52HUQ_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    /* AVX encoded VNNI INT8 instructions */
    void VPDPBSSD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPDPBSSDS_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPDPBSUD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPDPBSUDS_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPDPBUUD_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPDPBUUDS_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    // AVX512 OPMASK instructions (VEX encoded)
    void KADDB_KGbKHbKEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KANDB_KGbKHbKEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KANDNB_KGbKHbKEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVB_KGbKEbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVB_KGbKEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVB_KEbKGbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVB_KGbEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVB_GdKEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KNOTB_KGbKEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KORB_KGbKHbKEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KORTESTB_KGbKEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KSHIFTLB_KGbKEbIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KSHIFTRB_KGbKEbIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KXNORB_KGbKHbKEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KXORB_KGbKHbKEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KTESTB_KGbKEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void KADDW_KGwKHwKEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KANDW_KGwKHwKEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KANDNW_KGwKHwKEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVW_KGwKEwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVW_KGwKEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVW_KEwKGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVW_KGwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVW_GdKEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KUNPCKBW_KGwKHbKEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KNOTW_KGwKEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KORW_KGwKHwKEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KORTESTW_KGwKEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KSHIFTLW_KGwKEwIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KSHIFTRW_KGwKEwIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KXNORW_KGwKHwKEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KXORW_KGwKHwKEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KTESTW_KGwKEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void KADDD_KGdKHdKEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KANDD_KGdKHdKEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KANDND_KGdKHdKEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVD_KGdKEdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVD_KGdKEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVD_KEdKGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVD_KGdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVD_GdKEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KUNPCKWD_KGdKHwKEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KNOTD_KGdKEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KORD_KGdKHdKEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KORTESTD_KGdKEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KSHIFTLD_KGdKEdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KSHIFTRD_KGdKEdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KXNORD_KGdKHdKEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KXORD_KGdKHdKEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KTESTD_KGdKEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void KADDQ_KGqKHqKEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KANDQ_KGqKHqKEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KANDNQ_KGqKHqKEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVQ_KGqKEqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVQ_KGqKEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVQ_KEqKGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVQ_KGqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KMOVQ_GqKEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KUNPCKDQ_KGqKHdKEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KNOTQ_KGqKEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KORQ_KGqKHqKEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KORTESTQ_KGqKEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KSHIFTLQ_KGqKEqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KSHIFTRQ_KGqKEqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KXNORQ_KGqKHqKEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KXORQ_KGqKHqKEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void KTESTQ_KGqKEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    // AVX512 OPMASK instructions (VEX encoded)
#endif

#if BX_SUPPORT_EVEX
    void VADDPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VADDPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VADDSS_MASK_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VADDSD_MASK_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSUBPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSUBPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSUBSS_MASK_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSUBSD_MASK_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMULPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMULPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMULSS_MASK_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMULSD_MASK_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VDIVPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VDIVPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VDIVSS_MASK_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VDIVSD_MASK_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMINPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMINPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMINSS_MASK_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMINSD_MASK_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMAXPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMAXPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMAXSS_MASK_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMAXSD_MASK_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSQRTPS_MASK_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSQRTPD_MASK_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSQRTSS_MASK_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSQRTSD_MASK_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VFPCLASSPS_MASK_KGwWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFPCLASSPD_MASK_KGbWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFPCLASSSS_MASK_KGbWssIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFPCLASSSD_MASK_KGbWsdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VGETEXPPS_MASK_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VGETEXPPD_MASK_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VGETEXPSS_MASK_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VGETEXPSD_MASK_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VGETMANTPS_MASK_VpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VGETMANTPD_MASK_VpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VGETMANTSS_MASK_VssHpsWssIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VGETMANTSD_MASK_VsdHpdWsdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VRNDSCALEPS_MASK_VpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VRNDSCALEPD_MASK_VpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VRNDSCALESS_MASK_VssHpsWssIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VRNDSCALESD_MASK_VsdHpdWsdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VREDUCEPS_MASK_VpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VREDUCEPD_MASK_VpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VREDUCESS_MASK_VssHpsWssIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VREDUCESD_MASK_VsdHpdWsdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VSCALEFPS_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSCALEFPD_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSCALEFSS_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSCALEFSD_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VSCALEFPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSCALEFPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSCALEFSS_MASK_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSCALEFSD_MASK_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VRANGEPS_MASK_VpsHpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VRANGEPD_MASK_VpdHpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VRANGESS_MASK_VssHpsWssIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VRANGESD_MASK_VsdHpdWsdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VRCP14PS_MASK_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VRCP14PD_MASK_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VRCP14SS_MASK_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VRCP14SD_MASK_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VRSQRT14PS_MASK_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VRSQRT14PD_MASK_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VRSQRT14SS_MASK_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VRSQRT14SD_MASK_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VCVTSS2USI_GdWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTSS2USI_GqWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTSD2USI_GdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTSD2USI_GqWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VCVTTSS2USI_GdWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTTSS2USI_GqWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTTSD2USI_GdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTTSD2USI_GqWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VCVTUSI2SD_VsdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTUSI2SS_VssEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTUSI2SD_VsdEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTUSI2SS_VssEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VCVTTPS2UDQ_VdqWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTTPS2UDQ_MASK_VdqWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTTPD2UDQ_VdqWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTTPD2UDQ_MASK_VdqWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VCVTPS2UDQ_VdqWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTPS2UDQ_MASK_VdqWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTPD2UDQ_VdqWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTPD2UDQ_MASK_VdqWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VCVTUDQ2PS_VpsWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTUDQ2PS_MASK_VpsWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTUDQ2PD_VpdWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTUDQ2PD_MASK_VpdWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VCVTQQ2PS_VpsWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTQQ2PS_MASK_VpsWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTUQQ2PS_VpsWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTUQQ2PS_MASK_VpsWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VCVTQQ2PD_VpdWdqR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTQQ2PD_MASK_VpdWdqR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTUQQ2PD_VpdWdqR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTUQQ2PD_MASK_VpdWdqR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);

    void VCVTPS2QQ_VdqWpsR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTPS2QQ_MASK_VdqWpsR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTTPS2QQ_VdqWpsR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTTPS2QQ_MASK_VdqWpsR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTPS2UQQ_VdqWpsR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTPS2UQQ_MASK_VdqWpsR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTTPS2UQQ_VdqWpsR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTTPS2UQQ_MASK_VdqWpsR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);

    void VCVTPD2QQ_VdqWpdR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTPD2QQ_MASK_VdqWpdR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTTPD2QQ_VdqWpdR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTTPD2QQ_MASK_VdqWpdR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTPD2UQQ_VdqWpdR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTPD2UQQ_MASK_VdqWpdR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTTPD2UQQ_VdqWpdR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTTPD2UQQ_MASK_VdqWpdR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);

    void VCVTPD2PS_MASK_VpsWpdR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTPS2PD_MASK_VpdWpsR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTSS2SD_MASK_VsdWssR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTSD2SS_MASK_VssWsdR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);

    void VCVTPS2DQ_MASK_VdqWpsR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTTPS2DQ_MASK_VdqWpsR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTDQ2PS_MASK_VpsWdqR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);

    void VCVTPD2DQ_MASK_VdqWpdR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTTPD2DQ_MASK_VdqWpdR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTDQ2PD_MASK_VpdWdqR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);

    void VCVTPH2PS_MASK_VpsWpsR(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void VCVTPS2PH_MASK_WpsVpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCVTPS2PH_MASK_WpsVpsIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPABSB_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPABSW_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPABSD_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPABSQ_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPADDD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSUBD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPANDD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPANDND_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPORD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPXORD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMAXSD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMAXUD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMINSD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMINUD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMULLD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VUNPCKLPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VUNPCKHPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRAVD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLVD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLVD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPROLVD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPRORVD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRAD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMADDWD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPADDQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSUBQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPANDQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPANDNQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPORQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPXORQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMAXSQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMAXUQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMINSQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMINUQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMULLQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VUNPCKLPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VUNPCKHPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMULDQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMULUDQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRAVQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLVQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLVQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPROLVQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPRORVQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRAQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPROLD_MASK_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPROLQ_MASK_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPRORD_MASK_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPRORQ_MASK_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLW_MASK_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLD_MASK_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLQ_MASK_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRAW_MASK_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRAD_MASK_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRAQ_MASK_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLW_MASK_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLD_MASK_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLQ_MASK_UdqIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPSUBB_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSUBSB_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSUBUSB_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSUBW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSUBSW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSUBUSW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPADDB_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPADDSB_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPADDUSB_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPADDW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPADDSW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPADDUSW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMINSB_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMINUB_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMAXUB_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMAXSB_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMINSW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMINUW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMAXSW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMAXUW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPSRLW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRAW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPSRAVW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSRLVW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSLLVW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPAVGB_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPAVGW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMADDUBSW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMULLW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMULHW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMULHUW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMULHRSW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPACKSSWB_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPACKUSWB_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPACKSSDW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPACKUSDW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPUNPCKLBW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPUNPCKHBW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPUNPCKLWD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPUNPCKHWD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VMOVAPS_MASK_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVAPS_MASK_VpsWpsM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVAPS_MASK_WpsVpsM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVAPD_MASK_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVAPD_MASK_VpdWpdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVAPD_MASK_WpdVpdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VMOVUPS_MASK_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVUPS_MASK_VpsWpsM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVUPS_MASK_WpsVpsM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVUPD_MASK_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVUPD_MASK_VpdWpdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVUPD_MASK_WpdVpdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VMOVDQU8_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVDQU8_MASK_VdqWdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVDQU8_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VMOVDQU16_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVDQU16_MASK_VdqWdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVDQU16_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VMOVSD_MASK_VsdWsdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVSS_MASK_VssWssM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVSD_MASK_WsdVsdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVSS_MASK_WssVssM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVSD_MASK_VsdHpdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVSS_MASK_VssHpsWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VMOVSHDUP_MASK_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVSLDUP_MASK_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VMOVDDUP_MASK_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VFMADDPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMADDPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMADDSD_MASK_VpdHsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMADDSS_MASK_VpsHssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMADDSUBPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMADDSUBPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMSUBADDPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMSUBADDPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMSUBPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMSUBPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMSUBSD_MASK_VpdHsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFMSUBSS_MASK_VpsHssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMADDPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMADDPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMADDSD_MASK_VpdHsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMADDSS_MASK_VpsHssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMSUBPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMSUBPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMSUBSD_MASK_VpdHsdWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFNMSUBSS_MASK_VpsHssWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VFIXUPIMMSS_MASK_VssHssWssIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFIXUPIMMSD_MASK_VsdHsdWsdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFIXUPIMMPS_VpsHpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFIXUPIMMPD_VpdHpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFIXUPIMMPS_MASK_VpsHpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VFIXUPIMMPD_MASK_VpdHpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VBLENDMPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VBLENDMPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPBLENDMB_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBLENDMW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPCMPB_MASK_KGqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPUB_MASK_KGqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPW_MASK_KGdHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPUW_MASK_KGdHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPD_MASK_KGwHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPUD_MASK_KGwHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPQ_MASK_KGbHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPUQ_MASK_KGbHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPCMPEQB_MASK_KGqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPGTB_MASK_KGqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPEQW_MASK_KGdHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPGTW_MASK_KGdHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPEQD_MASK_KGwHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPGTD_MASK_KGwHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPEQQ_MASK_KGbHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCMPGTQ_MASK_KGbHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPTESTMB_MASK_KGqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPTESTNMB_MASK_KGqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPTESTMW_MASK_KGdHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPTESTNMW_MASK_KGdHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPTESTMD_MASK_KGwHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPTESTNMD_MASK_KGwHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPTESTMQ_MASK_KGbHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPTESTNMQ_MASK_KGbHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VCMPPS_MASK_KGwHpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCMPPD_MASK_KGbHpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCMPSS_MASK_KGbHssWssIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCMPSD_MASK_KGbHsdWsdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPSHUFB_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPERMQ_MASK_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSHUFPS_MASK_VpsHpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSHUFPD_MASK_VpdHpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHUFLW_MASK_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHUFHW_MASK_VdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPERMILPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMILPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMILPS_MASK_VpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMILPD_MASK_VpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VSHUFF32x4_MASK_VpsHpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSHUFF64x2_MASK_VpdHpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VALIGND_MASK_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VALIGNQ_MASK_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPALIGNR_MASK_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VDBPSADBW_MASK_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPERMI2B_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMI2W_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMT2B_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMT2W_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPERMI2PS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMI2PD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMT2PS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMT2PD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPERMB_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPERMPS_MASK_VpsHpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPERMPD_MASK_VpdHpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VINSERTF32x4_MASK_VpsHpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VINSERTF64x2_MASK_VpdHpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VINSERTF64x4_VpdHpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VINSERTF64x4_MASK_VpdHpdWpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VINSERTF32x8_MASK_VpsHpsWpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VEXTRACTF32x4_MASK_WpsVpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VEXTRACTF32x4_MASK_WpsVpsIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VEXTRACTF64x4_WpdVpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VEXTRACTF64x4_WpdVpdIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VEXTRACTF64x4_MASK_WpdVpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VEXTRACTF64x4_MASK_WpdVpdIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VEXTRACTF32x8_MASK_WpsVpsIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VEXTRACTF32x8_MASK_WpsVpsIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VEXTRACTF64x2_MASK_WpdVpdIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VEXTRACTF64x2_MASK_WpdVpdIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPBROADCASTB_MASK_VdqWbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTW_MASK_VdqWwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTD_MASK_VdqWdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTQ_MASK_VdqWqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTB_MASK_VdqWbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTW_MASK_VdqWwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTD_MASK_VdqWdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTQ_MASK_VdqWqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPBROADCASTB_VdqEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTW_VdqEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTD_VdqEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTQ_VdqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTB_MASK_VdqEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTW_MASK_VdqEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTD_MASK_VdqEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTQ_MASK_VdqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VBROADCASTF32x2_MASK_VpsWqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VBROADCASTF32x2_MASK_VpsWqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VBROADCASTF64x2_MASK_VpdMpd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VBROADCASTF32x4_MASK_VpsMps(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VBROADCASTF64x4_VpdMpd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VBROADCASTF32x8_MASK_VpsMps(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VBROADCASTF64x4_MASK_VpdMpd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPTERNLOGD_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPTERNLOGQ_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPTERNLOGD_MASK_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPTERNLOGQ_MASK_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VGATHERDPS_MASK_VpsVSib(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VGATHERQPS_MASK_VpsVSib(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VGATHERDPD_MASK_VpdVSib(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VGATHERQPD_MASK_VpdVSib(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VSCATTERDPS_MASK_VSibVps(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSCATTERQPS_MASK_VSibVps(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSCATTERDPD_MASK_VSibVpd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VSCATTERQPD_MASK_VSibVpd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VCOMPRESSPS_MASK_WpsVps(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VCOMPRESSPD_MASK_WpdVpd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VEXPANDPS_MASK_VpsWpsR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VEXPANDPD_MASK_VpdWpdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPCOMPRESSB_MASK_WdqVdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCOMPRESSW_MASK_WdqVdq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPEXPANDB_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPEXPANDW_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMOVQB_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVDB_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVWB_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVDW_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVQW_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVQD_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMOVQB_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVDB_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVWB_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVDW_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVQW_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVQD_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMOVQB_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVDB_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVWB_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVDW_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVQW_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVQD_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMOVUSQB_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVUSDB_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVUSWB_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVUSDW_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVUSQW_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVUSQD_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMOVUSQB_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVUSDB_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVUSWB_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVUSDW_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVUSQW_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVUSQD_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMOVUSQB_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVUSDB_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVUSWB_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVUSDW_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVUSQW_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVUSQD_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMOVSQB_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSDB_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSWB_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSDW_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSQW_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSQD_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMOVSQB_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSDB_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSWB_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSDW_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSQW_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSQD_MASK_WdqVdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMOVSQB_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSDB_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSWB_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSDW_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSQW_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSQD_MASK_WdqVdqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMOVSXBW_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSXBD_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSXBQ_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSXWD_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSXWQ_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVSXDQ_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMOVZXBW_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVZXBD_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVZXBQ_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVZXWD_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVZXWQ_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVZXDQ_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPCONFLICTD_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPCONFLICTQ_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPLZCNTD_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPLZCNTQ_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPOPCNTB_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPOPCNTW_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPOPCNTD_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPOPCNTQ_MASK_VdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPSHUFBITQMB_MASK_KGqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VP2INTERSECTD_KGqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VP2INTERSECTQ_KGqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPBROADCASTMB2Q_VdqKEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPBROADCASTMW2D_VdqKEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMOVM2B_VdqKEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVM2W_VdqKEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVM2D_VdqKEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVM2Q_VdqKEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMOVB2M_KGqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVW2M_KGdWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVD2M_KGwWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMOVQ2M_KGbWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMADD52LUQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMADD52HUQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPMULTISHIFTQB_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPMULTISHIFTQB_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPDPBUSD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPDPBUSDS_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPDPWSSD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPDPWSSDS_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPSHLDW_MASK_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHLDVW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHLDD_MASK_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHLDVD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHLDQ_MASK_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHLDVQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void VPSHRDW_MASK_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHRDVW_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHRDD_MASK_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHRDVD_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHRDQ_MASK_VdqHdqWdqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void VPSHRDVQ_MASK_VdqHdqWdqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif

    void LZCNT_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LZCNT_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
    void LZCNT_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif

    /* BMI - TZCNT */
    void TZCNT_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void TZCNT_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
    void TZCNT_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif
    /* BMI - TZCNT */

    /* SSE4A */
    void EXTRQ_UdqIbIb(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void EXTRQ_VdqUq(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void INSERTQ_VdqUqIbIb(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    void INSERTQ_VdqUdq(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
    /* SSE4A */

    void CMPXCHG8B(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RETnear32_Iw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RETnear16_Iw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RETfar32_Iw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RETfar16_Iw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void XADD_EbGbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XADD_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XADD_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void XADD_EbGbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XADD_EwGwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XADD_EdGdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void CMOVO_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNO_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVB_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNB_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVZ_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNZ_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVBE_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNBE_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVS_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNS_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVP_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNP_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVL_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNL_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVLE_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNLE_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void CMOVO_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNO_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVB_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNB_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVZ_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNZ_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVBE_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNBE_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVS_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNS_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVP_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNP_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVL_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNL_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVLE_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNLE_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void CWDE(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CDQ(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void CMPXCHG_EbGbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPXCHG_EwGwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPXCHG_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void CMPXCHG_EbGbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPXCHG_EwGwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPXCHG_EdGdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MUL_AXEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IMUL_AXEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DIV_AXEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IDIV_AXEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IMUL_GwEwIwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IMUL_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void NOP(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PAUSE(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_EbIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_EwIwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_EdIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void PUSH_EwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUSH_EwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUSH_EdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUSH_EdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void POP_EwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void POP_EwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void POP_EdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void POP_EdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void POPCNT_GwEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void POPCNT_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
    void POPCNT_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif

    void ADCX_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADOX_GdEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
    void ADCX_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADOX_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif

    // SMAP
    void CLAC(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void STAC(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    // SMAP

    // RDRAND/RDSEED
    void RDRAND_Ew(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RDRAND_Ed(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
    void RDRAND_Eq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif

    void RDSEED_Ew(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RDSEED_Ed(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
    void RDSEED_Eq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif

#if BX_SUPPORT_X86_64
    // 64 bit extensions
    void ADD_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_GqEqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_GqEqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_GqEqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_GqEqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_GqEqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_GqEqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_GqEqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_GqEqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_EqIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_EqIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_EqIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_EqIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_EqIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_EqIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_EqIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_EqIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ADD_EqIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OR_EqIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ADC_EqIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SBB_EqIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void AND_EqIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SUB_EqIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XOR_EqIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMP_EqIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void TEST_EqGqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void TEST_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void TEST_RAXId(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void XCHG_EqGqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XCHG_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void LEA_GqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOV_RAXOq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_OqRAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_EAXOq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_OqEAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_AXOq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_OqAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_ALOq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_OqAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOV_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_GqEqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_EqIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_EqIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOV64S_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV64S_GqEqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    // repeatable instructions
    void REP_MOVSQ_YqXq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_CMPSQ_XqYq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_STOSQ_YqRAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_LODSQ_RAXXq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void REP_SCASQ_RAXYq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    // qualified by address size
    void CMPSB64_XbYb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPSW64_XwYw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPSD64_XdYd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SCASB64_ALYb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SCASW64_AXYw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SCASD64_EAXYd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LODSB64_ALXb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LODSW64_AXXw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LODSD64_EAXXd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void STOSB64_YbAL(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void STOSW64_YwAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void STOSD64_YdEAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSB64_YbXb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSW64_YwXw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSD64_YdXd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void CMPSQ32_XqYq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPSQ64_XqYq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SCASQ32_RAXYq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SCASQ64_RAXYq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LODSQ32_RAXXq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LODSQ64_RAXXq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void STOSQ32_YqRAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void STOSQ64_YqRAX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSQ32_YqXq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSQ64_YqXq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void INSB64_YbDX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void INSW64_YwDX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void INSD64_YdDX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void OUTSB64_DXXb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OUTSW64_DXXw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void OUTSD64_DXXd(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void CALL_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JMP_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void JO_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNO_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JB_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNB_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JZ_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNZ_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JBE_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNBE_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JS_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNS_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JP_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNP_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JL_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNL_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JLE_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JNLE_Jq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ENTER64_IwIb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LEAVE64(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IRET64(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOV_CR0Rq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_CR2Rq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_CR3Rq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_CR4Rq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_RqCR0(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_RqCR2(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_RqCR3(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_RqCR4(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_DqRq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV_RqDq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void SHLD_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHLD_EqGqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHRD_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHRD_EqGqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOV64_GdEdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOV64_EdGdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOVZX_GqEbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVZX_GqEwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSX_GqEbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSX_GqEwM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSX_GqEdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOVZX_GqEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVZX_GqEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSX_GqEbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSX_GqEwR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVSX_GqEdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void BSF_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BSR_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void BT_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTS_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTR_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTC_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void BT_EqGqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTS_EqGqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTR_EqGqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTC_EqGqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void BT_EqIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTS_EqIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTR_EqIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTC_EqIbM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void BT_EqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTS_EqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTR_EqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BTC_EqIbR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void BSWAP_RRX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ROL_EqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ROR_EqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCL_EqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCR_EqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHL_EqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHR_EqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SAR_EqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void ROL_EqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void ROR_EqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCL_EqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RCR_EqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHL_EqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SHR_EqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SAR_EqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void NOT_EqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void NEG_EqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void NOT_EqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void NEG_EqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void TEST_EqIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void TEST_EqIdM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MUL_RAXEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IMUL_RAXEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DIV_RAXEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IDIV_RAXEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IMUL_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void IMUL_GqEqIdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void INC_EqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DEC_EqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void INC_EqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void DEC_EqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CALL_EqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CALL64_Ep(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JMP_EqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JMP64_Ep(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUSHF_Fq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void POPF_Fq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void CMPXCHG_EqGqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMPXCHG_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void CDQE(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CQO(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void XADD_EqGqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void XADD_EqGqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void RETnear64_Iw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RETfar64_Iw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void CMOVO_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNO_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVB_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNB_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVZ_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNZ_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVBE_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNBE_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVS_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNS_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVP_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNP_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVL_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNL_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVLE_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CMOVNLE_GqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOV_RRXIq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUSH_EqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUSH_EqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void POP_EqM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void POP_EqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void PUSH64_Id(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void PUSH64_Sw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void POP64_Sw(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void LSS_GqMp(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LFS_GqMp(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LGS_GqMp(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void SGDT64_Ms(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SIDT64_Ms(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LGDT64_Ms(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LIDT64_Ms(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void CMPXCHG16B(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void SWAPGS(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RDFSBASE_Ed(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RDGSBASE_Ed(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RDFSBASE_Eq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RDGSBASE_Eq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void WRFSBASE_Ed(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void WRGSBASE_Ed(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void WRFSBASE_Eq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void WRGSBASE_Eq(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void LOOPNE64_Jb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOOPE64_Jb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void LOOP64_Jb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void JRCXZ_Jb(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MOVQ_EqPqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVQ_EqVqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVQ_PqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MOVQ_VdqEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void CVTSI2SS_VssEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTSI2SD_VsdEqR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTTSD2SI_GqWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTTSS2SI_GqWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTSD2SI_GqWsdR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void CVTSS2SI_GqWssR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif  // #if BX_SUPPORT_X86_64

    void RDTSCP(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void INVLPG(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RSM(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void WRMSR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RDTSC(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RDPMC(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void RDMSR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SYSENTER(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void SYSEXIT(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void MONITOR(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void MWAIT(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void RDPID_Ed(bxInstruction_c*) BX_CPP_AttrRegparmN(1);

    void UndefinedOpcode(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BxError(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_HANDLERS_CHAINING_SPEEDUPS
    void BxEndTrace(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif

#if BX_CPU_LEVEL >= 6
    void BxNoSSE(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_AVX
    void BxNoAVX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif
#if BX_SUPPORT_EVEX
    void BxNoOpMask(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
    void BxNoEVEX(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif
#endif

    inline Bit32u BxResolve32(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
    inline Bit64u BxResolve64(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif
#if BX_SUPPORT_AVX
    bx_address BxResolveGatherD(bxInstruction_c*, unsigned) BX_CPP_AttrRegparmN(2);
    bx_address BxResolveGatherQ(bxInstruction_c*, unsigned) BX_CPP_AttrRegparmN(2);
#endif
    // <TAG-CLASS-CPU-END>

#if BX_DEBUGGER
    void       dbg_take_dma(void);
    bool       dbg_set_eflags(Bit32u val);
    void       dbg_set_eip(bx_address val);
    bool       dbg_get_sreg(bx_dbg_sreg_t* sreg, unsigned sreg_no);
    bool       dbg_set_sreg(unsigned sreg_no, bx_segment_reg_t* sreg);
    void       dbg_get_tr(bx_dbg_sreg_t* sreg);
    void       dbg_get_ldtr(bx_dbg_sreg_t* sreg);
    void       dbg_get_gdtr(bx_dbg_global_sreg_t* sreg);
    void       dbg_get_idtr(bx_dbg_global_sreg_t* sreg);
    unsigned   dbg_query_pending(void);
#endif
#if BX_DEBUGGER || BX_GDBSTUB
    bool  dbg_instruction_epilog(void);
#endif
    bool  dbg_xlate_linear2phy(bx_address linear, bx_phy_address* phy, Bit32u* lpf_mask = 0, bool verbose = 0, bool nested_walk = 0);
#if BX_LARGE_RAMFILE
    bool check_addr_in_tlb_buffers(const Bit8u* addr, const Bit8u* end);
#endif
    void atexit(void);

    // now for some ancillary functions...
    void cpu_loop(void);
#if BX_SUPPORT_SMP
    void cpu_run_trace(void);
#endif
    bool handleAsyncEvent(void);
    bool handleWaitForEvent(void);
    void InterruptAcknowledge(void);

    void boundaryFetch(const Bit8u* fetchPtr, unsigned remainingInPage, bxInstruction_c*);

    bxICacheEntry_c* serveICacheMiss(Bit32u eipBiased, bx_phy_address pAddr);
    bxICacheEntry_c* getICacheEntry(void);
    bool mergeTraces(bxICacheEntry_c* entry, bxInstruction_c* i, bx_phy_address pAddr);
#if BX_SUPPORT_HANDLERS_CHAINING_SPEEDUPS && BX_ENABLE_TRACE_LINKING
    void linkTrace(bxInstruction_c* i) BX_CPP_AttrRegparmN(1);
#endif
    void prefetch(void);
    void updateFetchModeMask(void);
    inline void invalidate_prefetch_q(void)
    {
        BX_CPU_THIS_PTR eipPageWindowSize = 0;
    }

    inline void invalidate_stack_cache(void)
    {
        BX_CPU_THIS_PTR espPageWindowSize = 0;
    }

    bool write_virtual_checks(bx_segment_reg_t* seg, Bit32u offset, unsigned len, bool align = false) BX_CPP_AttrRegparmN(4);
    bool read_virtual_checks(bx_segment_reg_t* seg, Bit32u offset, unsigned len, bool align = false) BX_CPP_AttrRegparmN(4);
    bool execute_virtual_checks(bx_segment_reg_t* seg, Bit32u offset, unsigned len) BX_CPP_AttrRegparmN(3);

    Bit8u read_linear_byte(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);
    Bit16u read_linear_word(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);
    Bit32u read_linear_dword(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);
    Bit64u read_linear_qword(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);
#if BX_CPU_LEVEL >= 6
    void read_linear_xmmword(unsigned seg, bx_address off, BxPackedXmmRegister* data) BX_CPP_AttrRegparmN(3);
    void read_linear_xmmword_aligned(unsigned seg, bx_address off, BxPackedXmmRegister* data) BX_CPP_AttrRegparmN(3);
    void read_linear_ymmword(unsigned seg, bx_address off, BxPackedYmmRegister* data) BX_CPP_AttrRegparmN(3);
    void read_linear_ymmword_aligned(unsigned seg, bx_address off, BxPackedYmmRegister* data) BX_CPP_AttrRegparmN(3);
    void read_linear_zmmword(unsigned seg, bx_address off, BxPackedZmmRegister* data) BX_CPP_AttrRegparmN(3);
    void read_linear_zmmword_aligned(unsigned seg, bx_address off, BxPackedZmmRegister* data) BX_CPP_AttrRegparmN(3);
#endif

    void write_linear_byte(unsigned seg, bx_address offset, Bit8u data) BX_CPP_AttrRegparmN(3);
    void write_linear_word(unsigned seg, bx_address offset, Bit16u data) BX_CPP_AttrRegparmN(3);
    void write_linear_dword(unsigned seg, bx_address offset, Bit32u data) BX_CPP_AttrRegparmN(3);
    void write_linear_qword(unsigned seg, bx_address offset, Bit64u data) BX_CPP_AttrRegparmN(3);
#if BX_CPU_LEVEL >= 6
    void write_linear_xmmword(unsigned seg, bx_address offset, const BxPackedXmmRegister* data) BX_CPP_AttrRegparmN(3);
    void write_linear_xmmword_aligned(unsigned seg, bx_address offset, const BxPackedXmmRegister* data) BX_CPP_AttrRegparmN(3);
    void write_linear_ymmword(unsigned seg, bx_address off, const BxPackedYmmRegister* data) BX_CPP_AttrRegparmN(3);
    void write_linear_ymmword_aligned(unsigned seg, bx_address off, const BxPackedYmmRegister* data) BX_CPP_AttrRegparmN(3);
    void write_linear_zmmword(unsigned seg, bx_address off, const BxPackedZmmRegister* data) BX_CPP_AttrRegparmN(3);
    void write_linear_zmmword_aligned(unsigned seg, bx_address off, const BxPackedZmmRegister* data) BX_CPP_AttrRegparmN(3);
#endif

    void tickle_read_linear(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);
    void tickle_read_virtual_32(unsigned seg, Bit32u offset) BX_CPP_AttrRegparmN(2);
    void tickle_read_virtual(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);

    Bit8u read_virtual_byte_32(unsigned seg, Bit32u offset) BX_CPP_AttrRegparmN(2);
    Bit16u read_virtual_word_32(unsigned seg, Bit32u offset) BX_CPP_AttrRegparmN(2);
    Bit32u read_virtual_dword_32(unsigned seg, Bit32u offset) BX_CPP_AttrRegparmN(2);
    Bit64u read_virtual_qword_32(unsigned seg, Bit32u offset) BX_CPP_AttrRegparmN(2);
#if BX_CPU_LEVEL >= 6
    void read_virtual_xmmword_32(unsigned seg, Bit32u off, BxPackedXmmRegister* data) BX_CPP_AttrRegparmN(3);
    void read_virtual_xmmword_aligned_32(unsigned seg, Bit32u off, BxPackedXmmRegister* data) BX_CPP_AttrRegparmN(3);
    void read_virtual_ymmword_32(unsigned seg, Bit32u off, BxPackedYmmRegister* data) BX_CPP_AttrRegparmN(3);
    void read_virtual_ymmword_aligned_32(unsigned seg, Bit32u off, BxPackedYmmRegister* data) BX_CPP_AttrRegparmN(3);
    void read_virtual_zmmword_32(unsigned seg, Bit32u off, BxPackedZmmRegister* data) BX_CPP_AttrRegparmN(3);
    void read_virtual_zmmword_aligned_32(unsigned seg, Bit32u off, BxPackedZmmRegister* data) BX_CPP_AttrRegparmN(3);
#endif

    void write_virtual_byte_32(unsigned seg, Bit32u offset, Bit8u data) BX_CPP_AttrRegparmN(3);
    void write_virtual_word_32(unsigned seg, Bit32u offset, Bit16u data) BX_CPP_AttrRegparmN(3);
    void write_virtual_dword_32(unsigned seg, Bit32u offset, Bit32u data) BX_CPP_AttrRegparmN(3);
    void write_virtual_qword_32(unsigned seg, Bit32u offset, Bit64u data) BX_CPP_AttrRegparmN(3);
#if BX_CPU_LEVEL >= 6
    void write_virtual_xmmword_32(unsigned seg, Bit32u offset, const BxPackedXmmRegister* data) BX_CPP_AttrRegparmN(3);
    void write_virtual_xmmword_aligned_32(unsigned seg, Bit32u offset, const BxPackedXmmRegister* data) BX_CPP_AttrRegparmN(3);
    void write_virtual_ymmword_32(unsigned seg, Bit32u off, const BxPackedYmmRegister* data) BX_CPP_AttrRegparmN(3);
    void write_virtual_ymmword_aligned_32(unsigned seg, Bit32u off, const BxPackedYmmRegister* data) BX_CPP_AttrRegparmN(3);
    void write_virtual_zmmword_32(unsigned seg, Bit32u off, const BxPackedZmmRegister* data) BX_CPP_AttrRegparmN(3);
    void write_virtual_zmmword_aligned_32(unsigned seg, Bit32u off, const BxPackedZmmRegister* data) BX_CPP_AttrRegparmN(3);
#endif

    Bit8u read_virtual_byte(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);
    Bit16u read_virtual_word(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);
    Bit32u read_virtual_dword(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);
    Bit64u read_virtual_qword(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);
#if BX_CPU_LEVEL >= 6
    void read_virtual_xmmword(unsigned seg, bx_address off, BxPackedXmmRegister* data) BX_CPP_AttrRegparmN(3);
    void read_virtual_xmmword_aligned(unsigned seg, bx_address off, BxPackedXmmRegister* data) BX_CPP_AttrRegparmN(3);
    void read_virtual_ymmword(unsigned seg, bx_address off, BxPackedYmmRegister* data) BX_CPP_AttrRegparmN(3);
    void read_virtual_ymmword_aligned(unsigned seg, bx_address off, BxPackedYmmRegister* data) BX_CPP_AttrRegparmN(3);
    void read_virtual_zmmword(unsigned seg, bx_address off, BxPackedZmmRegister* data) BX_CPP_AttrRegparmN(3);
    void read_virtual_zmmword_aligned(unsigned seg, bx_address off, BxPackedZmmRegister* data) BX_CPP_AttrRegparmN(3);
#endif

    void write_virtual_byte(unsigned seg, bx_address offset, Bit8u data) BX_CPP_AttrRegparmN(3);
    void write_virtual_word(unsigned seg, bx_address offset, Bit16u data) BX_CPP_AttrRegparmN(3);
    void write_virtual_dword(unsigned seg, bx_address offset, Bit32u data) BX_CPP_AttrRegparmN(3);
    void write_virtual_qword(unsigned seg, bx_address offset, Bit64u data) BX_CPP_AttrRegparmN(3);
#if BX_CPU_LEVEL >= 6
    void write_virtual_xmmword(unsigned seg, bx_address offset, const BxPackedXmmRegister* data) BX_CPP_AttrRegparmN(3);
    void write_virtual_xmmword_aligned(unsigned seg, bx_address offset, const BxPackedXmmRegister* data) BX_CPP_AttrRegparmN(3);
    void write_virtual_ymmword(unsigned seg, bx_address off, const BxPackedYmmRegister* data) BX_CPP_AttrRegparmN(3);
    void write_virtual_ymmword_aligned(unsigned seg, bx_address off, const BxPackedYmmRegister* data) BX_CPP_AttrRegparmN(3);
    void write_virtual_zmmword(unsigned seg, bx_address off, const BxPackedZmmRegister* data) BX_CPP_AttrRegparmN(3);
    void write_virtual_zmmword_aligned(unsigned seg, bx_address off, const BxPackedZmmRegister* data) BX_CPP_AttrRegparmN(3);
#endif

    Bit8u read_RMW_linear_byte(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);
    Bit16u read_RMW_linear_word(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);
    Bit32u read_RMW_linear_dword(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);
    Bit64u read_RMW_linear_qword(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);

    Bit8u read_RMW_virtual_byte_32(unsigned seg, Bit32u offset) BX_CPP_AttrRegparmN(2);
    Bit16u read_RMW_virtual_word_32(unsigned seg, Bit32u offset) BX_CPP_AttrRegparmN(2);
    Bit32u read_RMW_virtual_dword_32(unsigned seg, Bit32u offset) BX_CPP_AttrRegparmN(2);
    Bit64u read_RMW_virtual_qword_32(unsigned seg, Bit32u offset) BX_CPP_AttrRegparmN(2);

    Bit8u read_RMW_virtual_byte(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);
    Bit16u read_RMW_virtual_word(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);
    Bit32u read_RMW_virtual_dword(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);
    Bit64u read_RMW_virtual_qword(unsigned seg, bx_address offset) BX_CPP_AttrRegparmN(2);

    void write_RMW_linear_byte(Bit8u val8) BX_CPP_AttrRegparmN(1);
    void write_RMW_linear_word(Bit16u val16) BX_CPP_AttrRegparmN(1);
    void write_RMW_linear_dword(Bit32u val32) BX_CPP_AttrRegparmN(1);
    void write_RMW_linear_qword(Bit64u val64) BX_CPP_AttrRegparmN(1);

#if BX_SUPPORT_X86_64
    void read_RMW_linear_dqword_aligned_64(unsigned seg, bx_address laddr, Bit64u* hi, Bit64u* lo);
    void write_RMW_linear_dqword(Bit64u hi, Bit64u lo);
#endif

    // write of word/dword to new stack could happen only in legacy mode
    void write_new_stack_word(bx_segment_reg_t* seg, Bit32u offset, unsigned curr_pl, Bit16u data);
    void write_new_stack_dword(bx_segment_reg_t* seg, Bit32u offset, unsigned curr_pl, Bit32u data);
    void write_new_stack_qword(bx_segment_reg_t* seg, Bit32u offset, unsigned curr_pl, Bit64u data);

    void write_new_stack_word(bx_address laddr, unsigned curr_pl, Bit16u data);
    void write_new_stack_dword(bx_address laddr, unsigned curr_pl, Bit32u data);
    void write_new_stack_qword(bx_address laddr, unsigned curr_pl, Bit64u data);

    // dedicated optimized stack access methods
    void stack_write_byte(bx_address offset, Bit8u data) BX_CPP_AttrRegparmN(2);
    void stack_write_word(bx_address offset, Bit16u data) BX_CPP_AttrRegparmN(2);
    void stack_write_dword(bx_address offset, Bit32u data) BX_CPP_AttrRegparmN(2);
    void stack_write_qword(bx_address offset, Bit64u data) BX_CPP_AttrRegparmN(2);

    Bit8u stack_read_byte(bx_address offset) BX_CPP_AttrRegparmN(1);
    Bit16u stack_read_word(bx_address offset) BX_CPP_AttrRegparmN(1);
    Bit32u stack_read_dword(bx_address offset) BX_CPP_AttrRegparmN(1);
    Bit64u stack_read_qword(bx_address offset) BX_CPP_AttrRegparmN(1);

#if BX_SUPPORT_CET
    void shadow_stack_write_dword(bx_address offset, unsigned curr_pl, Bit32u data) BX_CPP_AttrRegparmN(3);
    void shadow_stack_write_qword(bx_address offset, unsigned curr_pl, Bit64u data) BX_CPP_AttrRegparmN(3);

    Bit32u shadow_stack_read_dword(bx_address offset, unsigned curr_pl) BX_CPP_AttrRegparmN(2);
    Bit64u shadow_stack_read_qword(bx_address offset, unsigned curr_pl) BX_CPP_AttrRegparmN(2);

    bool shadow_stack_lock_cmpxchg8b(bx_address offset, unsigned curr_pl, Bit64u data, Bit64u expected_data) BX_CPP_AttrRegparmN(4);
    bool shadow_stack_atomic_set_busy(bx_address offset, unsigned curr_pl) BX_CPP_AttrRegparmN(2);
    bool shadow_stack_atomic_clear_busy(bx_address offset, unsigned curr_pl) BX_CPP_AttrRegparmN(2);
#endif

    void stackPrefetch(bx_address offset, unsigned len) BX_CPP_AttrRegparmN(2);

    // dedicated system linear read/write methods with no segment
    Bit8u  system_read_byte(bx_address laddr) BX_CPP_AttrRegparmN(1);
    Bit16u system_read_word(bx_address laddr) BX_CPP_AttrRegparmN(1);
    Bit32u system_read_dword(bx_address laddr) BX_CPP_AttrRegparmN(1);
    Bit64u system_read_qword(bx_address laddr) BX_CPP_AttrRegparmN(1);

    void system_write_byte(bx_address laddr, Bit8u data) BX_CPP_AttrRegparmN(2);
    void system_write_word(bx_address laddr, Bit16u data) BX_CPP_AttrRegparmN(2);
    void system_write_dword(bx_address laddr, Bit32u data) BX_CPP_AttrRegparmN(2);

    Bit8u* v2h_read_byte(bx_address laddr, bool user) BX_CPP_AttrRegparmN(2);
    Bit8u* v2h_write_byte(bx_address laddr, bool user) BX_CPP_AttrRegparmN(2);

    void branch_near16(Bit16u new_IP) BX_CPP_AttrRegparmN(1);
    void branch_near32(Bit32u new_EIP) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
    void branch_near64(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif
    void branch_far(bx_selector_t* selector,
        bx_descriptor_t* descriptor, bx_address rip, unsigned cpl);

#if BX_SUPPORT_REPEAT_SPEEDUPS
    Bit32u FastRepMOVSB(unsigned srcSeg, Bit32u srcOff, unsigned dstSeg, Bit32u dstOff, Bit32u byteCount, Bit32u granularity);
    Bit32u FastRepMOVSB(bx_address laddrSrc, bx_address laddrDst, Bit64u byteCount, Bit32u granularity);

    Bit32u FastRepSTOSB(unsigned dstSeg, Bit32u dstOff, Bit8u  val, Bit32u  byteCount);
    Bit32u FastRepSTOSW(unsigned dstSeg, Bit32u dstOff, Bit16u val, Bit32u  wordCount);
    Bit32u FastRepSTOSD(unsigned dstSeg, Bit32u dstOff, Bit32u val, Bit32u dwordCount);

    Bit32u FastRepSTOSB(bx_address laddrDst, Bit8u  val, Bit32u  byteCount);
    Bit32u FastRepSTOSW(bx_address laddrDst, Bit16u val, Bit32u  wordCount);
    Bit32u FastRepSTOSD(bx_address laddrDst, Bit32u val, Bit32u dwordCount);

    Bit32u FastRepINSW(Bit32u dstOff, Bit16u port, Bit32u wordCount);
    Bit32u FastRepOUTSW(unsigned srcSeg, Bit32u srcOff, Bit16u port, Bit32u wordCount);
#endif

    void repeat(bxInstruction_c* i, BxRepIterationPtr_tR execute) BX_CPP_AttrRegparmN(2);
    void repeat_ZF(bxInstruction_c* i, BxRepIterationPtr_tR execute) BX_CPP_AttrRegparmN(2);

    // linear address for access_linear expected to be canonical !
    int access_read_linear(bx_address laddr, unsigned len, unsigned curr_pl, unsigned xlate_rw, Bit32u ac_mask, void* data);
    int access_write_linear(bx_address laddr, unsigned len, unsigned curr_pl, unsigned xlate_rw, Bit32u ac_mask, void* data);
    void page_fault(unsigned fault, bx_address laddr, unsigned user, unsigned rw);

    void map_physical_page(bx_phy_address paddr, unsigned rw);
    void access_read_physical(bx_phy_address paddr, unsigned len, void* data);
    void access_write_physical(bx_phy_address paddr, unsigned len, void* data);

    bx_hostpageaddr_t get_host_address(bx_phy_address addr, unsigned rw);

    // linear address for translate_linear expected to be canonical !
    bx_phy_address translate_linear(bx_TLB_entry* entry, bx_address laddr, unsigned user, unsigned rw);
    void update_access_dirty(bx_phy_address* entry_addr, Bit32u* entry, BxMemtype* entry_memtype, unsigned leaf, unsigned write);
#if BX_SUPPORT_X86_64
    bx_phy_address translate_linear_long_mode(bx_address laddr, Bit32u& lpf_mask, unsigned user, unsigned rw);
#endif

#if BX_CPU_LEVEL >= 6
    void TLB_flushNonGlobal(void);
#endif
    void TLB_flush(void);
    void TLB_invlpg(bx_address laddr);
    void inhibit_interrupts(unsigned mask);
    bool interrupts_inhibited(unsigned mask);
    const char* strseg(bx_segment_reg_t* seg);
    void interrupt(Bit8u vector, unsigned type, bool push_error, Bit16u error_code);
    void real_mode_int(Bit8u vector, bool push_error, Bit16u error_code);
    void protected_mode_int(Bit8u vector, bool soft_int, bool push_error, Bit16u error_code);
#if BX_SUPPORT_X86_64
    void long_mode_int(Bit8u vector, bool soft_int, bool push_error, Bit16u error_code);
#endif
    [[noreturn]] void exception(unsigned vector, Bit16u error_code);
    void init_SMRAM(void);
    int  int_number(unsigned s);

    bool SetCR0(bxInstruction_c* i, bx_address val);
    bool check_CR0(bx_address val) BX_CPP_AttrRegparmN(1);
    bool SetCR3(bx_address val) BX_CPP_AttrRegparmN(1);
#if BX_CPU_LEVEL >= 5
    bool SetCR4(bxInstruction_c* i, bx_address val);
    bool check_CR4(bx_address val) BX_CPP_AttrRegparmN(1);
    Bit32u get_cr4_allow_mask(void);
#endif
#if BX_CPU_LEVEL >= 6
    bool CheckPDPTR(bx_phy_address cr3_val) BX_CPP_AttrRegparmN(1);
#endif
#if BX_CPU_LEVEL >= 5
    bool SetEFER(bx_address val) BX_CPP_AttrRegparmN(1);
#endif

    bx_address read_CR0(void);
#if BX_CPU_LEVEL >= 5
    bx_address read_CR4(void);
#endif
#if BX_CPU_LEVEL >= 6
    Bit32u ReadCR8(bxInstruction_c* i);
    void WriteCR8(bxInstruction_c* i, bx_address val);
#endif

    void reset(unsigned source);
    void shutdown(void);
    void enter_sleep_state(unsigned state);
    void handleCpuModeChange(void);
    void handleCpuContextChange(void);
    void handleInterruptMaskChange(void);
#if BX_CPU_LEVEL >= 4
    void handleAlignmentCheck(void);
#endif
#if BX_CPU_LEVEL >= 6
    void handleSseModeChange(void);
    void handleAvxModeChange(void);
#endif

#if BX_SUPPORT_AVX
    void avx_masked_load8(bxInstruction_c* i, bx_address eaddr, BxPackedAvxRegister* dst, Bit64u mask);
    void avx_masked_load16(bxInstruction_c* i, bx_address eaddr, BxPackedAvxRegister* dst, Bit32u mask);
    void avx_masked_load32(bxInstruction_c* i, bx_address eaddr, BxPackedAvxRegister* dst, Bit32u mask);
    void avx_masked_load64(bxInstruction_c* i, bx_address eaddr, BxPackedAvxRegister* dst, Bit32u mask);
    void avx_masked_store8(bxInstruction_c* i, bx_address eaddr, const BxPackedAvxRegister* op, Bit64u mask);
    void avx_masked_store16(bxInstruction_c* i, bx_address eaddr, const BxPackedAvxRegister* op, Bit32u mask);
    void avx_masked_store32(bxInstruction_c* i, bx_address eaddr, const BxPackedAvxRegister* op, Bit32u mask);
    void avx_masked_store64(bxInstruction_c* i, bx_address eaddr, const BxPackedAvxRegister* op, Bit32u mask);
#endif

#if BX_SUPPORT_EVEX
    void avx512_write_regb_masked(bxInstruction_c* i, const BxPackedAvxRegister* op, unsigned vlen, Bit64u mask);
    void avx512_write_regw_masked(bxInstruction_c* i, const BxPackedAvxRegister* op, unsigned vlen, Bit32u mask);
    void avx512_write_regd_masked(bxInstruction_c* i, const BxPackedAvxRegister* op, unsigned vlen, Bit32u mask);
    void avx512_write_regq_masked(bxInstruction_c* i, const BxPackedAvxRegister* op, unsigned vlen, Bit32u mask);
#endif

#if BX_CPU_LEVEL >= 5
    bool rdmsr(Bit32u index, Bit64u* val_64) BX_CPP_AttrRegparmN(2);
    bool handle_unknown_rdmsr(Bit32u index, Bit64u* val_64) BX_CPP_AttrRegparmN(2);
    bool wrmsr(Bit32u index, Bit64u  val_64) BX_CPP_AttrRegparmN(2);
    bool handle_unknown_wrmsr(Bit32u index, Bit64u  val_64) BX_CPP_AttrRegparmN(2);
#endif

#if BX_SUPPORT_APIC
    bool relocate_apic(Bit64u val_64);
#endif

    void load_segw(bxInstruction_c* i, unsigned seg) BX_CPP_AttrRegparmN(2);
    void load_segd(bxInstruction_c* i, unsigned seg) BX_CPP_AttrRegparmN(2);
    void load_segq(bxInstruction_c* i, unsigned seg) BX_CPP_AttrRegparmN(2);

    void jmp_far16(bxInstruction_c* i, Bit16u cs_raw, Bit16u disp16);
    void jmp_far32(bxInstruction_c* i, Bit16u cs_raw, Bit32u disp32);
    void call_far16(bxInstruction_c* i, Bit16u cs_raw, Bit16u disp16);
    void call_far32(bxInstruction_c* i, Bit16u cs_raw, Bit32u disp32);
    void task_gate(bxInstruction_c* i, bx_selector_t* selector, bx_descriptor_t* gate_descriptor, unsigned source);
    void jump_protected(bxInstruction_c* i, Bit16u cs, bx_address disp) BX_CPP_AttrRegparmN(3);
    void jmp_call_gate(bx_selector_t* selector, bx_descriptor_t* gate_descriptor) BX_CPP_AttrRegparmN(2);
    void call_gate(bx_descriptor_t* gate_descriptor) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
    void jmp_call_gate64(bx_selector_t* selector) BX_CPP_AttrRegparmN(1);
#endif
    void call_protected(bxInstruction_c* i, Bit16u cs, bx_address disp) BX_CPP_AttrRegparmN(3);
#if BX_SUPPORT_X86_64
    void call_gate64(bx_selector_t* selector) BX_CPP_AttrRegparmN(1);
#endif
    void return_protected(bxInstruction_c* i, Bit16u pop_bytes) BX_CPP_AttrRegparmN(2);
    void iret_protected(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
    void long_iret(bxInstruction_c*) BX_CPP_AttrRegparmN(1);
#endif
#if BX_SUPPORT_CET
    void shadow_stack_switch(bx_address new_SSP) BX_CPP_AttrRegparmN(1);
    void call_far_shadow_stack_push(Bit16u cs, bx_address lip, bx_address old_ssp) BX_CPP_AttrRegparmN(3);
    bx_address shadow_stack_restore(Bit16u raw_cs_selector, const bx_descriptor_t& cs_descriptor, bx_address return_rip) BX_CPP_AttrRegparmN(3);
#endif
    void validate_seg_reg(unsigned seg);
    void validate_seg_regs(void);
    void stack_return_to_v86(Bit32u new_eip, Bit32u raw_cs_selector, Bit32u flags32);
    void iret16_stack_return_from_v86(bxInstruction_c*);
    void iret32_stack_return_from_v86(bxInstruction_c*);
    int  v86_redirect_interrupt(Bit8u vector);
    void init_v8086_mode(void);
    void task_switch_load_selector(bx_segment_reg_t* seg,
        bx_selector_t* selector, Bit16u raw_selector, Bit8u cs_rpl);
    void task_switch(bxInstruction_c* i, bx_selector_t* selector, bx_descriptor_t* descriptor,
        unsigned source, Bit32u dword1, Bit32u dword2, bool push_error = 0, Bit32u error_code = 0);
    void get_SS_ESP_from_TSS(unsigned pl, Bit16u* ss, Bit32u* esp);
#if BX_SUPPORT_X86_64
    Bit64u get_RSP_from_TSS(unsigned pl);
#endif
    void write_flags(Bit16u flags, bool change_IOPL, bool change_IF) BX_CPP_AttrRegparmN(3);
    void writeEFlags(Bit32u eflags, Bit32u changeMask) BX_CPP_AttrRegparmN(2); // Newer variant.
    void write_eflags_fpu_compare(int float_relation);
    Bit32u force_flags(void);
    Bit32u read_eflags(void) { return BX_CPU_THIS_PTR force_flags(); }

    bool allow_io(bxInstruction_c* i, Bit16u addr, unsigned len) BX_CPP_AttrRegparmN(3);
    Bit32u  get_descriptor_l(const bx_descriptor_t*) BX_CPP_AttrRegparmN(1);
    Bit32u  get_descriptor_h(const bx_descriptor_t*) BX_CPP_AttrRegparmN(1);
    bool set_segment_ar_data(bx_segment_reg_t* seg, bool valid, Bit16u raw_selector,
        bx_address base, Bit32u limit_scaled, Bit16u ar_data);
    void    check_cs(bx_descriptor_t* descriptor, Bit16u cs_raw, Bit8u check_rpl, Bit8u check_cpl);
    // the basic assumption of the code that load_cs and load_ss cannot fail !
    void    load_cs(bx_selector_t* selector, bx_descriptor_t* descriptor, Bit8u cpl) BX_CPP_AttrRegparmN(3);
    void    load_ss(bx_selector_t* selector, bx_descriptor_t* descriptor, Bit8u cpl) BX_CPP_AttrRegparmN(3);
    void    touch_segment(bx_selector_t* selector, bx_descriptor_t* descriptor) BX_CPP_AttrRegparmN(2);
    void    fetch_raw_descriptor(const bx_selector_t* selector,
        Bit32u* dword1, Bit32u* dword2, unsigned exception_no);
    bool fetch_raw_descriptor2(const bx_selector_t* selector,
        Bit32u* dword1, Bit32u* dword2) BX_CPP_AttrRegparmN(3);
    void    load_seg_reg(bx_segment_reg_t* seg, Bit16u new_value) BX_CPP_AttrRegparmN(2);
    void    load_null_selector(bx_segment_reg_t* seg, unsigned value) BX_CPP_AttrRegparmN(2);
#if BX_SUPPORT_X86_64
    void    fetch_raw_descriptor_64(const bx_selector_t* selector,
        Bit32u* dword1, Bit32u* dword2, Bit32u* dword3, unsigned exception_no);
    bool fetch_raw_descriptor2_64(const bx_selector_t* selector,
        Bit32u* dword1, Bit32u* dword2, Bit32u* dword3);
#endif
    void    push_16(Bit16u value16) BX_CPP_AttrRegparmN(1);
    void    push_32(Bit32u value32) BX_CPP_AttrRegparmN(1);
    Bit16u  pop_16(void);
    Bit32u  pop_32(void);
#if BX_SUPPORT_X86_64
    void    push_64(Bit64u value64) BX_CPP_AttrRegparmN(1);
    Bit64u  pop_64(void);
#endif
#if BX_SUPPORT_CET
    void    shadow_stack_push_32(Bit32u value32) BX_CPP_AttrRegparmN(1);
    Bit32u  shadow_stack_pop_32(void);
    void    shadow_stack_push_64(Bit64u value64) BX_CPP_AttrRegparmN(1);
    Bit64u  shadow_stack_pop_64(void);
#endif
    void    sanity_checks(void);
    void    assert_checks(void);

    void    enter_system_management_mode(void);
    bool    resume_from_system_management_mode(BX_SMM_State* smm_state);
    void    smram_save_state(Bit32u* smm_saved_state);
    bool    smram_restore_state(const Bit32u* smm_saved_state);

    void    raise_INTR(void);
    void    clear_INTR(void);

    void    deliver_INIT(void);
    void    deliver_NMI(void);
    void    deliver_SMI(void);
    void    deliver_SIPI(unsigned vector);
    void    debug(bx_address offset);

#if BX_X86_DEBUGGER
    // x86 hardware debug support
    bool hwbreakpoint_check(bx_address laddr, unsigned opa, unsigned opb);
#if BX_CPU_LEVEL >= 5
    void    iobreakpoint_match(unsigned port, unsigned len);
#endif
    Bit32u  code_breakpoint_match(bx_address laddr);
    void    hwbreakpoint_match(bx_address laddr, unsigned len, unsigned rw);
    Bit32u  hwdebug_compare(bx_address laddr, unsigned len, unsigned opa, unsigned opb);
#endif

    void init_FetchDecodeTables(void);

#if BX_SUPPORT_APIC
    inline Bit8u get_apic_id(void) { return BX_CPU_THIS_PTR bx_cpuid; }
#endif

    inline bool is_cpu_extension_supported(unsigned extension) {
        assert(extension < BX_ISA_EXTENSION_LAST);
        return BX_CPU_THIS_PTR ia_extensions_bitmask[extension / 32] & (1 << (extension % 32));
    }

    inline unsigned which_cpu(void) { return BX_CPU_THIS_PTR bx_cpuid; }
    inline const bx_gen_reg_t* get_gen_regfile() { return BX_CPU_THIS_PTR gen_reg; }

    inline Bit64u get_icount(void) { return BX_CPU_THIS_PTR icount; }
    inline void sync_icount(void) { BX_CPU_THIS_PTR icount_last_sync = BX_CPU_THIS_PTR icount; }
    inline Bit64u get_icount_last_sync(void) { return BX_CPU_THIS_PTR icount_last_sync; }

    inline bx_address get_instruction_pointer(void);

    inline Bit32u get_eip(void) { return (BX_CPU_THIS_PTR gen_reg[BX_32BIT_REG_EIP].dword.erx); }
    inline Bit16u get_ip(void) { return (BX_CPU_THIS_PTR gen_reg[BX_16BIT_REG_IP].word.rx); }
#if BX_SUPPORT_X86_64
    inline Bit64u get_rip(void) { return (BX_CPU_THIS_PTR gen_reg[BX_64BIT_REG_RIP].rrx); }
#endif

    inline Bit32u get_cpl(void) { return (BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.rpl); }

#if BX_SUPPORT_CET
    inline bx_address get_ssp(void) { return (BX_CPU_THIS_PTR gen_reg[BX_64BIT_REG_SSP].rrx); }
#endif

    inline Bit8u get_reg8l(unsigned reg);
    inline Bit8u get_reg8h(unsigned reg);
    inline void  set_reg8l(unsigned reg, Bit8u val);
    inline void  set_reg8h(unsigned reg, Bit8u val);

    inline Bit16u get_reg16(unsigned reg);
    inline void   set_reg16(unsigned reg, Bit16u val);
    inline Bit32u get_reg32(unsigned reg);
    inline void   set_reg32(unsigned reg, Bit32u val);
#if BX_SUPPORT_X86_64
    inline Bit64u get_reg64(unsigned reg);
    inline void   set_reg64(unsigned reg, Bit64u val);
#endif
#if BX_SUPPORT_EVEX
    inline Bit64u get_opmask(unsigned reg);
    inline void set_opmask(unsigned reg, Bit64u val);
#endif

#if BX_CPU_LEVEL >= 6
    inline unsigned get_cr8();
#endif

    bx_address get_segment_base(unsigned seg);

    // The linear address must be truncated to the 32-bit when CPU is not
    // executing in long64 mode.  The function  must  be used  to compute
    // linear address everywhere when a code is shared between long64 and
    // legacy mode. For legacy mode only  just use Bit32u to store linear
    // address value.
    bx_address get_laddr(unsigned seg, bx_address offset);

    Bit32u get_laddr32(unsigned seg, Bit32u offset);
#if BX_SUPPORT_X86_64
    Bit64u get_laddr64(unsigned seg, Bit64u offset);
#endif

    bx_address agen_read(unsigned seg, bx_address offset, unsigned len);
    Bit32u agen_read32(unsigned seg, Bit32u offset, unsigned len);
    Bit32u agen_read_execute32(unsigned seg, Bit32u offset, unsigned len);
    bx_address agen_read_aligned(unsigned seg, bx_address offset, unsigned len);
    Bit32u agen_read_aligned32(unsigned seg, Bit32u offset, unsigned len);

    bx_address agen_write(unsigned seg, bx_address offset, unsigned len);
    Bit32u agen_write32(unsigned seg, Bit32u offset, unsigned len);
    bx_address agen_write_aligned(unsigned seg, bx_address offset, unsigned len);
    Bit32u agen_write_aligned32(unsigned seg, Bit32u offset, unsigned len);

    DECLARE_EFLAG_ACCESSOR(ID, 21)
    DECLARE_EFLAG_ACCESSOR(VIP, 20)
    DECLARE_EFLAG_ACCESSOR(VIF, 19)
    DECLARE_EFLAG_ACCESSOR(AC, 18)
    DECLARE_EFLAG_ACCESSOR(VM, 17)
    DECLARE_EFLAG_ACCESSOR(RF, 16)
    DECLARE_EFLAG_ACCESSOR(NT, 14)
    DECLARE_EFLAG_ACCESSOR_IOPL(12)
    DECLARE_EFLAG_ACCESSOR(DF, 10)
    DECLARE_EFLAG_ACCESSOR(IF, 9)
    DECLARE_EFLAG_ACCESSOR(TF, 8)

    inline bool real_mode(void);
    inline bool smm_mode(void);
    inline bool protected_mode(void);
    inline bool v8086_mode(void);
    inline bool long_mode(void);
    inline bool long64_mode(void);
    inline unsigned get_cpu_mode(void);

#if BX_SUPPORT_ALIGNMENT_CHECK && BX_CPU_LEVEL >= 4
    inline bool alignment_check(void);
#endif

#if BX_CPU_LEVEL >= 5
    Bit64u get_TSC();
    void   set_TSC(Bit64u tsc);
#endif

#if BX_SUPPORT_FPU
    void print_state_FPU(void);
    void prepareFPU(bxInstruction_c* i, bool = 1);
    void FPU_check_pending_exceptions(void);
    void FPU_update_last_instruction(bxInstruction_c* i);
    void FPU_stack_underflow(bxInstruction_c* i, int stnr, int pop_stack = 0);
    void FPU_stack_overflow(bxInstruction_c* i);
    unsigned FPU_exception(bxInstruction_c* i, unsigned exception, bool = 0);
    bx_address fpu_save_environment(bxInstruction_c* i);
    bx_address fpu_load_environment(bxInstruction_c* i);
    Bit8u pack_FPU_TW(Bit16u tag_word);
    Bit16u unpack_FPU_TW(Bit16u tag_byte);
    Bit16u x87_get_FCS(void);
    Bit16u x87_get_FDS(void);
#endif

#if BX_CPU_LEVEL >= 5
    void prepareMMX(void);
    void prepareFPU2MMX(void); /* cause transition from FPU to MMX technology state */
    void print_state_MMX(void);
#endif

#if BX_CPU_LEVEL >= 6
    void check_exceptionsSSE(int);
    void print_state_SSE(void);

    void prepareXSAVE(void);
    void print_state_AVX(void);
#endif

#if BX_CPU_LEVEL >= 6
    void xsave_xrestor_init(void);
    Bit32u get_xcr0_allow_mask(void);
    Bit32u get_ia32_xss_allow_mask(void);
    Bit32u get_xinuse_vector(Bit32u requested_feature_bitmap);

    bool xsave_x87_state_xinuse(void);
    void xsave_x87_state(bxInstruction_c* i, bx_address offset);
    void xrstor_x87_state(bxInstruction_c* i, bx_address offset);
    void xrstor_init_x87_state(void);

    bool xsave_sse_state_xinuse(void);
    void xsave_sse_state(bxInstruction_c* i, bx_address offset);
    void xrstor_sse_state(bxInstruction_c* i, bx_address offset);
    void xrstor_init_sse_state(void);

#if BX_SUPPORT_AVX
    bool xsave_ymm_state_xinuse(void);
    void xsave_ymm_state(bxInstruction_c* i, bx_address offset);
    void xrstor_ymm_state(bxInstruction_c* i, bx_address offset);
    void xrstor_init_ymm_state(void);
#if BX_SUPPORT_EVEX
    bool xsave_opmask_state_xinuse(void);
    void xsave_opmask_state(bxInstruction_c* i, bx_address offset);
    void xrstor_opmask_state(bxInstruction_c* i, bx_address offset);
    void xrstor_init_opmask_state(void);

    bool xsave_zmm_hi256_state_xinuse(void);
    void xsave_zmm_hi256_state(bxInstruction_c* i, bx_address offset);
    void xrstor_zmm_hi256_state(bxInstruction_c* i, bx_address offset);
    void xrstor_init_zmm_hi256_state(void);

    bool xsave_hi_zmm_state_xinuse(void);
    void xsave_hi_zmm_state(bxInstruction_c* i, bx_address offset);
    void xrstor_hi_zmm_state(bxInstruction_c* i, bx_address offset);
    void xrstor_init_hi_zmm_state(void);
#endif
#endif

#endif

#if BX_SUPPORT_MONITOR_MWAIT
    bool   is_monitor(bx_phy_address addr, unsigned len);
    void   check_monitor(bx_phy_address addr, unsigned len);
    void   wakeup_monitor(void);
#endif
};

#if BX_CPU_LEVEL >= 5
inline void BX_CPU_C::prepareMMX(void)
{
    if (BX_CPU_THIS_PTR cr0.get_EM())
        exception(BX_UD_EXCEPTION, 0);

    if (BX_CPU_THIS_PTR cr0.get_TS())
        exception(BX_NM_EXCEPTION, 0);

    /* check floating point status word for a pending FPU exceptions */
    FPU_check_pending_exceptions();
}

inline void BX_CPU_C::prepareFPU2MMX(void)
{
    BX_CPU_THIS_PTR the_i387.twd = 0;
    BX_CPU_THIS_PTR the_i387.tos = 0; /* reset FPU Top-Of-Stack */
}
#endif

#if BX_CPU_LEVEL >= 6
inline void BX_CPU_C::prepareXSAVE(void)
{
    if (!BX_CPU_THIS_PTR cr4.get_OSXSAVE())
        exception(BX_UD_EXCEPTION, 0);

    if (BX_CPU_THIS_PTR cr0.get_TS())
        exception(BX_NM_EXCEPTION, 0);
}
#endif

// Can be used as LHS or RHS.
#define RMAddr(i)  (BX_CPU_THIS_PTR address_xlation.rm_addr)

#if defined(NEED_CPU_REG_SHORTCUTS)

#if BX_SUPPORT_X86_64
inline Bit64u BX_CPP_AttrRegparmN(1) BX_CPU_C::BxResolve64(bxInstruction_c* i)
{
    Bit64u eaddr = (Bit64u)(BX_READ_64BIT_REG(i->sibBase()) + i->displ32s());
    if (i->sibIndex() != 4)
        eaddr += BX_READ_64BIT_REG(i->sibIndex()) << i->sibScale();
    return eaddr;
}
#endif

inline Bit32u BX_CPP_AttrRegparmN(1) BX_CPU_C::BxResolve32(bxInstruction_c* i)
{
    Bit32u eaddr = (Bit32u)(BX_READ_32BIT_REG(i->sibBase()) + i->displ32s());
    if (i->sibIndex() != 4)
        eaddr += BX_READ_32BIT_REG(i->sibIndex()) << i->sibScale();
    return eaddr & i->asize_mask();
}

#include "stack.h"

#define PRESERVE_RSP { BX_CPU_THIS_PTR prev_rsp = RSP; }
#if BX_SUPPORT_CET
#define PRESERVE_SSP { BX_CPU_THIS_PTR prev_ssp = SSP; }
#else
#define PRESERVE_SSP
#endif

#define RSP_SPECULATIVE {                 \
  BX_CPU_THIS_PTR speculative_rsp = true; \
  PRESERVE_RSP;                           \
  PRESERVE_SSP;                           \
}

#define RSP_COMMIT { BX_CPU_THIS_PTR speculative_rsp = false; }

#endif // defined(NEED_CPU_REG_SHORTCUTS)

//
// bit 0 - CS.D_B
// bit 1 - long64 mode (CS.L)
// bit 2 - SSE_OK
// bit 3 - AVX_OK
// bit 4 - OPMASK_OK
// bit 5 - EVEX_OK
//

enum {
    BX_FETCH_MODE_IS32_MASK = (1 << 0),
    BX_FETCH_MODE_IS64_MASK = (1 << 1),
    BX_FETCH_MODE_SSE_OK = (1 << 2),
    BX_FETCH_MODE_AVX_OK = (1 << 3),
    BX_FETCH_MODE_OPMASK_OK = (1 << 4),
    BX_FETCH_MODE_EVEX_OK = (1 << 5)
};

//
// updateFetchModeMask - has to be called everytime
//   CS.L / CS.D_B / CR0.PE, CR0.TS or CR0.EM / CR4.OSFXSR / CR4.OSXSAVE changes
//
inline void BX_CPU_C::updateFetchModeMask(void)
{
    BX_CPU_THIS_PTR fetchModeMask =
#if BX_CPU_LEVEL >= 6
#if BX_SUPPORT_EVEX
    (BX_CPU_THIS_PTR evex_ok << 5) | (BX_CPU_THIS_PTR opmask_ok << 4) |
#endif
#if BX_SUPPORT_AVX
    (BX_CPU_THIS_PTR avx_ok << 3) |
#endif
        (BX_CPU_THIS_PTR sse_ok << 2) |
#endif
#if BX_SUPPORT_X86_64
        ((BX_CPU_THIS_PTR cpu_mode == BX_MODE_LONG_64) << 1) |
#endif
        unsigned(BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.u.segment.d_b);    // typecast to keep MSVC warnings silent

    BX_CPU_THIS_PTR user_pl = // CPL == 3
        (BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.rpl == 3);
}

#if BX_X86_DEBUGGER
enum {
    BX_HWDebugInstruction = 0x00,
    BX_HWDebugMemW = 0x01,
    BX_HWDebugIO = 0x02,
    BX_HWDebugMemRW = 0x03
};
#endif

inline bx_address BX_CPU_C::get_segment_base(unsigned seg)
{
#if BX_SUPPORT_X86_64
    if (BX_CPU_THIS_PTR cpu_mode == BX_MODE_LONG_64) {
        if (seg < BX_SEG_REG_FS) return 0;
    }
#endif
    return BX_CPU_THIS_PTR sregs[seg].cache.u.segment.base;
}

inline Bit32u BX_CPU_C::get_laddr32(unsigned seg, Bit32u offset)
{
    return (Bit32u)BX_CPU_THIS_PTR sregs[seg].cache.u.segment.base + offset;
}

#if BX_SUPPORT_X86_64
inline Bit64u BX_CPU_C::get_laddr64(unsigned seg, Bit64u offset)
{
    if (seg < BX_SEG_REG_FS)
        return offset;
    else
        return BX_CPU_THIS_PTR sregs[seg].cache.u.segment.base + offset;
}
#endif

inline bx_address BX_CPU_C::get_laddr(unsigned seg, bx_address offset)
{
#if BX_SUPPORT_X86_64
    if (BX_CPU_THIS_PTR cpu_mode == BX_MODE_LONG_64) {
        return get_laddr64(seg, offset);
    }
#endif
    return get_laddr32(seg, (Bit32u)offset);
}

// same as agen_read32 but also allow access to execute only segments
inline Bit32u BX_CPU_C::agen_read_execute32(unsigned s, Bit32u offset, unsigned len)
{
    bx_segment_reg_t* seg = &BX_CPU_THIS_PTR sregs[s];

    if (seg->cache.valid & SegAccessROK4G) {
        return offset;
    }

    if (seg->cache.valid & SegAccessROK) {
        if (offset <= (seg->cache.u.segment.limit_scaled - len + 1)) {
            return get_laddr32(s, offset);
        }
    }

    if (!execute_virtual_checks(seg, offset, len))
        exception(int_number(s), 0);

    return get_laddr32(s, offset);
}

inline Bit32u BX_CPU_C::agen_read32(unsigned s, Bit32u offset, unsigned len)
{
    bx_segment_reg_t* seg = &BX_CPU_THIS_PTR sregs[s];

    if (seg->cache.valid & SegAccessROK4G) {
        return offset;
    }

    if (seg->cache.valid & SegAccessROK) {
        if (offset <= (seg->cache.u.segment.limit_scaled - len + 1)) {
            return get_laddr32(s, offset);
        }
    }

    if (!read_virtual_checks(seg, offset, len))
        exception(int_number(s), 0);

    return get_laddr32(s, offset);
}

inline Bit32u BX_CPU_C::agen_read_aligned32(unsigned s, Bit32u offset, unsigned len)
{
    bx_segment_reg_t* seg = &BX_CPU_THIS_PTR sregs[s];

    if (seg->cache.valid & SegAccessROK4G) {
        return offset;
    }

    if (seg->cache.valid & SegAccessROK) {
        if (offset <= (seg->cache.u.segment.limit_scaled - len + 1)) {
            return get_laddr32(s, offset);
        }
    }

    if (!read_virtual_checks(seg, offset, len, true /* aligned */))
        exception(int_number(s), 0);

    return get_laddr32(s, offset);
}

inline Bit32u BX_CPU_C::agen_write32(unsigned s, Bit32u offset, unsigned len)
{
    bx_segment_reg_t* seg = &BX_CPU_THIS_PTR sregs[s];

    if (seg->cache.valid & SegAccessWOK4G) {
        return offset;
    }

    if (seg->cache.valid & SegAccessWOK) {
        if (offset <= (seg->cache.u.segment.limit_scaled - len + 1)) {
            return get_laddr32(s, offset);
        }
    }

    if (!write_virtual_checks(seg, offset, len))
        exception(int_number(s), 0);

    return get_laddr32(s, offset);
}

inline Bit32u BX_CPU_C::agen_write_aligned32(unsigned s, Bit32u offset, unsigned len)
{
    bx_segment_reg_t* seg = &BX_CPU_THIS_PTR sregs[s];

    if (seg->cache.valid & SegAccessWOK4G) {
        return offset;
    }

    if (seg->cache.valid & SegAccessWOK) {
        if (offset <= (seg->cache.u.segment.limit_scaled - len + 1)) {
            return get_laddr32(s, offset);
        }
    }

    if (!write_virtual_checks(seg, offset, len, true /* aligned */))
        exception(int_number(s), 0);

    return get_laddr32(s, offset);
}

inline bx_address BX_CPU_C::agen_read(unsigned s, bx_address offset, unsigned len)
{
#if BX_SUPPORT_X86_64
    if (BX_CPU_THIS_PTR cpu_mode == BX_MODE_LONG_64) {
        return get_laddr64(s, offset);
    }
#endif
    return agen_read32(s, (Bit32u)offset, len);
}

inline bx_address BX_CPU_C::agen_read_aligned(unsigned s, bx_address offset, unsigned len)
{
#if BX_SUPPORT_X86_64
    if (BX_CPU_THIS_PTR cpu_mode == BX_MODE_LONG_64) {
        return get_laddr64(s, offset);
    }
#endif
    return agen_read_aligned32(s, (Bit32u)offset, len);
}

inline bx_address BX_CPU_C::agen_write(unsigned s, bx_address offset, unsigned len)
{
#if BX_SUPPORT_X86_64
    if (BX_CPU_THIS_PTR cpu_mode == BX_MODE_LONG_64) {
        return get_laddr64(s, offset);
    }
#endif
    return agen_write32(s, (Bit32u)offset, len);
}

inline bx_address BX_CPU_C::agen_write_aligned(unsigned s, bx_address offset, unsigned len)
{
#if BX_SUPPORT_X86_64
    if (BX_CPU_THIS_PTR cpu_mode == BX_MODE_LONG_64) {
        return get_laddr64(s, offset);
    }
#endif
    return agen_write_aligned32(s, (Bit32u)offset, len);
}

#include "access.h"

inline Bit8u BX_CPU_C::get_reg8l(unsigned reg)
{
    assert(reg < BX_GENERAL_REGISTERS);
    return (BX_CPU_THIS_PTR gen_reg[reg].word.byte.rl);
}

inline void BX_CPU_C::set_reg8l(unsigned reg, Bit8u val)
{
    assert(reg < BX_GENERAL_REGISTERS);
    BX_CPU_THIS_PTR gen_reg[reg].word.byte.rl = val;
}

inline Bit8u BX_CPU_C::get_reg8h(unsigned reg)
{
    assert(reg < BX_GENERAL_REGISTERS);
    return (BX_CPU_THIS_PTR gen_reg[reg].word.byte.rh);
}

inline void BX_CPU_C::set_reg8h(unsigned reg, Bit8u val)
{
    assert(reg < BX_GENERAL_REGISTERS);
    BX_CPU_THIS_PTR gen_reg[reg].word.byte.rh = val;
}

#if BX_SUPPORT_X86_64
inline bx_address BX_CPU_C::get_instruction_pointer(void)
{
    return BX_CPU_THIS_PTR get_rip();
}
#else
inline bx_address BX_CPU_C::get_instruction_pointer(void)
{
    return BX_CPU_THIS_PTR get_eip();
}
#endif

inline Bit16u BX_CPU_C::get_reg16(unsigned reg)
{
    assert(reg < BX_GENERAL_REGISTERS);
    return (BX_CPU_THIS_PTR gen_reg[reg].word.rx);
}

inline void BX_CPU_C::set_reg16(unsigned reg, Bit16u val)
{
    assert(reg < BX_GENERAL_REGISTERS);
    BX_CPU_THIS_PTR gen_reg[reg].word.rx = val;
}

inline Bit32u BX_CPU_C::get_reg32(unsigned reg)
{
    assert(reg < BX_GENERAL_REGISTERS);
    return (BX_CPU_THIS_PTR gen_reg[reg].dword.erx);
}

inline void BX_CPU_C::set_reg32(unsigned reg, Bit32u val)
{
    assert(reg < BX_GENERAL_REGISTERS);
    BX_CPU_THIS_PTR gen_reg[reg].dword.erx = val;
}

#if BX_SUPPORT_X86_64
inline Bit64u BX_CPU_C::get_reg64(unsigned reg)
{
    assert(reg < BX_GENERAL_REGISTERS);
    return (BX_CPU_THIS_PTR gen_reg[reg].rrx);
}

inline void BX_CPU_C::set_reg64(unsigned reg, Bit64u val)
{
    assert(reg < BX_GENERAL_REGISTERS);
    BX_CPU_THIS_PTR gen_reg[reg].rrx = val;
}
#endif

#if BX_SUPPORT_EVEX
inline Bit64u BX_CPU_C::get_opmask(unsigned reg)
{
    assert(reg < 8);
    return (BX_CPU_THIS_PTR opmask[reg].rrx);
}

inline void BX_CPU_C::set_opmask(unsigned reg, Bit64u val)
{
    assert(reg < 8);
    BX_CPU_THIS_PTR opmask[reg].rrx = val;
}
#endif

#if BX_CPU_LEVEL >= 6
// CR8 is aliased to APIC->TASK PRIORITY register
//   APIC.TPR[7:4] = CR8[3:0]
//   APIC.TPR[3:0] = 0
// Reads of CR8 return zero extended APIC.TPR[7:4]
inline unsigned BX_CPU_C::get_cr8(void)
{
    // TODO: R3 invalid
    return 0;
}
#endif

inline bool BX_CPU_C::real_mode(void)
{
    return (BX_CPU_THIS_PTR cpu_mode == BX_MODE_IA32_REAL);
}

inline bool BX_CPU_C::smm_mode(void)
{
    return (BX_CPU_THIS_PTR in_smm);
}

inline bool BX_CPU_C::v8086_mode(void)
{
    return (BX_CPU_THIS_PTR cpu_mode == BX_MODE_IA32_V8086);
}

inline bool BX_CPU_C::protected_mode(void)
{
    return (BX_CPU_THIS_PTR cpu_mode >= BX_MODE_IA32_PROTECTED);
}

inline bool BX_CPU_C::long_mode(void)
{
#if BX_SUPPORT_X86_64
    return BX_CPU_THIS_PTR efer.get_LMA();
#else
    return 0;
#endif
}

inline bool BX_CPU_C::long64_mode(void)
{
#if BX_SUPPORT_X86_64
    return (BX_CPU_THIS_PTR cpu_mode == BX_MODE_LONG_64);
#else
    return 0;
#endif
}

inline unsigned BX_CPU_C::get_cpu_mode(void)
{
    return (BX_CPU_THIS_PTR cpu_mode);
}

#if BX_SUPPORT_ALIGNMENT_CHECK && BX_CPU_LEVEL >= 4
inline bool BX_CPU_C::alignment_check(void)
{
    return BX_CPU_THIS_PTR alignment_check_mask;
}
#endif

IMPLEMENT_EFLAG_ACCESSOR(ID, 21)
IMPLEMENT_EFLAG_ACCESSOR(VIP, 20)
IMPLEMENT_EFLAG_ACCESSOR(VIF, 19)
IMPLEMENT_EFLAG_ACCESSOR(AC, 18)
IMPLEMENT_EFLAG_ACCESSOR(VM, 17)
IMPLEMENT_EFLAG_ACCESSOR(RF, 16)
IMPLEMENT_EFLAG_ACCESSOR(NT, 14)
IMPLEMENT_EFLAG_ACCESSOR_IOPL(12)
IMPLEMENT_EFLAG_ACCESSOR(DF, 10)
IMPLEMENT_EFLAG_ACCESSOR(IF, 9)
IMPLEMENT_EFLAG_ACCESSOR(TF, 8)

IMPLEMENT_EFLAG_SET_ACCESSOR(ID, 21)
IMPLEMENT_EFLAG_SET_ACCESSOR(VIP, 20)
IMPLEMENT_EFLAG_SET_ACCESSOR(VIF, 19)
#if BX_SUPPORT_ALIGNMENT_CHECK && BX_CPU_LEVEL >= 4
IMPLEMENT_EFLAG_SET_ACCESSOR_AC(18)
#else
IMPLEMENT_EFLAG_SET_ACCESSOR(AC, 18)
#endif
IMPLEMENT_EFLAG_SET_ACCESSOR_VM(17)
IMPLEMENT_EFLAG_SET_ACCESSOR_RF(16)
IMPLEMENT_EFLAG_SET_ACCESSOR(NT, 14)
IMPLEMENT_EFLAG_SET_ACCESSOR(DF, 10)
IMPLEMENT_EFLAG_SET_ACCESSOR_IF(9)
IMPLEMENT_EFLAG_SET_ACCESSOR_TF(8)

// hardware task switching
enum {
    BX_TASK_FROM_CALL = 0,
    BX_TASK_FROM_IRET = 1,
    BX_TASK_FROM_JUMP = 2,
    BX_TASK_FROM_INT = 3
};

// exception types for interrupt method
enum {
    BX_EXTERNAL_INTERRUPT = 0,
    BX_NMI = 2,
    BX_HARDWARE_EXCEPTION = 3,  // all exceptions except #BP and #OF
    BX_SOFTWARE_INTERRUPT = 4,
    BX_PRIVILEGED_SOFTWARE_INTERRUPT = 5,
    BX_SOFTWARE_EXCEPTION = 6
};

#if BX_CPU_LEVEL >= 6
enum {
    BX_INVPCID_INDIVIDUAL_ADDRESS_NON_GLOBAL_INVALIDATION,
    BX_INVPCID_SINGLE_CONTEXT_NON_GLOBAL_INVALIDATION,
    BX_INVPCID_ALL_CONTEXT_INVALIDATION,
    BX_INVPCID_ALL_CONTEXT_NON_GLOBAL_INVALIDATION
};
#endif

class bxInstruction_c;

#if BX_SUPPORT_HANDLERS_CHAINING_SPEEDUPS

#define BX_COMMIT_INSTRUCTION(i) {                     \
  BX_CPU_THIS_PTR prev_rip = RIP; /* commit new RIP */ \
  BX_INSTR_AFTER_EXECUTION(BX_CPU_ID, (i));            \
  BX_CPU_THIS_PTR icount++;                            \
}

#define BX_EXECUTE_INSTRUCTION(i) {                    \
  BX_INSTR_BEFORE_EXECUTION(BX_CPU_ID, (i));           \
  RIP += (i)->ilen();                                  \
  return BX_CPU_CALL_METHOD(i->execute1, (i));         \
}

#define BX_NEXT_TRACE(i) {                             \
  BX_COMMIT_INSTRUCTION(i);                            \
  return;                                              \
}

#if BX_ENABLE_TRACE_LINKING == 0
#define linkTrace(i)
#endif

#define BX_LINK_TRACE(i) {                             \
  BX_COMMIT_INSTRUCTION(i);                            \
  linkTrace(i);                                        \
  return;                                              \
}

#define BX_NEXT_INSTR(i) {                             \
  BX_COMMIT_INSTRUCTION(i);                            \
  if (BX_CPU_THIS_PTR async_event) return;             \
  ++i;                                                 \
  BX_EXECUTE_INSTRUCTION(i);                           \
}

#else // BX_SUPPORT_HANDLERS_CHAINING_SPEEDUPS

#define BX_NEXT_TRACE(i) { return; }
#define BX_NEXT_INSTR(i) { return; }
#define BX_LINK_TRACE(i) { return; }

#endif

#endif  // #ifndef BX_CPU_H
