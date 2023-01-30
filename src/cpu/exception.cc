/////////////////////////////////////////////////////////////////////////
// $Id$
/////////////////////////////////////////////////////////////////////////
//
//  Copyright (C) 2001-2019  The Bochs Project
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA B 02110-1301 USA
//
/////////////////////////////////////////////////////////////////////////

#define NEED_CPU_REG_SHORTCUTS 1
#include "bochs.h"
#include "cpu.h"
#define LOG_THIS BX_CPU_THIS_PTR

#if BX_SUPPORT_X86_64 == 0
// Make life easier merging cpu64 & cpu code.
#define RIP EIP
#define RSP ESP
#endif

#if BX_SUPPORT_X86_64
void BX_CPU_C::long_mode_int(Bit8u vector, bool soft_int, bool push_error, Bit16u error_code)
{
  // interrupt vector must be within IDT table limits,
  // else #GP(vector*8 + 2 + EXT)
  if ((vector * 8 + 15) > BX_CPU_THIS_PTR idtr.limit) {
    BX_ERROR(("interrupt(long mode): vector must be within IDT table limits, IDT.limit = 0x%x", BX_CPU_THIS_PTR idtr.limit));
    exception(BX_GP_EXCEPTION, vector * 8 + 2);
  }

  Bit64u handler = system_read_qword(BX_CPU_THIS_PTR idtr.base + vector * 8);

  if (handler == 0)
  {
    BX_ERROR(("interrupt(long mode): handler@%u dose not present", vector));
    exception(BX_GP_EXCEPTION, vector*8 + 2);
  }

  ((void(*)(BX_CPU_C*))handler)(this);

  BX_CPU_THIS_PTR clear_IF();
  BX_CPU_THIS_PTR clear_TF();
  BX_CPU_THIS_PTR clear_RF();
  BX_CPU_THIS_PTR clear_NT();
}
#endif

void BX_CPU_C::protected_mode_int(Bit8u vector, bool soft_int, bool push_error, Bit16u error_code)
{
  bx_descriptor_t gate_descriptor;

  Bit16u raw_tss_selector;
  bx_selector_t   tss_selector;
  bx_descriptor_t tss_descriptor;

  // interrupt vector must be within IDT table limits,
  // else #GP(vector*8 + 2 + EXT)
  if ((vector*8 + 7) > BX_CPU_THIS_PTR idtr.limit) {
    BX_ERROR(("interrupt(): vector must be within IDT table limits, IDT.limit = 0x%x", BX_CPU_THIS_PTR idtr.limit));
    exception(BX_GP_EXCEPTION, vector*8 + 2);
  }

  Bit64u desctmp = system_read_qword(BX_CPU_THIS_PTR idtr.base + vector*8);

  Bit32u dword1 = GET32L(desctmp);
  Bit32u dword2 = GET32H(desctmp);

  parse_descriptor(dword1, dword2, &gate_descriptor);

  if ((gate_descriptor.valid==0) || gate_descriptor.segment) {
    BX_ERROR(("interrupt(): gate descriptor is not valid sys seg (vector=0x%02x)", vector));
    exception(BX_GP_EXCEPTION, vector*8 + 2);
  }

  // descriptor AR byte must indicate interrupt gate, trap gate,
  // or task gate, else #GP(vector*8 + 2 + EXT)
  switch (gate_descriptor.type) {
  case BX_TASK_GATE:
  case BX_286_INTERRUPT_GATE:
  case BX_286_TRAP_GATE:
  case BX_386_INTERRUPT_GATE:
  case BX_386_TRAP_GATE:
    break;
  default:
    BX_ERROR(("interrupt(): gate.type(%u) != {5,6,7,14,15}",
      (unsigned) gate_descriptor.type));
    exception(BX_GP_EXCEPTION, vector*8 + 2);
  }

  // if software interrupt, then gate descriptor DPL must be >= CPL,
  // else #GP(vector * 8 + 2 + EXT)
  if (soft_int && gate_descriptor.dpl < CPL) {
    BX_ERROR(("interrupt(): soft_int && (gate.dpl < CPL)"));
    exception(BX_GP_EXCEPTION, vector*8 + 2);
  }

  // Gate must be present, else #NP(vector * 8 + 2 + EXT)
  if (! IS_PRESENT(gate_descriptor)) {
    BX_ERROR(("interrupt(): gate not present"));
    exception(BX_NP_EXCEPTION, vector*8 + 2);
  }

  switch (gate_descriptor.type) {
  case BX_TASK_GATE:
    // examine selector to TSS, given in task gate descriptor
    raw_tss_selector = gate_descriptor.u.taskgate.tss_selector;
    parse_selector(raw_tss_selector, &tss_selector);

    // must specify global in the local/global bit,
    //      else #GP(TSS selector)
    if (tss_selector.ti) {
      BX_ERROR(("interrupt(): tss_selector.ti=1 from gate descriptor - #GP(tss_selector)"));
      exception(BX_GP_EXCEPTION, raw_tss_selector & 0xfffc);
    }

    // index must be within GDT limits, else #TS(TSS selector)
    fetch_raw_descriptor(&tss_selector, &dword1, &dword2, BX_GP_EXCEPTION);

    parse_descriptor(dword1, dword2, &tss_descriptor);

    // AR byte must specify available TSS,
    //   else #GP(TSS selector)
    if (tss_descriptor.valid==0 || tss_descriptor.segment) {
      BX_ERROR(("interrupt(): TSS selector points to invalid or bad TSS - #GP(tss_selector)"));
      exception(BX_GP_EXCEPTION, raw_tss_selector & 0xfffc);
    }

    if (tss_descriptor.type!=BX_SYS_SEGMENT_AVAIL_286_TSS &&
        tss_descriptor.type!=BX_SYS_SEGMENT_AVAIL_386_TSS)
    {
      BX_ERROR(("interrupt(): TSS selector points to bad TSS - #GP(tss_selector)"));
      exception(BX_GP_EXCEPTION, raw_tss_selector & 0xfffc);
    }

    // TSS must be present, else #NP(TSS selector)
    if (! IS_PRESENT(tss_descriptor)) {
      BX_ERROR(("interrupt(): TSS descriptor.p == 0"));
      exception(BX_NP_EXCEPTION, raw_tss_selector & 0xfffc);
    }

    // switch tasks with nesting to TSS
    //task_switch(0, &tss_selector, &tss_descriptor,
                    //BX_TASK_FROM_INT, dword1, dword2, push_error, error_code);
    return;

  default:
    BX_PANIC(("bad descriptor type in interrupt()!"));
    break;
  }
}

void BX_CPU_C::real_mode_int(Bit8u vector, bool push_error, Bit16u error_code)
{
  if ((vector*4+3) > BX_CPU_THIS_PTR idtr.limit) {
    BX_ERROR(("interrupt(real mode) vector > idtr.limit"));
    exception(BX_GP_EXCEPTION, 0);
  }

  push_16((Bit16u) read_eflags());
  push_16(BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.value);
  push_16(IP);

  Bit16u new_ip = system_read_word(BX_CPU_THIS_PTR idtr.base + 4 * vector);
  // CS.LIMIT can't change when in real/v8086 mode
  if (new_ip > BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.u.segment.limit_scaled) {
    BX_ERROR(("interrupt(real mode): instruction pointer not within code segment limits"));
    exception(BX_GP_EXCEPTION, 0);
  }

  Bit16u cs_selector = system_read_word(BX_CPU_THIS_PTR idtr.base + 4 * vector + 2);
  load_seg_reg(&BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS], cs_selector);
  EIP = new_ip;

  /* INT affects the following flags: I,T */
  BX_CPU_THIS_PTR clear_IF();
  BX_CPU_THIS_PTR clear_TF();
#if BX_CPU_LEVEL >= 4
  BX_CPU_THIS_PTR clear_AC();
#endif
  BX_CPU_THIS_PTR clear_RF();
}

void BX_CPU_C::interrupt(Bit8u vector, unsigned type, bool push_error, Bit16u error_code)
{
#if BX_DEBUGGER
  BX_CPU_THIS_PTR show_flag |= Flag_intsig;
#if BX_DEBUG_LINUX
  if (bx_dbg.linux_syscall) {
    if (vector == 0x80) bx_dbg_linux_syscall(BX_CPU_ID);
  }
#endif
  bx_dbg_interrupt(BX_CPU_ID, vector, error_code);
#endif

  BX_INSTR_INTERRUPT(BX_CPU_ID, vector);

  invalidate_prefetch_q();

  bool soft_int = false;
  switch(type) {
    case BX_SOFTWARE_INTERRUPT:
    case BX_SOFTWARE_EXCEPTION:
      soft_int = true;
      break;
    case BX_PRIVILEGED_SOFTWARE_INTERRUPT:
    case BX_EXTERNAL_INTERRUPT:
    case BX_NMI:
    case BX_HARDWARE_EXCEPTION:
      break;

    default:
      BX_PANIC(("interrupt(): unknown exception type %d", type));
  }

  BX_DEBUG(("interrupt(): vector = %02x, TYPE = %u, EXT = %u",
      vector, type, (unsigned) BX_CPU_THIS_PTR EXT));

  // Discard any traps and inhibits for new context; traps will
  // resume upon return.
  BX_CPU_THIS_PTR debug_trap = 0;
  BX_CPU_THIS_PTR inhibit_mask = 0;

  RSP_SPECULATIVE;

  if (long_mode()) {
    long_mode_int(vector, soft_int, push_error, error_code);
  }
  else
  {
    // software interrupt can be redirected in v8086 mode
    if (type != BX_SOFTWARE_INTERRUPT || !v8086_mode() || !v86_redirect_interrupt(vector))
    {
      if(real_mode()) {
        real_mode_int(vector, push_error, error_code);
      }
      else {
        protected_mode_int(vector, soft_int, push_error, error_code);
      }
    }
  }

  RSP_COMMIT;

#if BX_X86_DEBUGGER
  BX_CPU_THIS_PTR in_repeat = false;
#endif

  BX_CPU_THIS_PTR EXT = 0;
}

/* Exception classes.  These are used as indexes into the 'is_exception_OK'
 * array below, and are stored in the 'exception' array also
 */
enum {
  BX_ET_BENIGN = 0,
  BX_ET_CONTRIBUTORY = 1,
  BX_ET_PAGE_FAULT = 2,
  BX_ET_DOUBLE_FAULT = 10
};

static const bool is_exception_OK[3][3] = {
    { 1, 1, 1 }, /* 1st exception is BENIGN */
    { 1, 0, 1 }, /* 1st exception is CONTRIBUTORY */
    { 1, 0, 0 }  /* 1st exception is PAGE_FAULT */
};

enum {
  BX_EXCEPTION_CLASS_TRAP = 0,
  BX_EXCEPTION_CLASS_FAULT = 1,
  BX_EXCEPTION_CLASS_ABORT = 2
};

struct BxExceptionInfo exceptions_info[BX_CPU_HANDLED_EXCEPTIONS] = {
  /* DE */ { BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 0 },
  /* DB */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 02 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 }, // NMI
  /* BP */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_TRAP,  0 },
  /* OF */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_TRAP,  0 },
  /* BR */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* UD */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* NM */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* DF */ { BX_ET_DOUBLE_FAULT, BX_EXCEPTION_CLASS_FAULT, 1 },
             // coprocessor segment overrun (286,386 only)
  /* 09 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* TS */ { BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1 },
  /* NP */ { BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1 },
  /* SS */ { BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1 },
  /* GP */ { BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1 },
  /* PF */ { BX_ET_PAGE_FAULT,   BX_EXCEPTION_CLASS_FAULT, 1 },
  /* 15 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 }, // reserved
  /* MF */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* AC */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 1 },
  /* MC */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_ABORT, 0 },
  /* XM */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* VE */ { BX_ET_PAGE_FAULT,   BX_EXCEPTION_CLASS_FAULT, 0 },
  /* CP */ { BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1 },
  /* 22 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 23 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 24 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 25 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 26 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 27 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 28 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 29 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 30 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 }, // FIXME: SVM #SF
  /* 31 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 }
};

// vector:     0..255: vector in IDT
// error_code: if exception generates and error, push this error code
void BX_CPU_C::exception(unsigned vector, Bit16u error_code)
{
  unsigned exception_type = 0;
  unsigned exception_class = BX_EXCEPTION_CLASS_FAULT;
  bool push_error = false;

  if (vector < BX_CPU_HANDLED_EXCEPTIONS) {
     push_error = exceptions_info[vector].push_error;
     exception_class = exceptions_info[vector].exception_class;
     exception_type = exceptions_info[vector].exception_type;
  }
  else {
     BX_PANIC(("exception(%u): bad vector", vector));
  }

  /* Excluding page faults and double faults, error_code may not have the
   * least significant bit set correctly. This correction is applied first
   * to make the change transparent to any instrumentation.
   */
  if (vector != BX_PF_EXCEPTION && vector != BX_DF_EXCEPTION && vector != BX_CP_EXCEPTION) {
    // Page faults have different format
    error_code = (error_code & 0xfffe) | (Bit16u)(BX_CPU_THIS_PTR EXT);
  }

  BX_INSTR_EXCEPTION(BX_CPU_ID, vector, error_code);

#if BX_DEBUGGER
  bx_dbg_exception(BX_CPU_ID, vector, error_code);
#endif

  BX_DEBUG(("exception(0x%02x): error_code=%04x", vector, error_code));

  if (exception_class == BX_EXCEPTION_CLASS_FAULT)
  {
    // restore RIP/RSP to value before error occurred
    RIP = BX_CPU_THIS_PTR prev_rip;
    if (BX_CPU_THIS_PTR speculative_rsp) {
      RSP = BX_CPU_THIS_PTR prev_rsp;
    }
    BX_CPU_THIS_PTR speculative_rsp = false;

    if (BX_CPU_THIS_PTR last_exception_type == BX_ET_DOUBLE_FAULT)
    {
      debug(BX_CPU_THIS_PTR prev_rip); // print debug information to the log
#if BX_DEBUGGER
      // trap into debugger (the same as when a PANIC occurs)
      bx_debug_break();
#endif
      BX_PANIC(("exception(): 3rd (%d) exception with no resolution", vector));
      BX_ERROR(("WARNING: Any simulation after this point is completely bogus !"));
      shutdown();
      longjmp(BX_CPU_THIS_PTR jmp_buf_env, 1); // go back to main decode loop
    }

    if (vector != BX_DB_EXCEPTION) BX_CPU_THIS_PTR assert_RF();
  }

  if (vector == BX_DB_EXCEPTION) {
    // Commit debug events to DR6: preserve DR5.BS and DR6.BD values,
    // only software can clear them
    BX_CPU_THIS_PTR dr6.val32 = (BX_CPU_THIS_PTR dr6.val32  & 0xffff6ff0) |
                                (BX_CPU_THIS_PTR debug_trap & 0x0000e00f);

    // clear GD flag in the DR7 prior entering debug exception handler
    BX_CPU_THIS_PTR dr7.set_GD(0);
  }

  BX_CPU_THIS_PTR EXT = 1;

  /* if we've already had 1st exception, see if 2nd causes a
   * Double Fault instead. Otherwise, just record 1st exception.
   */
  if (exception_type != BX_ET_DOUBLE_FAULT) {
    if (! is_exception_OK[BX_CPU_THIS_PTR last_exception_type][exception_type]) {
      exception(BX_DF_EXCEPTION, 0);
    }
  }

  BX_CPU_THIS_PTR last_exception_type = exception_type;

  if (real_mode()) {
    push_error = false; // not INT, no error code pushed
    error_code = 0;
  }

  interrupt(vector, BX_HARDWARE_EXCEPTION, push_error, error_code);

  BX_CPU_THIS_PTR last_exception_type = 0; // error resolved

  longjmp(BX_CPU_THIS_PTR jmp_buf_env, 1); // go back to main decode loop
}
