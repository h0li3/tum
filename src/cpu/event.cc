/////////////////////////////////////////////////////////////////////////
// $Id$
/////////////////////////////////////////////////////////////////////////
//
//   Copyright (c) 2011-2013 Stanislav Shwartsman
//          Written by Stanislav Shwartsman [sshwarts at sourceforge net]
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
/////////////////////////////////////////////////////////////////////////

#define NEED_CPU_REG_SHORTCUTS 1
#include "bochs.h"
#include "cpu.h"
#define LOG_THIS BX_CPU_THIS_PTR

bool BX_CPU_C::handleWaitForEvent(void)
{
  if (BX_CPU_THIS_PTR activity_state == BX_ACTIVITY_STATE_WAIT_FOR_SIPI) {
    // HALT condition remains, return so other CPUs have a chance
#if BX_DEBUGGER
    BX_CPU_THIS_PTR stop_reason = STOP_CPU_HALTED;
#endif
    return 1; // Return to caller of cpu_loop.
  }

  // For one processor, pass the time as quickly as possible until
  // an interrupt wakes up the CPU.
  while (1)
  {
    if ((is_pending(BX_EVENT_PENDING_INTR | BX_EVENT_PENDING_LAPIC_INTR) && (BX_CPU_THIS_PTR get_IF() || BX_CPU_THIS_PTR activity_state == BX_ACTIVITY_STATE_MWAIT_IF)) ||
         is_unmasked_event_pending(BX_EVENT_NMI | BX_EVENT_SMI | BX_EVENT_INIT |
            BX_EVENT_VMX_VTPR_UPDATE |
            BX_EVENT_VMX_VEOI_UPDATE |
            BX_EVENT_VMX_VIRTUAL_APIC_WRITE |
            BX_EVENT_VMX_MONITOR_TRAP_FLAG |
            BX_EVENT_VMX_VIRTUAL_NMI))
    {
      // interrupt ends the HALT condition
#if BX_SUPPORT_MONITOR_MWAIT
      if (BX_CPU_THIS_PTR activity_state >= BX_ACTIVITY_STATE_MWAIT)
        BX_CPU_THIS_PTR monitor.reset_monitor();
#endif
      BX_CPU_THIS_PTR activity_state = BX_ACTIVITY_STATE_ACTIVE;
      BX_CPU_THIS_PTR inhibit_mask = 0; // clear inhibits for after resume
      break;
    }

    if (is_unmasked_event_pending(BX_EVENT_VMX_PREEMPTION_TIMER_EXPIRED)) {
      // Exit from waiting loop and proceed to VMEXIT
      break;
    }

    if (BX_CPU_THIS_PTR activity_state == BX_ACTIVITY_STATE_ACTIVE) {
      // happens also when MWAIT monitor was hit
//    BX_INFO(("handleWaitForEvent: reset detected in HLT state"));
      break;
    }

/*
    if (BX_HRQ && BX_DBG_ASYNC_DMA) {
      // handle DMA also when CPU is halted
      DEV_dma_raise_hlda();
    }

*/
    // for multiprocessor simulation, even if this CPU is halted we still
    // must give the others a chance to simulate.  If an interrupt has
    // arrived, then clear the HALT condition; otherwise just return from
    // the CPU loop with stop_reason STOP_CPU_HALTED.
#if BX_SUPPORT_SMP
    if (BX_SMP_PROCESSORS > 1) {
      // HALT condition remains, return so other CPUs have a chance
#if BX_DEBUGGER
      BX_CPU_THIS_PTR stop_reason = STOP_CPU_HALTED;
#endif
      return 1; // Return to caller of cpu_loop.
    }
#endif

#if BX_DEBUGGER
    if (bx_guard.interrupt_requested)
      return 1; // Return to caller of cpu_loop.
#endif
  }

  return 0;
}

void BX_CPU_C::InterruptAcknowledge(void)
{
  Bit8u vector = 0;

  BX_CPU_THIS_PTR EXT = 1; /* external event */

  BX_INSTR_HWINTERRUPT(BX_CPU_ID, vector,
      BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.value, RIP);
  interrupt(vector, BX_EXTERNAL_INTERRUPT, 0, 0);

  BX_CPU_THIS_PTR prev_rip = RIP; // commit new RIP
}

#if BX_SUPPORT_SVM
void BX_CPU_C::VirtualInterruptAcknowledge(void)
{
  Bit8u vector = SVM_V_INTR_VECTOR;

  if (SVM_INTERCEPT(SVM_INTERCEPT0_VINTR)) Svm_Vmexit(SVM_VMEXIT_VINTR);

  clear_event(BX_EVENT_SVM_VIRQ_PENDING);

  BX_CPU_THIS_PTR EXT = 1; /* external event */

  BX_INSTR_HWINTERRUPT(BX_CPU_ID, vector,
      BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.value, RIP);
  interrupt(vector, BX_EXTERNAL_INTERRUPT, 0, 0);

  BX_CPU_THIS_PTR prev_rip = RIP; // commit new RIP
}
#endif

bool BX_CPU_C::handleAsyncEvent(void)
{
  //
  // This area is where we process special conditions and events.
  //
  if (BX_CPU_THIS_PTR activity_state != BX_ACTIVITY_STATE_ACTIVE) {
    // For one processor, pass the time as quickly as possible until
    // an interrupt wakes up the CPU.
    if (handleWaitForEvent()) return 1;
  }

  // Priority 1: Hardware Reset and Machine Checks
  //   RESET
  //   Machine Check
  // (bochs doesn't support these)

#if BX_SUPPORT_SVM
  // debug exceptions or trap due to breakpoint register match
  // ignored and discarded if GIF == 0
  // debug traps due to EFLAGS.TF remain untouched
  if (! BX_CPU_THIS_PTR svm_gif)
    BX_CPU_THIS_PTR debug_trap &= BX_DEBUG_SINGLE_STEP_BIT;
#endif

  // APIC virtualization trap take priority over SMI, INIT and lower priority events and
  // not blocked by EFLAGS.IF or interrupt inhibits by MOV_SS and STI
#if BX_SUPPORT_VMX && BX_SUPPORT_X86_64
  if (is_unmasked_event_pending(BX_EVENT_VMX_VTPR_UPDATE |
                                BX_EVENT_VMX_VEOI_UPDATE | BX_EVENT_VMX_VIRTUAL_APIC_WRITE))
  {
    VMX_Virtual_Apic_Access_Trap();
  }
#endif

  // Priority 2: Trap on Task Switch
  //   T flag in TSS is set
  if (BX_CPU_THIS_PTR debug_trap & BX_DEBUG_TRAP_TASK_SWITCH_BIT) {
    exception(BX_DB_EXCEPTION, 0); // no error, not interrupt
  }

  // Priority 3: External Hardware Interventions
  //   FLUSH
  //   STOPCLK
  //   SMI
  //   INIT

  // Priority 4: Traps on Previous Instruction
  //   Breakpoints
  //   Debug Trap Exceptions (TF flag set or data/IO breakpoint)
  if (! interrupts_inhibited(BX_INHIBIT_DEBUG)) {
    // A trap may be inhibited on this boundary due to an instruction which loaded SS
#if BX_X86_DEBUGGER
    // Pages with code breakpoints always have async_event=1 and therefore come here
    BX_CPU_THIS_PTR debug_trap |= code_breakpoint_match(get_laddr(BX_SEG_REG_CS, BX_CPU_THIS_PTR prev_rip));
#endif
    if (BX_CPU_THIS_PTR debug_trap & 0xf000) {
      exception(BX_DB_EXCEPTION, 0); // no error, not interrupt
    }
    else {
      BX_CPU_THIS_PTR debug_trap = 0;
    }
  }

  // Priority 5: External Interrupts
  //   NMI Interrupts
  //   Maskable Hardware Interrupts
  if (interrupts_inhibited(BX_INHIBIT_INTERRUPTS)) {
    // Processing external interrupts is inhibited on this
    // boundary because of certain instructions like STI.
  }
  else if (is_unmasked_event_pending(BX_EVENT_NMI)) {
    clear_event(BX_EVENT_NMI);
    mask_event(BX_EVENT_NMI);
    BX_CPU_THIS_PTR EXT = 1; /* external event */
    BX_INSTR_HWINTERRUPT(BX_CPU_ID, 2, BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.value, RIP);
    interrupt(2, BX_NMI, 0, 0);
  }
  else if (is_unmasked_event_pending(BX_EVENT_PENDING_INTR | BX_EVENT_PENDING_LAPIC_INTR |
                                     BX_EVENT_PENDING_VMX_VIRTUAL_INTR))
  {
    InterruptAcknowledge();
  }

  if (BX_CPU_THIS_PTR get_TF())
  {
    // TF is set before execution of next instruction.  Schedule
    // a debug trap (#DB) after execution.  After completion of
    // next instruction, the code above will invoke the trap.
    BX_CPU_THIS_PTR debug_trap |= BX_DEBUG_SINGLE_STEP_BIT;
  }

  // Priority 6: Faults from fetching next instruction
  //   Code breakpoint fault
  //   Code segment limit violation (priority 7 on 486/Pentium)
  //   Code page fault (priority 7 on 486/Pentium)
  // (handled in main decode loop)

  // Priority 7: Faults from decoding next instruction
  //   Instruction length > 15 bytes
  //   Illegal opcode
  //   Coprocessor not available
  // (handled in main decode loop etc)

  // Priority 8: Faults on executing an instruction
  //   Floating point execution
  //   Overflow
  //   Bound error
  //   Invalid TSS
  //   Segment not present
  //   Stack fault
  //   General protection
  //   Data page fault
  //   Alignment check
  // (handled by rest of the code)

  return 0; // Continue executing cpu_loop.
}

// Certain instructions inhibit interrupts, some debug exceptions and single-step traps.
void BX_CPU_C::inhibit_interrupts(unsigned mask)
{
  // Loading of SS disables interrupts until the next instruction completes
  // but only under assumption that previous instruction didn't load SS also.
  if (mask != BX_INHIBIT_INTERRUPTS_BY_MOVSS || ! interrupts_inhibited(BX_INHIBIT_INTERRUPTS_BY_MOVSS)) {
    BX_DEBUG(("inhibit interrupts mask = %d", mask));
    BX_CPU_THIS_PTR inhibit_mask = mask;
    BX_CPU_THIS_PTR inhibit_icount = get_icount() + 1; // inhibit for next instruction
  }
}

bool BX_CPU_C::interrupts_inhibited(unsigned mask)
{
  return (get_icount() <= BX_CPU_THIS_PTR inhibit_icount) && (BX_CPU_THIS_PTR inhibit_mask & mask) == mask;
}

void BX_CPU_C::deliver_SIPI(unsigned vector)
{
  if (BX_CPU_THIS_PTR activity_state == BX_ACTIVITY_STATE_WAIT_FOR_SIPI) {
    BX_CPU_THIS_PTR activity_state = BX_ACTIVITY_STATE_ACTIVE;
    RIP = 0;
    load_seg_reg(&BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS], vector*0x100);
    unmask_event(BX_EVENT_INIT | BX_EVENT_SMI | BX_EVENT_NMI);
    BX_INFO(("CPU %d started up at %04X:%08X by APIC",
                   BX_CPU_THIS_PTR bx_cpuid, vector*0x100, EIP));
  } else {
    BX_INFO(("CPU %d started up by APIC, but was not halted at that time", BX_CPU_THIS_PTR bx_cpuid));
  }
}

void BX_CPU_C::deliver_INIT(void)
{
  if (! is_masked_event(BX_EVENT_INIT)) {
    signal_event(BX_EVENT_INIT);
  }
}

void BX_CPU_C::deliver_NMI(void)
{
  signal_event(BX_EVENT_NMI);
}

void BX_CPU_C::deliver_SMI(void)
{
  signal_event(BX_EVENT_SMI);
}

void BX_CPU_C::raise_INTR(void)
{
  signal_event(BX_EVENT_PENDING_INTR);
}

void BX_CPU_C::clear_INTR(void)
{
  clear_event(BX_EVENT_PENDING_INTR);
}

#if BX_DEBUGGER

void BX_CPU_C::dbg_take_dma(void)
{
  // NOTE: similar code in ::cpu_loop()
  if (BX_HRQ) {
    BX_CPU_THIS_PTR async_event = 1; // set in case INTR is triggered
    DEV_dma_raise_hlda();
  }
}

#endif  // #if BX_DEBUGGER
