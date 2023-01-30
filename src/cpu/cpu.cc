#define NEED_CPU_REG_SHORTCUTS 1
#include "bochs.h"
#include "cpu.h"
#define LOG_THIS BX_CPU_THIS_PTR

#include "memory/memory-bochs.h"
#include "cpustats.h"

#if BX_SUPPORT_HANDLERS_CHAINING_SPEEDUPS

#define BX_SYNC_TIME_IF_SINGLE_PROCESSOR(allowed_delta) {                               \
  if (BX_SMP_PROCESSORS == 1) {                                                         \
    Bit32u delta = (Bit32u)(BX_CPU_THIS_PTR icount - BX_CPU_THIS_PTR icount_last_sync); \
    if (delta >= allowed_delta) {                                                       \
      BX_CPU_THIS_PTR sync_icount();                                                    \
      BX_TICKN(delta);                                                                  \
    }                                                                                   \
  }                                                                                     \
}

#else

#define BX_SYNC_TIME_IF_SINGLE_PROCESSOR(allowed_delta) \
  if (BX_SMP_PROCESSORS == 1) BX_TICK1()

#endif

jmp_buf BX_CPU_C::jmp_buf_env;

void BX_CPU_C::cpu_loop(void)
{
#if BX_DEBUGGER
    BX_CPU_THIS_PTR break_point = 0;
    BX_CPU_THIS_PTR magic_break = 0;
    BX_CPU_THIS_PTR stop_reason = STOP_NO_REASON;
#endif

    if (setjmp(BX_CPU_THIS_PTR jmp_buf_env)) {
        // can get here only from exception function or VMEXIT
        BX_CPU_THIS_PTR icount++;
#if BX_DEBUGGER || BX_GDBSTUB
        if (dbg_instruction_epilog()) return;
#endif
#if BX_GDBSTUB
        if (bx_dbg.gdbstub_enabled) return;
#endif
    }

    // If the exception() routine has encountered a nasty fault scenario,
    // the debugger may request that control is returned to it so that
    // the situation may be examined.
#if BX_DEBUGGER
    if (bx_guard.interrupt_requested) return;
#endif

    // We get here either by a normal function call, or by a longjmp
    // back from an exception() call.  In either case, commit the
    // new EIP/ESP, and set up other environmental fields.  This code
    // mirrors similar code below, after the interrupt() call.
    BX_CPU_THIS_PTR prev_rip = RIP; // commit new EIP
    BX_CPU_THIS_PTR speculative_rsp = false;

    while (1) {

        bxICacheEntry_c* entry = getICacheEntry();
        bxInstruction_c* i = entry->i;

        bxInstruction_c* last = i + (entry->tlen);

        for (;;) {
            // want to allow changing of the instruction inside instrumentation callback
            RIP += i->ilen();
            BX_CPU_CALL_METHOD(i->execute1, (i)); // might iterate repeat instruction
            BX_CPU_THIS_PTR prev_rip = RIP; // commit new RIP
            BX_CPU_THIS_PTR icount++;

            //if (BX_CPU_THIS_PTR async_event) break;

            if (++i == last) {
                entry = getICacheEntry();
                i = entry->i;
                last = i + (entry->tlen);
            }
        }
    }  // while (1)
}

#if BX_SUPPORT_SMP

void BX_CPU_C::cpu_run_trace(void)
{
  // check on events which occurred for previous instructions (traps)
  // and ones which are asynchronous to the CPU (hardware interrupts)
  if (BX_CPU_THIS_PTR async_event) {
    if (handleAsyncEvent()) {
      // If request to return to caller ASAP.
      return;
    }
  }

  bxICacheEntry_c *entry = getICacheEntry();
  bxInstruction_c *i = entry->i;

#if BX_SUPPORT_HANDLERS_CHAINING_SPEEDUPS
  // want to allow changing of the instruction inside instrumentation callback
  RIP += i->ilen();
  // when handlers chaining is enabled this single call will execute entire trace
  BX_CPU_CALL_METHOD(i->execute1, (i)); // might iterate repeat instruction

  if (BX_CPU_THIS_PTR async_event) {
    // clear stop trace magic indication that probably was set by repeat or branch32/64
    BX_CPU_THIS_PTR async_event &= ~BX_ASYNC_EVENT_STOP_TRACE;
  }
#else
  bxInstruction_c *last = i + (entry->tlen);

  for(;;) {
    // want to allow changing of the instruction inside instrumentation callback
    BX_INSTR_BEFORE_EXECUTION(BX_CPU_ID, i);
    RIP += i->ilen();
    BX_CPU_CALL_METHOD(i->execute1, (i)); // might iterate repeat instruction
    BX_CPU_THIS_PTR prev_rip = RIP; // commit new RIP
    BX_CPU_THIS_PTR icount++;

    if (BX_CPU_THIS_PTR async_event) {
      // clear stop trace magic indication that probably was set by repeat or branch32/64
      BX_CPU_THIS_PTR async_event &= ~BX_ASYNC_EVENT_STOP_TRACE;
      break;
    }

    if (++i == last) break;
  }
#endif // BX_SUPPORT_HANDLERS_CHAINING_SPEEDUPS
}

#endif

#include "decoder/ia_opcodes.h"

bxICacheEntry_c* BX_CPU_C::getICacheEntry(void)
{
  bx_address eipBiased = RIP + BX_CPU_THIS_PTR eipPageBias;

  if (eipBiased >= BX_CPU_THIS_PTR eipPageWindowSize) {
    prefetch();
    eipBiased = RIP + BX_CPU_THIS_PTR eipPageBias;
  }

  INC_ICACHE_STAT(iCacheLookups);

  bx_phy_address pAddr = BX_CPU_THIS_PTR pAddrFetchPage + eipBiased;
  bxICacheEntry_c *entry = BX_CPU_THIS_PTR iCache.find_entry(pAddr, BX_CPU_THIS_PTR fetchModeMask);

  if (entry == NULL)
  {
    // iCache miss. No validated instruction with matching fetch parameters
    // is in the iCache.
    INC_ICACHE_STAT(iCacheMisses);
    entry = serveICacheMiss((Bit32u) eipBiased, pAddr);
  }

  return entry;
}

#define BX_REPEAT_TIME_UPDATE_INTERVAL (BX_MAX_TRACE_LENGTH-1)

void BX_CPP_AttrRegparmN(2) BX_CPU_C::repeat(bxInstruction_c *i, BxRepIterationPtr_tR execute)
{
  // non repeated instruction
  if (! i->repUsedL()) {
    BX_CPU_CALL_REP_ITERATION(execute, (i));
    return;
  }

#if BX_X86_DEBUGGER
  BX_CPU_THIS_PTR in_repeat = false;
#endif

#if BX_SUPPORT_X86_64
  if (i->as64L()) {
    while(1) {
      if (RCX != 0) {
        BX_CPU_CALL_REP_ITERATION(execute, (i));
        RCX --;
      }
      if (RCX == 0) return;

#if BX_DEBUGGER == 0
      if (BX_CPU_THIS_PTR async_event)
#endif
        break; // exit always if debugger enabled

      BX_CPU_THIS_PTR icount++;

    }
  }
  else
#endif
  if (i->as32L()) {
    while(1) {
      if (ECX != 0) {
        BX_CPU_CALL_REP_ITERATION(execute, (i));
        RCX = ECX - 1;
      }
      if (ECX == 0) return;

#if BX_DEBUGGER == 0
      if (BX_CPU_THIS_PTR async_event)
#endif
        break; // exit always if debugger enabled

      BX_CPU_THIS_PTR icount++;

    }
  }
  else  // 16bit addrsize
  {
    while(1) {
      if (CX != 0) {
        BX_CPU_CALL_REP_ITERATION(execute, (i));
        CX --;
      }
      if (CX == 0) return;

#if BX_DEBUGGER == 0
      if (BX_CPU_THIS_PTR async_event)
#endif
        break; // exit always if debugger enabled

      BX_CPU_THIS_PTR icount++;

    }
  }

#if BX_X86_DEBUGGER
  BX_CPU_THIS_PTR in_repeat = true;
#endif

  RIP = BX_CPU_THIS_PTR prev_rip; // repeat loop not done, restore RIP

  // assert magic async_event to stop trace execution
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
}

void BX_CPP_AttrRegparmN(2) BX_CPU_C::repeat_ZF(bxInstruction_c *i, BxRepIterationPtr_tR execute)
{
  unsigned rep = i->lockRepUsedValue();

  // non repeated instruction
  if (rep < 2) {
    BX_CPU_CALL_REP_ITERATION(execute, (i));
    return;
  }

#if BX_X86_DEBUGGER
  BX_CPU_THIS_PTR in_repeat = false;
#endif

  if (rep == 3) { /* repeat prefix 0xF3 */
#if BX_SUPPORT_X86_64
    if (i->as64L()) {
      while(1) {
        if (RCX != 0) {
          BX_CPU_CALL_REP_ITERATION(execute, (i));
          RCX --;
        }
        if (! get_ZF() || RCX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_CPU_THIS_PTR icount++;

      }
    }
    else
#endif
    if (i->as32L()) {
      while(1) {
        if (ECX != 0) {
          BX_CPU_CALL_REP_ITERATION(execute, (i));
          RCX = ECX - 1;
        }
        if (! get_ZF() || ECX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_CPU_THIS_PTR icount++;

      }
    }
    else  // 16bit addrsize
    {
      while(1) {
        if (CX != 0) {
          BX_CPU_CALL_REP_ITERATION(execute, (i));
          CX --;
        }
        if (! get_ZF() || CX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_CPU_THIS_PTR icount++;

      }
    }
  }
  else {          /* repeat prefix 0xF2 */
#if BX_SUPPORT_X86_64
    if (i->as64L()) {
      while(1) {
        if (RCX != 0) {
          BX_CPU_CALL_REP_ITERATION(execute, (i));
          RCX --;
        }
        if (get_ZF() || RCX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_CPU_THIS_PTR icount++;

      }
    }
    else
#endif
    if (i->as32L()) {
      while(1) {
        if (ECX != 0) {
          BX_CPU_CALL_REP_ITERATION(execute, (i));
          RCX = ECX - 1;
        }
        if (get_ZF() || ECX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_CPU_THIS_PTR icount++;

      }
    }
    else  // 16bit addrsize
    {
      while(1) {
        if (CX != 0) {
          BX_CPU_CALL_REP_ITERATION(execute, (i));
          CX --;
        }
        if (get_ZF() || CX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_CPU_THIS_PTR icount++;

      }
    }
  }

#if BX_X86_DEBUGGER
  BX_CPU_THIS_PTR in_repeat = true;
#endif

  RIP = BX_CPU_THIS_PTR prev_rip; // repeat loop not done, restore RIP

  // assert magic async_event to stop trace execution
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
}

void BX_CPU_C::prefetch(void)
{
    bx_address laddr;
    unsigned pageOffset;

    INC_ICACHE_STAT(iCachePrefetch);

    if (long64_mode()) {
        if (!IsCanonical(RIP)) {
            BX_ERROR(("prefetch: #GP(0): RIP crossed canonical boundary"));
            exception(BX_GP_EXCEPTION, 0);
        }

        // linear address is equal to RIP in 64-bit long mode
        pageOffset = PAGE_OFFSET(EIP);
        laddr = RIP;

        // Calculate RIP at the beginning of the page.
        BX_CPU_THIS_PTR eipPageBias = pageOffset - RIP;
        BX_CPU_THIS_PTR eipPageWindowSize = 4096;
    }
    else {
        BX_CLEAR_64BIT_HIGH(BX_64BIT_REG_RIP); /* avoid 32-bit EIP wrap */
        laddr = get_laddr32(BX_SEG_REG_CS, EIP);
        pageOffset = PAGE_OFFSET(laddr);

        // Calculate RIP at the beginning of the page.
        BX_CPU_THIS_PTR eipPageBias = (bx_address)pageOffset - EIP;

        Bit32u limit = BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.u.segment.limit_scaled;
        if (EIP > limit) {
            BX_ERROR(("prefetch: EIP [%08x] > CS.limit [%08x]", EIP, limit));
            exception(BX_GP_EXCEPTION, 0);
        }

        BX_CPU_THIS_PTR eipPageWindowSize = 4096;
        if (limit + BX_CPU_THIS_PTR eipPageBias < 4096) {
            BX_CPU_THIS_PTR eipPageWindowSize = (Bit32u)(limit + BX_CPU_THIS_PTR eipPageBias + 1);
        }
    }

#if BX_X86_DEBUGGER
    if (hwbreakpoint_check(laddr, BX_HWDebugInstruction, BX_HWDebugInstruction)) {
        signal_event(BX_EVENT_CODE_BREAKPOINT_ASSIST);
        if (!interrupts_inhibited(BX_INHIBIT_DEBUG)) {
            // The next instruction could already hit a code breakpoint but
            // async_event won't take effect immediatelly.
            // Check if the next executing instruction hits code breakpoint

            // check only if not fetching page cross instruction
            // this check is 32-bit wrap safe as well
            if (EIP == (Bit32u)BX_CPU_THIS_PTR prev_rip) {
                Bit32u dr6_bits = code_breakpoint_match(laddr);
                if (dr6_bits & BX_DEBUG_TRAP_HIT) {
                    BX_ERROR(("#DB: x86 code breakpoint caught"));
                    BX_CPU_THIS_PTR debug_trap |= dr6_bits;
                    exception(BX_DB_EXCEPTION, 0);
                }
            }
        }
    }
    else {
        clear_event(BX_EVENT_CODE_BREAKPOINT_ASSIST);
    }
#endif

    BX_CPU_THIS_PTR clear_RF();
    bx_address lpf = LPFOf(laddr);
    bx_TLB_entry* tlbEntry = BX_ITLB_ENTRY_OF(laddr);
    Bit8u* fetchPtr = 0;

    if ((tlbEntry->lpf == lpf) && (tlbEntry->accessBits & (1 << unsigned(USER_PL))) != 0) {
        BX_CPU_THIS_PTR pAddrFetchPage = tlbEntry->ppf;
        fetchPtr = (Bit8u*)tlbEntry->hostPageAddr;
    }
    else {
        bx_phy_address pAddr = translate_linear(tlbEntry, laddr, USER_PL, BX_EXECUTE);
        BX_CPU_THIS_PTR pAddrFetchPage = PPFOf(pAddr);
    }

    if (fetchPtr) {
        BX_CPU_THIS_PTR eipFetchPtr = fetchPtr;
    }
    else {
        BX_CPU_THIS_PTR eipFetchPtr = (const Bit8u*)get_host_address(BX_CPU_THIS_PTR pAddrFetchPage, BX_EXECUTE);

        // Sanity checks
        if (!BX_CPU_THIS_PTR eipFetchPtr) {
            bx_phy_address pAddr = BX_CPU_THIS_PTR pAddrFetchPage + pageOffset;
            BX_PANIC(("prefetch: get_host_address vetoed direct read, pAddr=0x" FMT_PHY_ADDRX, pAddr));
        }
    }
}

#if BX_DEBUGGER || BX_GDBSTUB
bool BX_CPU_C::dbg_instruction_epilog(void)
{
#if BX_DEBUGGER
  bx_address debug_eip = RIP;
  Bit16u cs = BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.value;

  BX_CPU_THIS_PTR guard_found.cs  = cs;
  BX_CPU_THIS_PTR guard_found.eip = debug_eip;
  BX_CPU_THIS_PTR guard_found.laddr = get_laddr(BX_SEG_REG_CS, debug_eip);
  BX_CPU_THIS_PTR guard_found.code_32_64 = BX_CPU_THIS_PTR fetchModeMask;

  //
  // Take care of break point conditions generated during instruction execution
  //

  // Check if we hit read/write or time breakpoint
  if (BX_CPU_THIS_PTR break_point) {
    Bit64u tt = bx_pc_system.time_ticks();
    switch (BX_CPU_THIS_PTR break_point) {
    case BREAK_POINT_TIME:
      BX_INFO(("[" FMT_LL "d] Caught time breakpoint", tt));
      BX_CPU_THIS_PTR stop_reason = STOP_TIME_BREAK_POINT;
      return(1); // on a breakpoint
    case BREAK_POINT_READ:
      BX_INFO(("[" FMT_LL "d] Caught read watch point", tt));
      BX_CPU_THIS_PTR stop_reason = STOP_READ_WATCH_POINT;
      return(1); // on a breakpoint
    case BREAK_POINT_WRITE:
      BX_INFO(("[" FMT_LL "d] Caught write watch point", tt));
      BX_CPU_THIS_PTR stop_reason = STOP_WRITE_WATCH_POINT;
      return(1); // on a breakpoint
    default:
      BX_PANIC(("Weird break point condition"));
    }
  }

  if (BX_CPU_THIS_PTR magic_break) {
    BX_INFO(("[" FMT_LL "d] Stopped on MAGIC BREAKPOINT", bx_pc_system.time_ticks()));
    BX_CPU_THIS_PTR stop_reason = STOP_MAGIC_BREAK_POINT;
    return(1); // on a breakpoint
  }

  // convenient point to see if user requested debug break or typed Ctrl-C
  if (bx_guard.interrupt_requested) {
    return(1);
  }

  // support for 'show' command in debugger
  extern unsigned dbg_show_mask;
  if(dbg_show_mask) {
    int rv = bx_dbg_show_symbolic();
    if (rv) return(rv);
  }

  // Just committed an instruction, before fetching a new one
  // see if debugger is looking for iaddr breakpoint of any type
  if (bx_guard.guard_for & BX_DBG_GUARD_IADDR_ALL) {
#if (BX_DBG_MAX_VIR_BPOINTS > 0)
    if (bx_guard.guard_for & BX_DBG_GUARD_IADDR_VIR) {
      for (unsigned n=0; n<bx_guard.iaddr.num_virtual; n++) {
        if (bx_guard.iaddr.vir[n].enabled &&
           (bx_guard.iaddr.vir[n].cs  == cs) &&
           (bx_guard.iaddr.vir[n].eip == debug_eip))
        {
          if (! bx_guard.iaddr.vir[n].condition || bx_dbg_eval_condition(bx_guard.iaddr.vir[n].condition)) {
            BX_CPU_THIS_PTR guard_found.guard_found = BX_DBG_GUARD_IADDR_VIR;
            BX_CPU_THIS_PTR guard_found.iaddr_index = n;
            return(1); // on a breakpoint
          }
        }
      }
    }
#endif
#if (BX_DBG_MAX_LIN_BPOINTS > 0)
    if (bx_guard.guard_for & BX_DBG_GUARD_IADDR_LIN) {
      for (unsigned n=0; n<bx_guard.iaddr.num_linear; n++) {
        if (bx_guard.iaddr.lin[n].enabled &&
           (bx_guard.iaddr.lin[n].addr == BX_CPU_THIS_PTR guard_found.laddr))
        {
          if (! bx_guard.iaddr.lin[n].condition || bx_dbg_eval_condition(bx_guard.iaddr.lin[n].condition)) {
            BX_CPU_THIS_PTR guard_found.guard_found = BX_DBG_GUARD_IADDR_LIN;
            BX_CPU_THIS_PTR guard_found.iaddr_index = n;
            return(1); // on a breakpoint
          }
        }
      }
    }
#endif
#if (BX_DBG_MAX_PHY_BPOINTS > 0)
    if (bx_guard.guard_for & BX_DBG_GUARD_IADDR_PHY) {
      bx_phy_address phy;
      bool valid = dbg_xlate_linear2phy(BX_CPU_THIS_PTR guard_found.laddr, &phy);
      if (valid) {
        for (unsigned n=0; n<bx_guard.iaddr.num_physical; n++) {
          if (bx_guard.iaddr.phy[n].enabled && (bx_guard.iaddr.phy[n].addr == phy))
          {
            if (! bx_guard.iaddr.phy[n].condition || bx_dbg_eval_condition(bx_guard.iaddr.phy[n].condition)) {
              BX_CPU_THIS_PTR guard_found.guard_found = BX_DBG_GUARD_IADDR_PHY;
              BX_CPU_THIS_PTR guard_found.iaddr_index = n;
              return(1); // on a breakpoint
            }
          }
        }
      }
    }
#endif
  }

  // see if debugger requesting icount guard
  if (bx_guard.guard_for & BX_DBG_GUARD_ICOUNT) {
    if (get_icount() >= BX_CPU_THIS_PTR guard_found.icount_max) {
      return(1);
    }
  }
#endif

#if BX_GDBSTUB
  if (bx_dbg.gdbstub_enabled) {
    unsigned reason = bx_gdbstub_check(EIP);
    if (reason != GDBSTUB_STOP_NO_REASON) return(1);
  }
#endif

  return(0);
}
#endif // BX_DEBUGGER || BX_GDBSTUB
