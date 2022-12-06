/////////////////////////////////////////////////////////////////////////
// $Id$
/////////////////////////////////////////////////////////////////////////
//
//   Copyright (c) 2008-2019 Stanislav Shwartsman
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
//
/////////////////////////////////////////////////////////////////////////

#define NEED_CPU_REG_SHORTCUTS 1
#include "bochs.h"
#include "cpu.h"
#include "msr.h"
#define LOG_THIS BX_CPU_THIS_PTR

#if BX_CPU_LEVEL >= 5
bool BX_CPP_AttrRegparmN(2) BX_CPU_C::rdmsr(Bit32u index, Bit64u *msr)
{
	return false;
}

bool BX_CPP_AttrRegparmN(2) BX_CPU_C::handle_unknown_rdmsr(Bit32u index, Bit64u *msr)
{
  Bit64u val_64 = 0;

  // Try to check cpuid_t first (can implement some MSRs)
  int result = BX_CPU_THIS_PTR cpuid->rdmsr(index, &val_64);
  if (result == 0)
    return 0; // #GP fault due to not supported MSR

  if (result < 0) {
	  // cpuid_t have no idea about this MSR
      // failed to find the MSR, could #GP or ignore it silently
	  BX_ERROR(("RDMSR: Unknown register %#x", index));

	  if (! BX_CPU_THIS_PTR ignore_bad_msrs)
		  return 0; // will result in #GP fault due to unknown MSR
  }

  *msr = val_64;
  return 1;
}

#endif // BX_CPU_LEVEL >= 5

void BX_CPP_AttrRegparmN(1) BX_CPU_C::RDMSR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 5
  // CPL is always 0 in real mode
  if (/* !real_mode() && */ CPL!=0) {
    BX_ERROR(("RDMSR: CPL != 0 not in real mode"));
    exception(BX_GP_EXCEPTION, 0);
  }

  Bit32u index = ECX;
  Bit64u val64 = 0;

  if (!rdmsr(index, &val64))
    exception(BX_GP_EXCEPTION, 0);

  RAX = GET32L(val64);
  RDX = GET32H(val64);
#endif

  BX_NEXT_INSTR(i);
}

#if BX_CPU_LEVEL >= 6
bool isMemTypeValidMTRR(unsigned memtype)
{
  switch(memtype) {
  case BX_MEMTYPE_UC:
  case BX_MEMTYPE_WC:
  case BX_MEMTYPE_WT:
  case BX_MEMTYPE_WP:
  case BX_MEMTYPE_WB:
    return true;
  default:
    return false;
  }
}

BX_CPP_INLINE bool isMemTypeValidPAT(unsigned memtype)
{
  return (memtype == 0x07) /* UC- */ || isMemTypeValidMTRR(memtype);
}

bool isValidMSR_PAT(Bit64u pat_val)
{
  // use packed register as 64-bit value with convinient accessors
  BxPackedRegister pat_msr = pat_val;
  for (unsigned i=0; i<8; i++)
    if (! isMemTypeValidPAT(pat_msr.ubyte(i))) return false;

  return true;
}

bool isValidMSR_FixedMTRR(Bit64u fixed_mtrr_val)
{
  // use packed register as 64-bit value with convinient accessors
  BxPackedRegister fixed_mtrr_msr = fixed_mtrr_val;
  for (unsigned i=0; i<8; i++)
    if (! isMemTypeValidMTRR(fixed_mtrr_msr.ubyte(i))) return false;

  return true;
}
#endif

#if BX_CPU_LEVEL >= 5
bool BX_CPP_AttrRegparmN(2) BX_CPU_C::wrmsr(Bit32u index, Bit64u val_64)
{
	return false;
}

bool BX_CPP_AttrRegparmN(2) BX_CPU_C::handle_unknown_wrmsr(Bit32u index, Bit64u val_64)
{
  // Try to check cpuid_t first (can implement some MSRs)
  int result = BX_CPU_THIS_PTR cpuid->wrmsr(index, val_64);
  if (result == 0)
    return 0; // #GP fault due to not supported MSR

  if (result < 0) {
    // cpuid_t have no idea about this MSR
    // failed to find the MSR, could #GP or ignore it silently
    BX_ERROR(("WRMSR: Unknown register %#x", index));
    if (! BX_CPU_THIS_PTR ignore_bad_msrs)
      return 0; // will result in #GP fault due to unknown MSR
  }

  return 1;
}

#endif // BX_CPU_LEVEL >= 5

void BX_CPP_AttrRegparmN(1) BX_CPU_C::WRMSR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 5
  // CPL is always 0 in real mode
  if (/* !real_mode() && */ CPL!=0) {
    BX_ERROR(("WRMSR: CPL != 0 not in real mode"));
    exception(BX_GP_EXCEPTION, 0);
  }

  invalidate_prefetch_q();

  Bit64u val_64 = ((Bit64u) EDX << 32) | EAX;
  Bit32u index = ECX;

  if (! wrmsr(index, val_64))
    exception(BX_GP_EXCEPTION, 0);
#endif

  BX_NEXT_TRACE(i);
}

