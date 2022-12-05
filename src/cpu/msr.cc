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

#if BX_SUPPORT_CET
extern bool is_invalid_cet_control(bx_address val);
#endif

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
#if BX_CONFIGURE_MSRS
    if (index < BX_MSR_MAX_INDEX && BX_CPU_THIS_PTR msrs[index]) {
      val_64 = BX_CPU_THIS_PTR msrs[index]->get64();
    }
    else
#endif
    {
      // failed to find the MSR, could #GP or ignore it silently
      BX_ERROR(("RDMSR: Unknown register %#x", index));

      if (! BX_CPU_THIS_PTR ignore_bad_msrs)
        return 0; // will result in #GP fault due to unknown MSR
    }
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

#if BX_SUPPORT_SVM
  if (BX_CPU_THIS_PTR in_svm_guest) {
    if (SVM_INTERCEPT(SVM_INTERCEPT0_MSR)) SvmInterceptMSR(BX_READ, index);
  }
#endif

#if BX_SUPPORT_VMX
  if (BX_CPU_THIS_PTR in_vmx_guest)
    VMexit_MSR(VMX_VMEXIT_RDMSR, index);
#endif

#if BX_SUPPORT_VMX >= 2
  if (BX_CPU_THIS_PTR in_vmx_guest) {
    if (SECONDARY_VMEXEC_CONTROL(VMX_VM_EXEC_CTRL3_VIRTUALIZE_X2APIC_MODE)) {
      if (index >= 0x800 && index <= 0x8FF) {
        if (index == 0x808 || SECONDARY_VMEXEC_CONTROL(VMX_VM_EXEC_CTRL3_VIRTUALIZE_APIC_REGISTERS)) {
          unsigned vapic_offset = (index & 0xff) << 4;
          RAX = VMX_Read_Virtual_APIC(vapic_offset);
          RDX = VMX_Read_Virtual_APIC(vapic_offset + 4);
          BX_NEXT_INSTR(i);
        }
      }
    }
  }
#endif

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
#if BX_CONFIGURE_MSRS
    if (index < BX_MSR_MAX_INDEX && BX_CPU_THIS_PTR msrs[index]) {
      if (! BX_CPU_THIS_PTR msrs[index]->set64(val_64)) {
        BX_ERROR(("WRMSR: Write failed to MSR %#x - #GP fault", index));
        return 0;
      }
      return 1;
    }
#endif
    // failed to find the MSR, could #GP or ignore it silently
    BX_ERROR(("WRMSR: Unknown register %#x", index));
    if (! BX_CPU_THIS_PTR ignore_bad_msrs)
      return 0; // will result in #GP fault due to unknown MSR
  }

  return 1;
}

#endif // BX_CPU_LEVEL >= 5

#if BX_SUPPORT_APIC
bool BX_CPU_C::relocate_apic(Bit64u val_64)
{
  /* MSR_APICBASE
   *  [0:7]  Reserved
   *    [8]  This is set if CPU is BSP
   *    [9]  Reserved
   *   [10]  X2APIC mode bit (1=enabled 0=disabled)
   *   [11]  APIC Global Enable bit (1=enabled 0=disabled)
   * [12:M]  APIC Base Address (physical)
   * [M:63]  Reserved
   */

  const Bit32u BX_MSR_APICBASE_RESERVED_BITS = (0x2ff | (is_cpu_extension_supported(BX_ISA_X2APIC) ? 0 : 0x400));

  if (BX_CPU_THIS_PTR msr.apicbase & 0x800) {
    Bit32u val32_hi = GET32H(val_64), val32_lo = GET32L(val_64);
    BX_INFO(("WRMSR: wrote %08x:%08x to MSR_APICBASE", val32_hi, val32_lo));
    if (! IsValidPhyAddr(val_64)) {
      BX_ERROR(("relocate_apic: invalid physical address"));
      return 0;
    }
    if (val32_lo & BX_MSR_APICBASE_RESERVED_BITS) {
      BX_ERROR(("relocate_apic: attempt to set reserved bits"));
      return 0;
    }

#if BX_CPU_LEVEL >= 6
    if (is_cpu_extension_supported(BX_ISA_X2APIC)) {
      unsigned apic_state = (BX_CPU_THIS_PTR msr.apicbase >> 10) & 3;
      unsigned new_state = (val32_lo >> 10) & 3;

      if (new_state != apic_state) {
        if (new_state == BX_APIC_STATE_INVALID) {
          BX_ERROR(("relocate_apic: attempt to set invalid apic state"));
          return 0;
        }
        if (apic_state == BX_APIC_X2APIC_MODE && new_state != BX_APIC_GLOBALLY_DISABLED) {
          BX_ERROR(("relocate_apic: attempt to switch from x2apic -> xapic"));
          return 0;
        }
      }
    }
#endif

    BX_CPU_THIS_PTR msr.apicbase = (bx_phy_address) val_64;
    BX_CPU_THIS_PTR lapic.set_base(BX_CPU_THIS_PTR msr.apicbase);
    // TLB flush is required for emulation correctness
    TLB_flush();  // don't care about performance of apic relocation
  }
  else {
    BX_INFO(("WRMSR: MSR_APICBASE APIC global enable bit cleared !"));
  }

  return 1;
}
#endif

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

#if BX_SUPPORT_SVM
  if (BX_CPU_THIS_PTR in_svm_guest) {
    if (SVM_INTERCEPT(SVM_INTERCEPT0_MSR)) SvmInterceptMSR(BX_WRITE, index);
  }
#endif

#if BX_SUPPORT_VMX
  if (BX_CPU_THIS_PTR in_vmx_guest)
    VMexit_MSR(VMX_VMEXIT_WRMSR, index);
#endif

#if BX_SUPPORT_VMX >= 2
  if (BX_CPU_THIS_PTR in_vmx_guest) {
    if (SECONDARY_VMEXEC_CONTROL(VMX_VM_EXEC_CTRL3_VIRTUALIZE_X2APIC_MODE)) {
      if (Virtualize_X2APIC_Write(index, val_64))
        BX_NEXT_INSTR(i);
    }
  }
#endif

  if (! wrmsr(index, val_64))
    exception(BX_GP_EXCEPTION, 0);
#endif

  BX_NEXT_TRACE(i);
}

#if BX_CONFIGURE_MSRS

int BX_CPU_C::load_MSRs(const char *file)
{
  char line[512];
  unsigned linenum = 0;
  Bit32u index, type;
  Bit32u reset_hi, reset_lo;
  Bit32u rsrv_hi, rsrv_lo;
  Bit32u ignr_hi, ignr_lo;

  FILE *fd = fopen (file, "r");
  if (fd == NULL) return -1;
  int retval = 0;
  do {
    linenum++;
    char* ret = fgets(line, sizeof(line)-1, fd);
    line[sizeof(line) - 1] = '\0';
    size_t len = strlen(line);
    if (len>0 && line[len-1] < ' ')
      line[len-1] = '\0';

    if (ret != NULL && strlen(line)) {
      if (line[0] == '#') continue;
      retval = sscanf(line, "%x %d %08x %08x %08x %08x %08x %08x",
         &index, &type, &reset_hi, &reset_lo, &rsrv_hi, &rsrv_lo, &ignr_hi, &ignr_lo);

      if (retval < 8) {
        retval = -1;
        BX_PANIC(("%s:%d > error parsing MSRs config file!", file, linenum));
        break;  // quit parsing after first error
      }
      if (index >= BX_MSR_MAX_INDEX) {
        BX_PANIC(("%s:%d > MSR index is too big !", file, linenum));
        continue;
      }
      if (BX_CPU_THIS_PTR msrs[index]) {
        BX_PANIC(("%s:%d > MSR[0x%03x] is already defined!", file, linenum, index));
        continue;
      }
      if (type > 2) {
        BX_PANIC(("%s:%d > MSR[0x%03x] unknown type !", file, linenum, index));
        continue;
      }

      BX_INFO(("loaded MSR[0x%03x] type=%d %08x:%08x %08x:%08x %08x:%08x", index, type,
        reset_hi, reset_lo, rsrv_hi, rsrv_lo, ignr_hi, ignr_lo));

      BX_CPU_THIS_PTR msrs[index] = new MSR(index, type,
        ((Bit64u)(reset_hi) << 32) | reset_lo,
        ((Bit64u) (rsrv_hi) << 32) | rsrv_lo,
        ((Bit64u) (ignr_hi) << 32) | ignr_lo);
    }
  } while (!feof(fd));

  fclose(fd);
  return retval;
}

#endif
