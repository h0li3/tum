#include "system_service.h"


Bit32u BxSystemService::services_[512];
int BxSystemService::services_count_;

extern "C" bx_address __stdcall internal_syscall(
    int index,
    bx_address arg0,
    bx_address arg1,
    bx_address arg2,
    bx_address arg3,
    bx_address arg4,
    bx_address arg5,
    bx_address arg6,
    bx_address arg7,
    bx_address arg8,
    bx_address arg9,
    bx_address arg10,
    bx_address arg11,
    bx_address arg12,
    bx_address arg13,
    bx_address arg14,
    bx_address arg15,
    bx_address arg16,
    bx_address arg17,
    bx_address arg18,
    bx_address arg19
    // Dick sucker
);

bx_address BxSystemService::CallSystemService64(BX_CPU_C* cpu)
{
    int index = cpu->get_reg32(BX_32BIT_REG_EAX);
    //if (index < 0 || index > services_count_) {
        //return -1;
    //}

    Bit64u rsp = cpu->get_reg64(BX_64BIT_REG_RSP);
    Bit64u arg0 = cpu->get_reg64(BX_64BIT_REG_R10);
    Bit64u arg1 = cpu->get_reg64(BX_64BIT_REG_RDX);
    Bit64u arg2 = cpu->get_reg64(BX_64BIT_REG_R8);
    Bit64u arg3 = cpu->get_reg64(BX_64BIT_REG_R9);
    // stdcall
    Bit64u arg4 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 0x28);
    Bit64u arg5 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 0x30);
    Bit64u arg6 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 0x38);
    Bit64u arg7 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 0x40);
    Bit64u arg8 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 0x48);
    Bit64u arg9 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 0x50);
    Bit64u arg10 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 0x58);
    Bit64u arg11 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 0x60);
    Bit64u arg12 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 0x68);
    Bit64u arg13 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 0x70);
    Bit64u arg14 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 0x78);
    Bit64u arg15 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 0x80);
    Bit64u arg16 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 0x88);
    Bit64u arg17 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 0x90);
    Bit64u arg18 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 0x98);
    Bit64u arg19 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 0xA0);

    return internal_syscall(index,
        arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
        arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15,
        arg16, arg17, arg18, arg19);
}
