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
    bx_address arg7
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
    Bit64u arg4 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 8);
    Bit64u arg5 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 16);
    Bit64u arg6 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 24);
    Bit64u arg7 = cpu->read_linear_qword(BX_SEG_REG_SS, rsp + 32);

    return internal_syscall(index, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}
