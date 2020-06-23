#ifndef ENABLED

#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <sos.h>
#include <sel4/sel4.h>

#include "sossysnr.h"

long sys_brk(va_list ap)
{
    size_t newbrk = va_arg(ap, size_t);
    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, SOS_SYSCALL_BRK);
    seL4_SetMR(1, newbrk);
    
    msginfo = seL4_Call(SOS_IPC_EP_CAP, msginfo);

    // negative errno semantic
    if(seL4_GetMR(0) < 0)
        return 0;

    return seL4_GetMR(0);
}

#endif