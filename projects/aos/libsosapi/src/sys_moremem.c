#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>
#include <sos.h>
#include <sel4/sel4.h>

#include "sossysnr.h"

long sys_brk(va_list ap)
{
    // params
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

long sys_mmap(va_list ap)
{
    // params
    void *addr = va_arg(ap, void *);
    size_t length = va_arg(ap, size_t);
    int prot = va_arg(ap, int);
    int flags = va_arg(ap, int);
    int fd = va_arg(ap, int);
    off_t offset = va_arg(ap, off_t);

    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, 7);
    seL4_SetMR(0, SOS_SYSCALL_MMAP);
    seL4_SetMR(1, addr);
    seL4_SetMR(2, length);
    seL4_SetMR(3, prot);
    seL4_SetMR(4, flags);
    seL4_SetMR(5, fd);
    seL4_SetMR(6, offset);
    
    msginfo = seL4_Call(SOS_IPC_EP_CAP, msginfo);

    // negative errno semantic, but we return to caller as-is
    return seL4_GetMR(0);
}
