/*
 * Copyright 2019, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(DATA61_GPL)
 */
#include <stdarg.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sos.h>
#include <sys/types.h>

#include <sel4/sel4.h>
#include <errno.h>
#include <utils/arith.h>

#include "sossysnr.h"

int sos_errno = 0;
char debugstr[4096];

// because of flat file structure, we will cache the dir handle :)
int dirfh = -1;

inline int sos_sys_rw(bool read, int file, char *buf, size_t nbyte);

int sos_sys_not_implemented(void);

void sos_debug_printf(const char* str, ...);

int sos_sys_opendir(const char* path)
{
    uint32_t len = strnlen(path, MAX_IO_BUF);
    if(len >= MAX_IO_BUF) {
        sos_errno = ENAMETOOLONG;
        return -1;
    }

    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, 3);
    seL4_SetMR(0, SOS_SYSCALL_OPENDIR);
    seL4_SetMR(1, path);
    seL4_SetMR(2, len);

    msginfo = seL4_Call(SOS_IPC_EP_CAP, msginfo);

    ssize_t ret = seL4_GetMR(0);
    if(ret < 0) {
        sos_errno = ret * -1;
        return -1;
    }
    return ret;
}

int sos_sys_getdirent_f(int fh, int pos, char *name, size_t nbyte)
{
    // request pos-th dir entry
    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, 5);
    seL4_SetMR(0, SOS_SYSCALL_DIRREAD);
    seL4_SetMR(1, fh);
    seL4_SetMR(2, pos);
    seL4_SetMR(3, name);
    seL4_SetMR(4, nbyte);

    seL4_Call(SOS_IPC_EP_CAP, msginfo);
    int ret = seL4_GetMR(0);
    if(ret < 0) {
        sos_errno = ret * -1;
        return -1;
    }
    return ret;
}

int sos_sys_open(const char *path, fmode_t mode)
{
    uint32_t len = strnlen(path, MAX_IO_BUF);
    if(len >= MAX_IO_BUF) {
        sos_errno = ENAMETOOLONG;
        return -1;
    }

    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, 4);
    seL4_SetMR(0, SOS_SYSCALL_OPEN);
    seL4_SetMR(1, path);
    seL4_SetMR(2, len);
    seL4_SetMR(3, mode);

    msginfo = seL4_Call(SOS_IPC_EP_CAP, msginfo);

    ssize_t ret = seL4_GetMR(0);
    if(ret < 0) {
        sos_errno = ret * -1;
        return -1;
    }
    return ret;
}

int sos_sys_close(int file)
{
    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, SOS_SYSCALL_CLOSE);
    seL4_SetMR(1, file);
    seL4_Call(SOS_IPC_EP_CAP, msginfo);
    // close always success no matter what :)
    return 0;
}

int sos_sys_read(int file, char *buf, size_t nbyte)
{
    return sos_sys_rw(true, file, buf, nbyte);
}

int sos_sys_write(int file, const char *buf, size_t nbyte)
{
    return sos_sys_rw(false, file, (char*)buf, nbyte);
}

int sos_getdirent(int pos, char *name, size_t nbyte)
{
    if(dirfh < 0)
        dirfh = sos_sys_opendir("/");
    // error!
    if(dirfh < 0)
        return dirfh;
    
    return sos_sys_getdirent_f(dirfh, pos, name, nbyte);
}

int sos_stat(const char *path, sos_stat_t *buf)
{
    uint32_t len = strnlen(path, MAX_IO_BUF);

    if(len >= MAX_IO_BUF) {
        sos_errno = ENAMETOOLONG;
        return -1;
    }

    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, 3);
    seL4_SetMR(0, SOS_SYSCALL_STAT);
    seL4_SetMR(1, path);
    seL4_SetMR(2, len);
    
    msginfo = seL4_Call(SOS_IPC_EP_CAP, msginfo);

    ssize_t ret = seL4_GetMR(0);
    if(ret < 0) {
        sos_errno = ret * -1;
        return -1;
    } else {
        memcpy(buf, seL4_GetIPCBuffer()->msg + 1, sizeof(sos_stat_t));
        return 0;
    }
}

pid_t sos_process_create(const char *path)
{
    return sos_sys_not_implemented();
}

int sos_process_delete(pid_t pid)
{
    return sos_sys_not_implemented();
}

pid_t sos_my_id(void)
{
    return sos_sys_not_implemented();
}

int sos_process_status(sos_process_t *processes, unsigned max)
{
    return sos_sys_not_implemented();
}

pid_t sos_process_wait(pid_t pid)
{
    return sos_sys_not_implemented();
}

void sos_sys_usleep(int msec)
{   
    if (msec < 0){
        // reject the request
        sos_errno = EINVAL;
        return -1;
    }

    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, SOS_SYSCALL_USLEEP);
    seL4_SetMR(1, msec);

    seL4_Call(SOS_IPC_EP_CAP, msginfo);
}

int64_t sos_sys_time_stamp(void)
{
    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, SOS_SYSCALL_TIMESTAMP);

    msginfo = seL4_Call(SOS_IPC_EP_CAP, msginfo);   

    // get the reply
    ssize_t ret = seL4_GetMR(0);
    if(ret < 0) {
        sos_errno = ret * -1;
        return -1;
    } else {
        return ret;
    }
}

int sos_sys_rw(bool read, int file, char *buf, size_t nbyte)
{
    // truncate, as we have to return in signed int (while nbyte could be 64 bit)
    if(nbyte > INT32_MAX)
        nbyte = INT32_MAX;

    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, 4);
    seL4_MessageInfo_t retinfo;

    size_t rd = 0;

    seL4_SetMR(0, read ? SOS_SYSCALL_READ : SOS_SYSCALL_WRITE);
    seL4_SetMR(1, file);
    seL4_SetMR(2, buf);
    seL4_SetMR(3, nbyte);
    retinfo = seL4_Call(SOS_IPC_EP_CAP, msginfo);

    ssize_t ret = seL4_GetMR(0);
    if(ret < 0) {
        sos_errno = ret * -1;
        return -1;
    } else
        return ret;
    
    return rd;
}

size_t sos_grow_stack(ssize_t pages)
{
    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, SOS_SYSCALL_GROW_STACK);
    seL4_SetMR(1, pages);
    seL4_Call(SOS_IPC_EP_CAP, msginfo);

    ssize_t ret = seL4_GetMR(0);
    if(ret < 0)
        return 0;
    return ret;
}

ssize_t sos_brk(uintptr_t target)
{
    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, SOS_SYSCALL_BRK);
    seL4_SetMR(1, target);
    
    msginfo = seL4_Call(SOS_IPC_EP_CAP, msginfo);

    // negative errno semantic
    if(seL4_GetMR(0) < 0) {
        sos_errno = -seL4_GetMR(0);
        return -1;
    }

    return seL4_GetMR(0);
}

int sos_sys_not_implemented()
{
    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, SOS_SYSCALL_UNIMPLEMENTED);
    seL4_Send(SOS_IPC_EP_CAP, msginfo);
    sos_errno = ENOSYS;
    return -1;
}

void sos_debug_printf(const char* str, ...)
{
    va_list args;

    va_start(args, str);
    int len = vsprintf(debugstr, str, args);
    va_end(args);

    for(int i=0; i<len; ++i)
        seL4_DebugPutChar(debugstr[i]);
}
