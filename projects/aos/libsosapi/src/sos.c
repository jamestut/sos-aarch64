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
#include <sos.h>

#include <sel4/sel4.h>
#include <errno.h>
#include <utils/arith.h>

#include "sossysnr.h"

#define UINT32_LIMIT 0x7FFFFFFF

int sos_errno = 0;

inline int sos_sys_rw(bool read, int file, char *buf, size_t nbyte);

int sos_sys_open(const char *path, fmode_t mode)
{
    uint32_t len = strnlen(path, MAX_IO_BUF);
    if(len >= MAX_IO_BUF) {
        sos_errno = ENAMETOOLONG;
        return -1;
    }

    void* bigipc = sos_large_ipc_buffer();
    memcpy(bigipc, path, len);

    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, 3);
    seL4_SetMR(0, SOS_SYSCALL_OPEN);
    seL4_SetMR(1, len);
    seL4_SetMR(2, mode);

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
    assert(!"You need to implement this");
    return -1;
}

int sos_stat(const char *path, sos_stat_t *buf)
{
    assert(!"You need to implement this");
    return -1;
}

pid_t sos_process_create(const char *path)
{
    assert(!"You need to implement this");
    return -1;
}

int sos_process_delete(pid_t pid)
{
    assert(!"You need to implement this");
    return -1;
}

pid_t sos_my_id(void)
{
    assert(!"You need to implement this");
    return -1;

}

int sos_process_status(sos_process_t *processes, unsigned max)
{
    assert(!"You need to implement this");
    return -1;
}

pid_t sos_process_wait(pid_t pid)
{
    assert(!"You need to implement this");
    return -1;
}

void sos_sys_usleep(int msec)
{   
    // TODO range ?
    if (msec < 0){
        // reject the request
        sos_errno = EINVAL;
        return -1;
        
    }

    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, SOS_SYSCALL_USLEEP);
    seL4_SetMR(1, msec);

    msginfo = seL4_Call(SOS_IPC_EP_CAP, msginfo);

    ssize_t ret = seL4_GetMR(0);
    printf("Get the reply with number: %ll", ret);
    if(ret < 0) {
        sos_errno = ret * -1;
        return -1;
    } else{
        return ret;
    }

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
    // truncate, as we have to return in int (while nbyte could be 64 bit)
    if(nbyte > UINT32_LIMIT)
        nbyte = UINT32_LIMIT;

    void* bigipc = sos_large_ipc_buffer();

    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, 3);
    seL4_MessageInfo_t retinfo;

    size_t rd = 0;

    while(rd < nbyte) {
        size_t numrd = MIN(nbyte - rd, MAX_IO_BUF);
        
        // write operation: copy from source to ipc
        if(!read) {
            memcpy(bigipc, buf, numrd);
            // advance position
            buf += numrd;
        }

        // syscall
        seL4_SetMR(0, read ? SOS_SYSCALL_READ : SOS_SYSCALL_WRITE);
        seL4_SetMR(1, file);
        seL4_SetMR(2, numrd);
        retinfo = seL4_Call(SOS_IPC_EP_CAP, msginfo);
        
        ssize_t ret = seL4_GetMR(0);
        if(ret < 0) {
            sos_errno = ret * -1;
            return -1;
        } else {
            // read operation: copy from ipc to buf
            if(read) {
                memcpy(buf, bigipc, ret);
                buf += ret;
            }

            rd += ret;
            // if SOS indicated that it does less than we want, we reached EOF.
            // stop now!
            if(ret < numrd)
                break;
        }
    }
    
    return rd;
}

void* sos_large_ipc_buffer(void)
{
    return (void*)((uintptr_t)seL4_GetIPCBuffer() + MAX_IO_BUF);
}
