#include "delegate.h"
#include "utils.h"
#include "network.h"

#include <utils/arith.h>

typedef enum {
    // generic
    INT_THRDREQ_NONE = 0,
    INT_THRDREQ_USERPTR_READ,
    INT_THRDREQ_USERPTR_WRITE_START,
    INT_THRDREQ_USERPTR_WRITE_NEXT,
    INT_THRDREQ_USERPTR_UNMAP,
    INT_THRDREQ_CAP_DELETE_FREE,
    INT_THRDREQ_UT_FREE,
    // NFS specific
    INT_THRDREQ_NFS_OPEN,
    INT_THRDREQ_NFS_PREAD,
    INT_THRDREQ_NFS_PWRITE,
    INT_THRDREQ_NFS_STAT,
    INT_THRDREQ_NFS_OPENDIR,
    INT_THRDREQ_NFS_DIRENT,
    INT_THRDREQ_NFS_CLOSEDIR,
    INT_THRDREQ_NFS_CLOSE
} IntThreadReq;

/* ---- common declarations ---- */
// we'll panic if we got a different parameter, because that's mean we have a bug!
#define PARAM_COUNT_CHECK(count, expected) {ZF_LOGF_IF((expected) != (count), "Wrong param count");}

/* ---- declaration for reply functions ---- */
void hdl_do_nothing(seL4_CPtr reply);

void hdl_userptr_read(seL4_CPtr reply);

void hdl_userptr_write_start(seL4_CPtr reply);

void hdl_userptr_write_next(seL4_CPtr reply);

void hdl_userptr_unmap(seL4_CPtr reply);

void hdl_free_cap(seL4_CPtr reply);

void hdl_free_ut(seL4_CPtr reply);

void hdl_nfs_open(seL4_CPtr reply);

void hdl_nfs_pread(seL4_CPtr reply);

void hdl_nfs_pwrite(seL4_CPtr reply);

void hdl_nfs_stat(seL4_CPtr reply);

void hdl_nfs_opendir(seL4_CPtr reply);

void hdl_nfs_pclose(seL4_CPtr reply);

void hdl_nfs_dirent(seL4_CPtr reply);

void hdl_nfs_closedir(seL4_CPtr reply);

/* ---- definitions start here ---- */

void delegate_do_nothing(seL4_CPtr ep)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, INT_THRDREQ_NONE);
    seL4_Call(ep, msg);
}

void* delegate_userptr_read(seL4_CPtr ep, userptr_t src, size_t len, seL4_Word badge, seL4_CPtr vspace)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 5);
    seL4_SetMR(0, INT_THRDREQ_USERPTR_READ);
    seL4_SetMR(1, src);
    seL4_SetMR(2, len);
    seL4_SetMR(3, badge);
    seL4_SetMR(4, vspace);
    seL4_Call(ep, msg);
    return seL4_GetMR(0);
}

userptr_write_state_t delegate_userptr_write_start(seL4_CPtr ep, userptr_t src, size_t len, dynarray_t* userasarr, seL4_Word badge, seL4_CPtr vspace)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 6);
    seL4_SetMR(0, INT_THRDREQ_USERPTR_WRITE_START);
    seL4_SetMR(1, src);
    seL4_SetMR(2, len);
    seL4_SetMR(3, userasarr);
    seL4_SetMR(4, badge);
    seL4_SetMR(5, vspace);
    seL4_Call(ep, msg);
    
    userptr_write_state_t ret;
    memcpy(&ret, seL4_GetIPCBuffer()->msg, sizeof(ret));
    return ret;
}

bool delegate_userptr_write_next(seL4_CPtr ep, userptr_write_state_t* it)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, INT_THRDREQ_USERPTR_WRITE_NEXT);
    seL4_SetMR(1, it);
    seL4_Call(ep, msg);
    return seL4_GetMR(0);
}

void delegate_userptr_unmap(seL4_CPtr ep, void* sosaddr)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, INT_THRDREQ_USERPTR_UNMAP);
    seL4_SetMR(1, sosaddr);
    seL4_Call(ep, msg);
}

void delegate_free_cap(seL4_CPtr ep, seL4_CPtr cap, bool del_cap, bool free_slot)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 4);
    seL4_SetMR(0, INT_THRDREQ_CAP_DELETE_FREE);
    seL4_SetMR(1, cap);
    seL4_SetMR(2, del_cap);
    seL4_SetMR(3, free_slot);
    seL4_Call(ep, msg);
}

void delegate_free_ut(seL4_CPtr ep, ut_t* ut)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, INT_THRDREQ_UT_FREE);
    seL4_SetMR(1, ut);
    seL4_Call(ep, msg);
}

int delegate_libnfs_open_async(seL4_CPtr ep, const char *path, int flags, nfs_cb cb, void *private_data)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 5);
    seL4_SetMR(0, INT_THRDREQ_NFS_OPEN);
    seL4_SetMR(1, path);
    seL4_SetMR(2, flags);
    seL4_SetMR(3, cb);
    seL4_SetMR(4, private_data);
    seL4_Call(ep, msg);
    return seL4_GetMR(0);
}

int delegate_libnfs_pread_async(seL4_CPtr ep, struct nfsfh *nfsfh,
    uint64_t offset, uint64_t count, nfs_cb cb, void *private_data)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 6);
    seL4_SetMR(0, INT_THRDREQ_NFS_PREAD);
    seL4_SetMR(1, nfsfh);
    seL4_SetMR(2, offset);
    seL4_SetMR(3, count);
    seL4_SetMR(4, cb);
    seL4_SetMR(5, private_data);
    seL4_Call(ep, msg);
    return seL4_GetMR(0);
}

int delegate_libnfs_pwrite_async(seL4_CPtr ep, struct nfsfh *nfsfh, uint64_t offset, 
    uint64_t count, const void *buf, nfs_cb cb, void *private_data)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 7);
    seL4_SetMR(0, INT_THRDREQ_NFS_PWRITE);
    seL4_SetMR(1, nfsfh);
    seL4_SetMR(2, offset);
    seL4_SetMR(3, count);
    seL4_SetMR(4, buf);
    seL4_SetMR(5, cb);
    seL4_SetMR(6, private_data);
    seL4_Call(ep, msg);
    return seL4_GetMR(0);
}

int delegate_libnfs_stat_async(seL4_CPtr ep, const char* path, nfs_cb cb, void* private_data)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 4);
    seL4_SetMR(0, INT_THRDREQ_NFS_STAT);
    seL4_SetMR(1, path);
    seL4_SetMR(2, cb);
    seL4_SetMR(3, private_data);
    seL4_Call(ep, msg);
    return seL4_GetMR(0);
}

int delegate_libnfs_opendir_async(seL4_CPtr ep, const char* path, nfs_cb cb, void* private_data)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 4);
    seL4_SetMR(0, INT_THRDREQ_NFS_OPENDIR);
    seL4_SetMR(1, path);
    seL4_SetMR(2, cb);
    seL4_SetMR(3, private_data);
    seL4_Call(ep, msg);
    return seL4_GetMR(0);
}

int delegate_libnfs_close_async(seL4_CPtr ep, struct nfsfh *nfsfh, nfs_cb cb, void *private_data)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 4);
    seL4_SetMR(0, INT_THRDREQ_NFS_CLOSE);
    seL4_SetMR(1, nfsfh);
    seL4_SetMR(2, cb);
    seL4_SetMR(3, private_data);
    seL4_Call(ep, msg);
    return seL4_GetMR(0);
}

const char* delegate_libnfs_dirent(seL4_CPtr ep, struct nfsdir *nfsdir, size_t idx)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 3);
    seL4_SetMR(0, INT_THRDREQ_NFS_DIRENT);
    seL4_SetMR(1, nfsdir);
    seL4_SetMR(2, idx);
    seL4_Call(ep, msg);
    return seL4_GetMR(0);
}

void delegate_libnfs_closedir(seL4_CPtr ep, struct nfsdir *nfsdir)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, INT_THRDREQ_NFS_CLOSEDIR);
    seL4_SetMR(1, nfsdir);
    seL4_Call(ep, msg);
}

/* ---- definitions for handler @ main thread ---- */

void handle_delegate_req(seL4_Word badge, seL4_Word msglen, seL4_CPtr reply, ut_t* reply_ut)
{
    ZF_LOGD("Got internal request from thread %d\n", badge);
    IntThreadReq cmd = seL4_GetMR(0);
    switch(cmd) {
        case INT_THRDREQ_NONE:
            PARAM_COUNT_CHECK(msglen, 1);
            hdl_do_nothing(reply);
            break;

        case INT_THRDREQ_USERPTR_READ:
            PARAM_COUNT_CHECK(msglen, 5);
            hdl_userptr_read(reply);
            break;

        case INT_THRDREQ_USERPTR_WRITE_START:
            PARAM_COUNT_CHECK(msglen, 6);
            hdl_userptr_write_start(reply);
            break;

        case INT_THRDREQ_USERPTR_WRITE_NEXT:
            PARAM_COUNT_CHECK(msglen, 2);
            hdl_userptr_write_next(reply);
            break;

        case INT_THRDREQ_USERPTR_UNMAP:
            PARAM_COUNT_CHECK(msglen, 2);
            hdl_userptr_unmap(reply);
            break;

        case INT_THRDREQ_CAP_DELETE_FREE:
            PARAM_COUNT_CHECK(msglen, 4);
            hdl_free_cap(reply);
            break;

        case INT_THRDREQ_UT_FREE:
            PARAM_COUNT_CHECK(msglen, 2);
            hdl_free_ut(reply);
            break;

        case INT_THRDREQ_NFS_OPEN:
            PARAM_COUNT_CHECK(msglen, 5);
            hdl_nfs_open(reply);
            break;

        case INT_THRDREQ_NFS_PREAD:
            PARAM_COUNT_CHECK(msglen, 6);
            hdl_nfs_pread(reply);
            break;

        case INT_THRDREQ_NFS_PWRITE:
            PARAM_COUNT_CHECK(msglen, 7);
            hdl_nfs_pwrite(reply);
            break;

        case INT_THRDREQ_NFS_STAT:
            PARAM_COUNT_CHECK(msglen, 4);
            hdl_nfs_stat(reply);
            break;

        case INT_THRDREQ_NFS_OPENDIR:
            PARAM_COUNT_CHECK(msglen, 4);
            hdl_nfs_opendir(reply);
            break;

        case INT_THRDREQ_NFS_DIRENT:
            PARAM_COUNT_CHECK(msglen, 3);
            hdl_nfs_dirent(reply);
            break;

        case INT_THRDREQ_NFS_CLOSEDIR:
            PARAM_COUNT_CHECK(msglen, 2);
            hdl_nfs_closedir(reply);
            break;

        case INT_THRDREQ_NFS_CLOSE:
            PARAM_COUNT_CHECK(msglen, 4);
            hdl_nfs_pclose(reply);
            break;
        
        default:
            ZF_LOGF("Unknown request code!");
    }

    // finished with these reply object
    cspace_delete(&cspace, reply);
    cspace_free_slot(&cspace, reply);
    ut_free(reply_ut);
}

void hdl_do_nothing(seL4_CPtr reply) 
{
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 0);
    seL4_Send(reply, reply_msg);
}

void hdl_userptr_read(seL4_CPtr reply)
{
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    uintptr_t ret = (uintptr_t)userptr_read(seL4_GetMR(1), seL4_GetMR(2), seL4_GetMR(3), seL4_GetMR(4));
    seL4_SetMR(0, ret);
    seL4_Send(reply, reply_msg);
}

void hdl_userptr_write_start(seL4_CPtr reply)
{
    userptr_write_state_t ret = 
        userptr_write_start(seL4_GetMR(1), seL4_GetMR(2), seL4_GetMR(3), seL4_GetMR(4), seL4_GetMR(5));
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, DIV_ROUND_UP(sizeof(ret), sizeof(seL4_Word)));
    memcpy(seL4_GetIPCBuffer()->msg, &ret, sizeof(ret));
    seL4_Send(reply, reply_msg);
}

void hdl_userptr_write_next(seL4_CPtr reply)
{
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    bool ret = userptr_write_next(seL4_GetMR(1));
    seL4_SetMR(0, ret);
    seL4_Send(reply, reply_msg);
}

void hdl_userptr_unmap(seL4_CPtr reply)
{
    userptr_unmap(seL4_GetMR(1));
    hdl_do_nothing(reply);
}

void hdl_free_cap(seL4_CPtr reply)
{
    if(seL4_GetMR(2))
        cspace_delete(&cspace, seL4_GetMR(1));
    if(seL4_GetMR(3))
        cspace_free_slot(&cspace, seL4_GetMR(1));
    hdl_do_nothing(reply);
}

void hdl_free_ut(seL4_CPtr reply)
{
    ut_free(seL4_GetMR(1));
    hdl_do_nothing(reply);
}

void hdl_nfs_open(seL4_CPtr reply)
{
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    int ret = sos_libnfs_open_async(seL4_GetMR(1), seL4_GetMR(2), seL4_GetMR(3), seL4_GetMR(4));
    seL4_SetMR(0, ret);
    seL4_Send(reply, reply_msg);
}

void hdl_nfs_pread(seL4_CPtr reply)
{
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    int ret = sos_libnfs_pread_async(seL4_GetMR(1), seL4_GetMR(2), seL4_GetMR(3),
        seL4_GetMR(4), seL4_GetMR(5));
    seL4_SetMR(0, ret);
    seL4_Send(reply, reply_msg);
}

void hdl_nfs_pwrite(seL4_CPtr reply)
{
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    int ret = sos_libnfs_pwrite_async(seL4_GetMR(1), seL4_GetMR(2), seL4_GetMR(3), seL4_GetMR(4),
        seL4_GetMR(5), seL4_GetMR(6));
    seL4_SetMR(0, ret);
    seL4_Send(reply, reply_msg);
}

void hdl_nfs_stat(seL4_CPtr reply)
{
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    int ret = sos_libnfs_stat_async(seL4_GetMR(1), seL4_GetMR(2), seL4_GetMR(3));
    seL4_SetMR(0, ret);
    seL4_Send(reply, reply_msg);
}

void hdl_nfs_opendir(seL4_CPtr reply)
{
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    int ret = sos_libnfs_opendir_async(seL4_GetMR(1), seL4_GetMR(2), seL4_GetMR(3));
    seL4_SetMR(0, ret);
    seL4_Send(reply, reply_msg);
}

void hdl_nfs_pclose(seL4_CPtr reply)
{
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    int ret = sos_libnfs_close_async(seL4_GetMR(1), seL4_GetMR(2), seL4_GetMR(3));
    seL4_SetMR(0, ret);
    seL4_Send(reply, reply_msg);
}

void hdl_nfs_dirent(seL4_CPtr reply)
{
    const char* ret = sos_libnfs_readdir(seL4_GetMR(1), seL4_GetMR(2));
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, ret);
    seL4_Send(reply, reply_msg);
}

void hdl_nfs_closedir(seL4_CPtr reply)
{
    sos_libnfs_closedir(seL4_GetMR(1));
    hdl_do_nothing(reply);
}
