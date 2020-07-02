#include "nfs.h"
#include "../utils.h"
#include "../grp01.h"
#include "../threads.h"
#include "../network.h"
#include "../delegate.h"
#include "../backtrace.h"

#include <sys/stat.h>
#include <sos/gen_config.h>
#include <sync/mutex.h>
#include <sync/condition_var.h>
#include <utils/zf_log_if.h>
#include <nfsc/libnfs.h>
#include <errno.h>
#include <poll.h>
#include <utils/arith.h>

// otherwise libnfs will complain about not enough memory
#define MAX_LIBNFS_CHUNK 8192

// contains pool for sync between request and libnfs' async callback
typedef struct {
    bool used;
    bool asyncfinish;
    
    // 0 or above = success. meaning depends on command.
    // <0 = negative errno
    int status; 

    union {
        // open
        uintptr_t nfsfh;
        void* readtarget;
    } multipurpose;
    sync_cv_t cv;
    sync_bin_sem_t lck;
} poolobj_t;

typedef enum {
    CMD_OPEN,
    CMD_CLOSE,
    CMD_WRITE,
    CMD_READ
} CmdType;

typedef struct {
    CmdType type;
    size_t poolidx;
} cbparam_t;

static struct {
    poolobj_t objs[BG_HANDLERS];
    sync_mutex_t lck;
    // used for acquire pool
    uint32_t clockhand;
} pool = {0};

/* ---- callbacks for libnfs ---- */
void cb_generic(int status, struct nfs_context *nfs, void *data, void *private_data);

/* ---- util functions ---- */
size_t acquire_pool(void);

void free_pool(size_t idx);

/* ---- macros ---- */
#define GRP01_NFS_PREAMBLE(paramtype) \
    if(!check_nfs_mount_status()) { \
        ZF_LOGE("NFS mount error"); \
        return -EIO; \
    } \
    \
    cbparam_t param; \
    param.poolidx = acquire_pool(); \
    param.type = (paramtype); \
    poolobj_t* mypool = pool.objs + param.poolidx; \
    \
    mypool->asyncfinish = false; \
    mypool->status = 0; \

#define GRP01_NFS_WAIT_ASYNC_FINISH \
    sync_bin_sem_wait(&mypool->lck); \
    while(!mypool->asyncfinish) \
        sync_cv_wait(&mypool->lck, &mypool->cv); \
    sync_bin_sem_post(&mypool->lck); \


void grp01_nfs_init()
{
    ZF_LOGI("Initializing GRP01 NFS sync primitives.");
    int err = 0;

    // mutex for the whole pool
    seL4_CPtr ntfn;
    if(!alloc_retype(&ntfn, seL4_NotificationObject, seL4_NotificationBits)) {
        ZF_LOGE("Error creating notification object");
        return;
    }
    sync_mutex_init(&pool.lck, ntfn);

    // initialize sync primitives for bg workers
    for(int i = 0; i < BG_HANDLERS; ++i) {
        if(!alloc_retype(&ntfn, seL4_NotificationObject, seL4_NotificationBits)) {
            ZF_LOGE("Error creating notification object");
            return;
        }
        sync_bin_sem_init(&pool.objs[i].lck, ntfn, 1);

        if(!alloc_retype(&ntfn, seL4_NotificationObject, seL4_NotificationBits)) {
            ZF_LOGE("Error creating notification object");
            return;
        }
        sync_cv_init(&pool.objs[i].cv, ntfn);
    }
}

ssize_t grp01_nfs_open(seL4_CPtr ep, const char* fn, int mode)
{
    GRP01_NFS_PREAMBLE(CMD_OPEN)
    
    ssize_t ret;
    ret = delegate_libnfs_open_async(ep, fn, mode, cb_generic, &param);
    if(ret) {
        ZF_LOGI("Error initializing NFS open.");
        ret = -EIO;
    } else {
        GRP01_NFS_WAIT_ASYNC_FINISH

        if(mypool->status)
            // ret is negative errno
            ret = mypool->status;
        else
            // zero status = success
            ret = mypool->multipurpose.nfsfh;
    }

    free_pool(param.poolidx);
    return ret;
}

ssize_t grp01_nfs_read(seL4_CPtr ep, ssize_t id, void* ptr, off_t offset, size_t len)
{
    GRP01_NFS_PREAMBLE(CMD_READ)
    
    ssize_t ret;
    mypool->multipurpose.readtarget = ptr;
    ret = delegate_libnfs_pread_async(ep, (struct nfsfh*)id, offset, len, cb_generic, &param);
    if(ret) {
        ZF_LOGI("Error initializing NFS pread.");
        ret = -EIO;
    } else {
        GRP01_NFS_WAIT_ASYNC_FINISH

        ret = mypool->status;
    }
    free_pool(param.poolidx);
    return ret;
}

ssize_t grp01_nfs_write(seL4_CPtr ep, ssize_t id, void* ptr, off_t offset, size_t len)
{
    GRP01_NFS_PREAMBLE(CMD_WRITE)

    ssize_t ret;
    size_t rem = len;
    size_t acc = 0;
    ssize_t err = 0;
    // chunk write so that NFS doesn't run out of memory
    while(rem) {
        size_t towrite = MIN(rem, MAX_LIBNFS_CHUNK);
        
        // don't forget to reset the callback status for each loop!
        mypool->asyncfinish = false;
        mypool->status = 0;

        ret = delegate_libnfs_pwrite_async(ep, (struct nfsfh*)id, offset + acc, towrite, 
            (void*)((uintptr_t)ptr + acc), cb_generic, &param);
        if(ret) {
            ZF_LOGI("Error initializing NFS pwrite.");
            err = -EIO;
            break;
        } else {
            GRP01_NFS_WAIT_ASYNC_FINISH

            if(mypool->status < 0) {
                err = mypool->status;
                break;
            }
            
            // update offset and remaining
            rem -= mypool->status;
            acc += mypool->status;
            // premature stopping whenlibnfs wrote less than what we asked
            if(mypool->status < towrite)
                break;
        }
    }

    free_pool(param.poolidx);
    if(err)
        return err;
    return acc;
}

void grp01_nfs_close(seL4_CPtr ep, ssize_t id)
{
    GRP01_NFS_PREAMBLE(CMD_CLOSE)

    ssize_t ret;
    ret = delegate_libnfs_close_async(ep, (struct nfsfh*)id, cb_generic, &param);
    if(ret) {
        ZF_LOGE("Error closing NFS handle.");
    } else {
        GRP01_NFS_WAIT_ASYNC_FINISH

        if(mypool->status)
            ZF_LOGE("NFS close with error %d", mypool->status);
    }
    free_pool(param.poolidx);
}

void cb_generic(int status, struct nfs_context *nfs, void *data, void *private_data)
{
    cbparam_t* param = private_data;
    poolobj_t *mypool = pool.objs + param->poolidx;

    // set result
    mypool->status = status;
    if(status < 0) {
        ZF_LOGE("Failed to process NFS request: %s", data);
    } else {
        // success. actions and return info depends on command!
        switch(param->type) {
            case CMD_OPEN:
                mypool->multipurpose.nfsfh = data;
                break;
            case CMD_READ:
                if(status > 0) {
                    // fingers crossed that fileman is providing a correct pointer here!
                    memcpy(mypool->multipurpose.readtarget, data, status);
                }
                break;
            case CMD_WRITE:
            case CMD_CLOSE:
                break;
            default:
                // DEBUG. remove assert after finished!
                ZF_LOGF("NFS command not implemented!");
        }
    }

    // notify parent
    sync_bin_sem_wait(&mypool->lck);
    mypool->asyncfinish = true;
    sync_cv_signal(&mypool->cv);
    sync_bin_sem_post(&mypool->lck);
}

size_t acquire_pool()
{
    sync_mutex_lock(&pool.lck);
    ssize_t ret = -1;
    for(size_t i=0; i<BG_HANDLERS; ++i) {
        pool.clockhand = (pool.clockhand + 1) % BG_HANDLERS;
        if(!pool.objs[pool.clockhand].used) {
            pool.objs[pool.clockhand].used = true;
            ret = pool.clockhand;
            break;
        }
    }
    sync_mutex_unlock(&pool.lck);
    // should never happen
    ZF_LOGF_IF(ret == -1, "Cannot grab a pool for NFS");
    return ret;
}

void free_pool(size_t idx)
{
    sync_mutex_lock(&pool.lck);
    pool.objs[idx].used = false;
    sync_mutex_unlock(&pool.lck);
}
