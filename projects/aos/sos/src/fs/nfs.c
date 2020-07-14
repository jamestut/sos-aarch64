#include "nfs.h"
#include "../utils.h"
#include "../grp01.h"
#include "../threads.h"
#include "../network.h"
#include "../delegate.h"
#include "../backtrace.h"

#include <sys/stat.h>
#include <sync/mutex.h>
#include <sync/condition_var.h>
#include <utils/zf_log_if.h>
#include <nfsc/libnfs.h>
#include <errno.h>
#include <poll.h>
#include <utils/arith.h>
#include <fcntl.h>

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
        sos_stat_t* stattarget;
        struct nfsdir* nfsdir;
    } multipurpose;
    sync_cv_t cv;
    sync_bin_sem_t lck;
} poolobj_t;

typedef union {
    uintptr_t nfsfh; // for open
    void* readtarget;
    sos_stat_t* stattarget;
    struct nfsdir* nfsdir;
} multipurpose_word_t;

typedef enum {
    CMD_OPEN,
    CMD_CLOSE,
    CMD_WRITE,
    CMD_READ,
    CMD_STAT,
    CMD_OPENDIR,
    CMD_OTHER
} CmdType;

typedef struct {
    ssize_t status; // <0 = errno, >=0 = success
    CmdType type;
    multipurpose_word_t data;
    seL4_CPtr ntfn;
} cb_param_t;

// fileman will give us a PID to guarantee that same PID = same thread
// we can leverage this fact to store notification objects to avoid
// recreating/freeing them over and over again
seL4_CPtr ntfnpool[MAX_PID] = {0};

/* ---- callbacks for libnfs ---- */
void cb_generic(int status, struct nfs_context *nfs, void *data, void *private_data);

/* ---- macros ---- */
#define GRP01_NFS_CHECK \
    if(!check_nfs_mount_status()) { \
        ZF_LOGE("NFS mount error"); \
        return -EIO; \
    }

#define GRP01_NFS_ASYNC_PREAMBLE(paramtype) \
    cb_param_t param; \
    param.type = (paramtype); \
    param.ntfn = ntfnpool[pid]; \
    seL4_Poll(param.ntfn, NULL);

/* ---- util functions ---- */
void convert_stat(struct stat* src, sos_stat_t* dst);

void grp01_nfs_init()
{
    // create notification objects on pool
    for(int i = 0; i < MAX_PID; ++i) {
        ZF_LOGF_IF(!alloc_retype(ntfnpool + i, seL4_NotificationObject, seL4_NotificationBits),
            "Error creating notification object pool for NFS driver");
    }
}

ssize_t grp01_nfs_open(seL4_Word pid, const char* fn, int mode)
{
    GRP01_NFS_CHECK
    GRP01_NFS_ASYNC_PREAMBLE(CMD_OPEN)
    
    ssize_t ret;
    // we intentionally include O_CREAT here as sosh doesn't pass this flag
    // otherwise, cp on unmodified sosh will fail
    ret = sos_libnfs_open_async(fn, mode | O_CREAT, cb_generic, &param);
    if(ret) {
        ZF_LOGI("Error initializing NFS open.");
        ret = -EIO;
    } else {
        seL4_Wait(param.ntfn, NULL);

        if(param.status)
            ret = param.status;
        else
            // zero status = success
            ret = param.data.nfsfh;
    }

    return ret;
}

ssize_t grp01_nfs_read(seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len)
{
    GRP01_NFS_ASYNC_PREAMBLE(CMD_READ)

    ssize_t ret;
    param.data.readtarget = ptr;
    ret = sos_libnfs_pread_async((struct nfsfh*)id, offset, len, cb_generic, &param);
    if(ret) {
        ZF_LOGI("Error initializing NFS pread.");
        ret = -EIO;
    } else {
        seL4_Wait(param.ntfn, NULL);
        ret = param.status; // -0 == 0
    }
    return ret;
}

ssize_t grp01_nfs_write(seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len)
{
    GRP01_NFS_ASYNC_PREAMBLE(CMD_WRITE)

    ssize_t ret;
    size_t rem = len;
    size_t acc = 0;
    ssize_t err = 0;
    // chunk write so that NFS doesn't run out of memory
    while(rem) {
        size_t towrite = MIN(rem, MAX_LIBNFS_CHUNK);
        
        // don't forget to reset the callback status for each loop!
        param.status = 0;

        ret = sos_libnfs_pwrite_async((struct nfsfh*)id, offset + acc, towrite, 
            (void*)((uintptr_t)ptr + acc), cb_generic, &param);
        if(ret) {
            ZF_LOGI("Error initializing NFS pwrite.");
            err = -EIO;
            break;
        } else {
            seL4_Wait(param.ntfn, NULL);

            if(param.status < 0) {
                err = param.status;
                break;
            }
            
            // update offset and remaining
            rem -= param.status;
            acc += param.status;
            // premature stopping when libnfs wrote less than what we asked
            if(param.status < towrite)
                break;
        }
    }

    if(err)
        return err;
    return acc;
}

ssize_t grp01_nfs_stat(seL4_Word pid, char* path, sos_stat_t* out)
{
    GRP01_NFS_CHECK
    GRP01_NFS_ASYNC_PREAMBLE(CMD_STAT)

    ssize_t ret;
    param.data.stattarget = out;
    ret = sos_libnfs_stat_async(path, cb_generic, &param);
    if(ret) {
        ZF_LOGE("Error retreiving stat");
        ret = -EIO;
    } else {
        seL4_Wait(param.ntfn, NULL);
        ret = param.status;
    }

    return ret;
}

ssize_t grp01_nfs_opendir(seL4_Word pid, char* path)
{
    GRP01_NFS_CHECK
    GRP01_NFS_ASYNC_PREAMBLE(CMD_OPENDIR)

    ssize_t ret;
    ret = sos_libnfs_opendir_async(path, cb_generic, &param);
    if(ret) {
        ZF_LOGE("Error opening directory");
        ret = -EIO;
    } else {
        seL4_Wait(param.ntfn, NULL);
        ret = param.status;
        if(!ret)
            ret = param.data.nfsdir;
    }

    return ret;
}

const char* grp01_nfs_dirent(seL4_Word pid, ssize_t id, size_t pos)
{
    return sos_libnfs_readdir(id, pos);
}

void grp01_nfs_closedir(seL4_Word pid, ssize_t id)
{
    sos_libnfs_closedir(id);
}

void grp01_nfs_close(seL4_Word pid, ssize_t id)
{
    GRP01_NFS_ASYNC_PREAMBLE(CMD_CLOSE)    

    ssize_t ret;
    ret = sos_libnfs_close_async((struct nfsfh*)id, cb_generic, &param);
    if(ret) {
        ZF_LOGE("Error closing NFS handle.");
    } else {
        seL4_Wait(param.ntfn, NULL);
        if(param.status)
            ZF_LOGE("NFS close with error %d", param.status);
    }
}

void cb_generic(int status, struct nfs_context *nfs, void *data, void *private_data)
{
    cb_param_t* param = private_data;

    // set result
    param->status = status;
    if(status < 0) {
        ZF_LOGE("Failed to process NFS request: %s", data);
    } else {
        // success. actions and return info depends on command!
        switch(param->type) {
            case CMD_OPEN:
                param->data.nfsfh = (uintptr_t)data;
                break;
            case CMD_READ:
                if(status > 0) {
                    // fingers crossed that fileman is providing a correct pointer here!
                    memcpy(param->data.readtarget, data, status);
                }
                break;
            case CMD_WRITE:
            case CMD_CLOSE:
                break;
            case CMD_STAT:
                convert_stat(data, param->data.stattarget);
                break;
            case CMD_OPENDIR:
                param->data.nfsdir = data;
                break;
            default:
                ZF_LOGF("NFS command not implemented!");
        }
    }

    // notify parent
    seL4_Signal(param->ntfn);
}

/* useless definitions that interferes with our data structure! */
#undef st_atime
#undef st_ctime

void convert_stat(struct stat* src, sos_stat_t* dst)
{
    dst->st_atime = src->st_atim.tv_sec * 1000 + src->st_atim.tv_nsec / 1000000;
    dst->st_ctime = src->st_ctim.tv_sec * 1000 + src->st_ctim.tv_nsec / 1000000;
    dst->st_size = src->st_size;

    dst->st_fmode = ((S_IREAD & src->st_mode) ? FM_READ : 0) |
        ((S_IWRITE & src->st_mode) ? FM_WRITE : 0) |
        ((S_IEXEC & src->st_mode) ? FM_EXEC : 0);
    dst->st_type = S_ISREG(src->st_mode) ? ST_FILE : ST_SPECIAL; 
}
