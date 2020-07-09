#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <utils/zf_log.h>
#include <utils/zf_log_if.h>
#include <sync/mutex.h>
#include <cspace/cspace.h>
#include <sys/types.h>

#include "utils.h"
#include "fs/console.h"
#include "fs/nullfile.h"
#include "fs/nfs.h"
#include "fs/fake.h"
#include "bgworker.h"
#include "ut.h"
#include "grp01.h"
#include "vm/mapping2.h"
#include "delegate.h"

#include "fileman.h"
#include "proctable.h"

#define MAX_FH  128
#define SPECIAL_HANDLERS 1

// WARNING! double eval!
#define DIV_ROUND_UP_CEXPR(n,d) \
    (((n) + (d) - 1) / (d))

// struct declaration area

struct filehandler
{
    file_open_fn open;
    file_rw_fn read;
    file_rw_fn write;
    file_stat_fn stat;
    file_opendir_fn opendir;
    file_dirent_fn gdent;
    file_closedir_fn closedir;
    file_close_fn close;
};

struct fileentry
{
    bool used;
    bool dir; // true = directory, false = file
    struct filehandler * handler;
    ssize_t id; // id internal to the file system
    off_t offset;
};

struct filetable
{
    bool used;
    uint16_t ch; // clockhand
    struct fileentry fe[MAX_FH];
    sync_mutex_t felock; // big lock to lock the whole fe table
};

// PLAN: GRP01 should be replaced by a hashmap once we have more than one handlers
struct {
    const char* name;
    struct filehandler handler;
} specialhandlers[SPECIAL_HANDLERS];

struct filehandler nullhandler;

struct filehandler defaulthandler;

// structs specific for arguments to bgworker
struct bg_open_param {
    char* filename;
    size_t filename_len;
    char filename_term;
    seL4_Word pid;
    seL4_CPtr reply;
    ut_t* reply_ut;
    int mode;
    bool dir;
};

struct bg_rw_param {
    bool read; //false = write
    userptr_t buff;
    uint32_t len;
    seL4_Word pid;
    int fh;
    seL4_CPtr reply;
    ut_t* reply_ut;
};

struct bg_close_param {
    seL4_Word pid;
    int fh;
    seL4_CPtr reply;
    ut_t* reply_ut;
};

struct bg_stat_param {
    char* filename;
    size_t filename_len;
    char filename_term;
    seL4_Word pid;
    seL4_CPtr reply;
    ut_t* reply_ut;
};

struct bg_readdir_param {
    seL4_Word pid;
    userptr_t buff;
    size_t bufflen;
    size_t pos;
    int fh;
    seL4_CPtr reply;
    ut_t* reply_ut;
};

// local variables declaration area

struct filetable ft[MAX_PID];

// local functions declaration area
void send_and_free_reply_cap(seL4_CPtr delegate_ep, ssize_t response, seL4_CPtr reply, ut_t* reply_ut);
void send_and_free_reply_cap_ex(seL4_CPtr delegate_ep, ssize_t response, size_t extrawords, void* extradata, seL4_CPtr reply, ut_t* reply_ut);
void bg_fileman_open(seL4_CPtr delegate_ep, void* data);
void bg_fileman_rw(seL4_CPtr delegate_ep, void* data);
void bg_fileman_close(seL4_CPtr delegate_ep, void* data);
void bg_fileman_stat(seL4_CPtr delegate_ep, void* data);
void bg_fileman_readdir(seL4_CPtr delegate_ep, void* data);
int fileman_rw_dispatch(bool read, seL4_Word pid, int fh, seL4_CPtr reply, ut_t* reply_ut, userptr_t buff, uint32_t len);
ssize_t fileman_write_broker(seL4_CPtr delegate_ep, struct filehandler* fh, ssize_t id, userptr_t ptr, seL4_Word badge, size_t len, off_t offset);
ssize_t fileman_read_broker(seL4_CPtr delegate_ep, struct filehandler* fh, ssize_t id, userptr_t ptr, seL4_Word badge, size_t len, off_t offset);
struct filehandler * find_handler(const char* fn);
char* map_user_string(userptr_t ptr, size_t len, seL4_Word badge, char* originalchar);
void unmap_user_string_bg(seL4_CPtr ep, char* myptr, size_t len, seL4_Word badge, char originalchar);
int find_unused_slot(struct filetable* pft);

// function definitions area

bool fileman_init()
{
    memset(ft, 0, sizeof(ft));

    nullhandler.open = null_fs_open;
    nullhandler.close = null_fs_close;
    nullhandler.read = null_fs_read;
    nullhandler.write = null_fs_write;
    nullhandler.stat = null_fs_stat;
    nullhandler.opendir = null_fs_opendir;
    nullhandler.gdent = null_fs_dirent;
    nullhandler.closedir = null_fs_closedir;

    defaulthandler.open = grp01_nfs_open;
    defaulthandler.close = grp01_nfs_close;
    defaulthandler.read = grp01_nfs_read;
    defaulthandler.write = grp01_nfs_write;
    defaulthandler.stat = grp01_nfs_stat;
    defaulthandler.opendir = grp01_nfs_opendir;
    defaulthandler.gdent = grp01_nfs_dirent;
    defaulthandler.closedir = grp01_nfs_closedir;
    

    // install special handlers (console)
    specialhandlers[0].name = "console";
    specialhandlers[0].handler.open = console_fs_open;
    specialhandlers[0].handler.close = console_fs_close;
    specialhandlers[0].handler.read = console_fs_read;
    specialhandlers[0].handler.write = console_fs_write;
    specialhandlers[0].handler.stat = null_fs_stat;
    specialhandlers[0].handler.opendir = null_fs_opendir;
    specialhandlers[0].handler.gdent = null_fs_dirent;
    specialhandlers[0].handler.closedir = null_fs_closedir;

    // specialhandlers[1].name = "fake";
    // specialhandlers[1].handler.open = null_fs_open;
    // specialhandlers[1].handler.close = null_fs_close;
    // specialhandlers[1].handler.read = null_fs_read;
    // specialhandlers[1].handler.write = null_fs_write;
    // specialhandlers[1].handler.stat = fake_fs_stat;
    // specialhandlers[1].handler.opendir = fake_fs_opendir;
    // specialhandlers[1].handler.gdent = fake_fs_dirent;
    // specialhandlers[1].handler.closedir = null_fs_close;

    return true;
}

int fileman_create(seL4_Word pid)
{
    // the usual error checking
    if(pid >= MAX_PID)
        return EBADF;
    if(ft[pid].used)
        return EEXIST;

    // initialize the sync primitives (if not exists)
    // notification 0 means that we didn't initialize the mutex for this PID before.
    // because upon SOS startup, we zeroed out the whole table.
    if(!ft[pid].felock.notification) {
    seL4_CPtr tmp_ntfn;
        if(!alloc_retype(&tmp_ntfn, seL4_NotificationObject, seL4_NotificationBits)) {
            ZF_LOGE("Cannot create notification object.");
            return ENOMEM;
        }
        sync_mutex_init(&ft[pid].felock, tmp_ntfn);
    }

    // empty the file table
    memset(ft[pid].fe, 0, sizeof(ft[pid].fe));

    // by default, stdin/out/err is reserved!
    for(int i=0; i<=2; ++i) {
        ft[pid].fe[i].used = true;
        ft[pid].fe[i].handler = &nullhandler;
    }
    
    // set the flag to indicate that someone is using this PID
    ft[pid].used = true;

    return 0;
}

int fileman_open(seL4_Word pid, seL4_CPtr reply, ut_t* reply_ut, userptr_t filename, size_t filename_len, bool dir, int mode)
{
    // error checking
    // bad pid
    if((pid >= MAX_PID) || (!ft[pid].used))
        return EBADF * -1;

    // prepare for run the open in background
    struct bg_open_param * param = malloc(sizeof(struct bg_open_param));
    if(!param)
        return ENOMEM * -1;
    param->filename = map_user_string(filename, filename_len, pid, &param->filename_term);
    if(!param->filename) {
        free(param);
        return -EFAULT;
    }
    param->filename_len = filename_len;
    param->mode = mode;
    param->dir = dir;
    param->pid = pid;
    param->reply = reply;
    param->reply_ut = reply_ut;

    bgworker_enqueue_callback(pid, bg_fileman_open, param);
    return 0;
}

int fileman_close(seL4_Word pid, seL4_CPtr reply, ut_t* reply_ut, int fh)
{
    // basic error check
    if((pid >= MAX_PID) || (!ft[pid].used))
        return 1;
    if((fh < 0) || fh >= MAX_FH)
        return 1;

    // run in bg. close operation may block when waiting for lock, for example
    struct bg_close_param * param = malloc(sizeof(struct bg_close_param));
    if(!param)
        return ENOMEM * -1;
    param->pid = pid;
    param->fh = fh;
    param->reply = reply;
    param->reply_ut = reply_ut;

    bgworker_enqueue_callback(pid, bg_fileman_close, param);
    return 0;
}

int fileman_write(seL4_Word pid, int fh, seL4_CPtr reply, ut_t* reply_ut, userptr_t buff, uint32_t len)
{
    return fileman_rw_dispatch(false, pid, fh, reply, reply_ut, buff, len);
}

int fileman_read(seL4_Word pid, int fh, seL4_CPtr reply, ut_t* reply_ut, userptr_t buff, uint32_t len)
{
    return fileman_rw_dispatch(true, pid, fh, reply, reply_ut, buff, len);
}

int fileman_rw_dispatch(bool read, seL4_Word pid, int fh, seL4_CPtr reply, ut_t* reply_ut, userptr_t buff, uint32_t len)
{
    // error checking
    // bad pid
    if((pid >= MAX_PID) || (!ft[pid].used))
        return EBADF * -1;

    // bad fh
    if((fh < 0) || fh >= MAX_FH)
        return EBADF * -1;

    // prepare for bg run
    struct bg_rw_param * param = malloc(sizeof(struct bg_rw_param));
    if(!param)
        return ENOMEM * -1;
    param->read = read;
    param->pid = pid;
    param->fh = fh;
    param->buff = buff;
    param->len = len;
    param->reply = reply;
    param->reply_ut = reply_ut;

    bgworker_enqueue_callback(pid, bg_fileman_rw, param);
    return 0;
}

int fileman_stat(seL4_Word pid, seL4_CPtr reply, ut_t* reply_ut, userptr_t filename, size_t filename_len)
{
    if(pid >= MAX_PID)
        return -EINVAL;
    
    struct bg_stat_param * param = malloc(sizeof(struct bg_stat_param));
    if(!param)
        return -ENOMEM;
    
    param->filename = map_user_string(filename, filename_len, pid, &param->filename_term);
    if(!filename) {
        free(param);
        return -EFAULT;
    }
    
    param->filename_len = filename_len;
    param->pid = pid;
    param->reply = reply;
    param->reply_ut = reply_ut;

    bgworker_enqueue_callback(pid, bg_fileman_stat, param);
    return 0;
}

int fileman_readdir(seL4_Word pid, int fh, seL4_CPtr reply, ut_t* reply_ut, size_t pos, userptr_t buff, size_t bufflen)
{
    if(pid >= MAX_PID)
        return -EINVAL;

    struct bg_readdir_param * param = malloc(sizeof(struct bg_readdir_param));
    if(!param)
        return -ENOMEM;
    
    param->pid = pid;
    param->buff = buff;
    param->bufflen = bufflen;
    param->pos = pos;
    param->fh = fh;
    param->reply = reply;
    param->reply_ut = reply_ut;

    bgworker_enqueue_callback(pid, bg_fileman_readdir, param);
    return 0;
}

void send_and_free_reply_cap(seL4_CPtr delegate_ep, ssize_t response, seL4_CPtr reply, ut_t* reply_ut)
{
    send_and_free_reply_cap_ex(delegate_ep, response, 0, NULL, reply, reply_ut);
}

void send_and_free_reply_cap_ex(seL4_CPtr delegate_ep, ssize_t response, size_t extrawords, void* extradata, seL4_CPtr reply, ut_t* reply_ut)
{
    ZF_LOGF_IF(extrawords >= seL4_MsgMaxLength, "Extra reply too large");
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1 + extrawords);
    seL4_SetMR(0, response);
    if(extrawords) 
        memcpy(seL4_GetIPCBuffer()->msg + 1, extradata, extrawords * sizeof(seL4_Word));

    seL4_Send(reply, reply_msg);
    // delete the reply cap for now (and mark the backing ut as free)
    delegate_free_cap(delegate_ep, reply, true, true);
    delegate_free_ut(delegate_ep, reply_ut);
}

void bg_fileman_open(seL4_CPtr delegate_ep, void* data)
{
    struct bg_open_param * param = data;
    struct filetable* pft = ft + param->pid;

    // 0 or more = file handle number
    // negative = negative errno convention
    int ret = 0;

    sync_mutex_lock(&pft->felock);

    // find unused slot in the process' file table
    int slot = find_unused_slot(pft);

    // process file table is full!
    if(slot < 0) {
        ret = EMFILE * -1;
        goto finish;
    }

    struct filehandler * handler = find_handler(param->filename);

    // try open
    ssize_t id = param->dir ? 
        handler->opendir(delegate_ep, param->filename) :
        handler->open(delegate_ep, param->filename, param->mode);
    if(id < 0) {
        // failure. we expect the opener to return our negative errno model.
        ret = id;
        goto finish;
    }

    // OK. assign to process' file table entry
    struct fileentry * pfe = pft->fe + slot;
    pfe->used = true;
    pfe->dir = param->dir;
    pfe->id = id;
    pfe->handler = handler;
    pfe->offset = 0;

    // and return the slot number
    ret = slot;

finish:
    unmap_user_string_bg(delegate_ep, param->filename, param->filename_len, param->pid,
        param->filename_term);
    sync_mutex_unlock(&pft->felock);
    send_and_free_reply_cap(delegate_ep, ret, param->reply, param->reply_ut);
    free(param);
}

void bg_fileman_rw(seL4_CPtr delegate_ep, void* data)
{
    struct bg_rw_param * param = data;
    struct filetable* pft = ft + param->pid;
    struct fileentry* pfe = pft->fe + param->fh;

    // 0 or more = number of bytes writen (yes, can be 0!)
    // negative = negative errno convention
    ssize_t ret = 0;

    sync_mutex_lock(&pft->felock);
    if(!pfe->used) {
        ret = EBADF * -1;
        goto finish;
    }

    // use directory function please!
    if(pfe->dir) {
        ret = -EBADF;
        goto finish;
    }

    if(!param->len) {
        ret = 0;
        goto finish;
    }

    if(!param->buff) {
        ret = EFAULT * -1;
        goto finish;
    }

    // action!
    if(param->read)
        ret = fileman_read_broker(delegate_ep, pfe->handler, pfe->id, param->buff, param->pid, param->len, pfe->offset);
    else
        ret = fileman_write_broker(delegate_ep, pfe->handler, pfe->id, param->buff, param->pid, param->len, pfe->offset);

    // increment offset if we got a successful read!
    if(ret > 0) 
        pfe->offset += ret;

finish:
    sync_mutex_unlock(&pft->felock);
    send_and_free_reply_cap(delegate_ep, ret, param->reply, param->reply_ut);
    free(param);
}

void bg_fileman_close(seL4_CPtr delegate_ep, void* data)
{
    struct bg_close_param * param = data;
    struct filetable* pft = ft + param->pid;
    struct fileentry* pfe = pft->fe + param->fh;

    sync_mutex_lock(&pft->felock);
    if(pfe->used) {
        if(pfe->dir)
            pfe->handler->closedir(delegate_ep, pfe->id);
        else
            pfe->handler->close(delegate_ep, pfe->id);
        
        pfe->used = false;
    }
    
    //finish:
    sync_mutex_unlock(&pft->felock);
    send_and_free_reply_cap(delegate_ep, 1, param->reply, param->reply_ut);
    free(param);
}

void bg_fileman_stat(seL4_CPtr delegate_ep, void* data)
{
    struct bg_stat_param * param = data;
    struct filehandler * handler = find_handler(param->filename);
    union {
        sos_stat_t st;
        seL4_Word matcher[DIV_ROUND_UP_CEXPR(sizeof(sos_stat_t), sizeof(seL4_Word))];
    } target = {0};
    ssize_t err = handler->stat(delegate_ep, param->filename, &target.st);

finish:
    unmap_user_string_bg(delegate_ep, param->filename, param->filename_len, param->pid,
        param->filename_term);
    if(err)
        send_and_free_reply_cap(delegate_ep, err, param->reply, param->reply_ut);
    else
        send_and_free_reply_cap_ex(delegate_ep, 1, sizeof(target)/sizeof(seL4_Word), target.matcher,
            param->reply, param->reply_ut);
    free(param);
}

void bg_fileman_readdir(seL4_CPtr delegate_ep, void* data)
{
    struct bg_readdir_param * param = data;
    struct filetable* pft = ft + param->pid;
    struct fileentry* pfe = pft->fe + param->fh;

    // 0 or more = number of bytes writen (e.g. file name length)
    // negative = negative errno convention
    ssize_t ret = 0;

    sync_mutex_lock(&pft->felock);
    if(!pfe->used) {
        ret = EBADF * -1;
        goto finish;
    }
    if(!pfe->dir) {
        ret = -EBADF;
        goto finish;
    }

    const char* dent = pfe->handler->gdent(delegate_ep, pfe->id, param->pos);

    // NULL file name? "return" 0!
    if(!dent)
        goto finish;

    // if we got a string, get the length first
    // if buffer is not enough, let user takes care about the terminating NULL
    ret = MIN(strlen(dent) + 1, param->bufflen);

    // copy to the pointer given to user
    userptr_write_state_t it = delegate_userptr_write_start(delegate_ep, 
        param->buff, ret, param->pid);

    if(!it.curr) {
        ret = -EFAULT;
        goto finish;
    }
    // used for unmapping userptr
    void* startptr = (void*)it.curr;

    while(it.curr) {
        memcpy((void*)it.curr, dent, it.remcurr);
        dent += it.remcurr;
        if(!delegate_userptr_write_next(delegate_ep, &it)) {
            ret = -EFAULT;
            break;
        }
    }

    delegate_userptr_unmap(delegate_ep, startptr);

finish:
    sync_mutex_unlock(&pft->felock);
    send_and_free_reply_cap(delegate_ep, ret, param->reply, param->reply_ut);
    free(param);
}

ssize_t fileman_write_broker(seL4_CPtr delegate_ep, struct filehandler* fh, ssize_t id, userptr_t ptr, seL4_Word badge, size_t len, off_t offset)
{
    void* buff = delegate_userptr_read(delegate_ep, ptr, len, badge);
    if(!buff)
        return EFAULT * -1;
    
    ssize_t ret = fh->write(delegate_ep, id, buff, offset, len);

    delegate_userptr_unmap(delegate_ep, buff);

    return ret;
}

ssize_t fileman_read_broker(seL4_CPtr delegate_ep, struct filehandler* fh, ssize_t id, userptr_t ptr, seL4_Word badge, size_t len, off_t offset)
{
    if(!len)
        return 0;

    userptr_write_state_t it = delegate_userptr_write_start(delegate_ep, ptr, len, badge);
    if(!it.curr)
        return -EFAULT;
    
    ssize_t ret = 0;
    void* startptr = (void*)it.curr;

    while(it.curr) {
        ssize_t rd = fh->read(delegate_ep, id, (void*)it.curr, ret + offset, it.remcurr);
        if(rd < 0) {
            ZF_LOGE("Filesystem returned an error");
            ret = -EIO;
            break;
        }
        ret += rd;
        if (rd < it.remcurr)
            // EOF!
            break;
        
        if(!delegate_userptr_write_next(delegate_ep, &it)) {
            ZF_LOGE("Error incrementing pointer when handling user read request.");
            ret = -EIO;
            break;
        }
    }

    delegate_userptr_unmap(delegate_ep, startptr);
    
    return ret;
}

struct filehandler * find_handler(const char* fn)
{
    for(int i=0; i<SPECIAL_HANDLERS; ++i) {
        if(strcmp(fn, specialhandlers[i].name) == 0) 
            return &specialhandlers[i].handler;
    }
    
    return &defaulthandler;
}

char* map_user_string(userptr_t ptr, size_t len, seL4_Word badge, char* originalchar)
{
    // WARNING! this function is meant to be called from main thread
    char* ret = userptr_read(ptr, len + 1, badge);
    if(!ret)
        return ret;
    // set last char to NULL to ensure safety
    *originalchar = ret[len];
    ret[len] = 0;
    return ret;
}

void unmap_user_string_bg(seL4_CPtr ep, char* myptr, size_t len, seL4_Word badge, char originalchar)
{
    // WARNING! this function is meant to be called from background thread
    myptr[len] = originalchar;
    delegate_userptr_unmap(ep, myptr);
}

int find_unused_slot(struct filetable* pft)
{
    int slot = -1;
    for(int i=0; i<MAX_FH; ++i) {
        if(!pft->fe[pft->ch].used) 
            slot = pft->ch;
        // increment clockhand
        pft->ch = (pft->ch + 1) % MAX_FH;
        
        if(slot >= 0)
            break;
    }

    return slot;
}