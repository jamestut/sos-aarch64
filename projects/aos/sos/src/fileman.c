#include <sos/gen_config.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <utils/zf_log.h>
#include <utils/zf_log_if.h>
#include <cspace/cspace.h>
#include <sys/types.h>
#include <fcntl.h>

#include "utils.h"
#include "fs/console.h"
#include "fs/nullfile.h"
#include "fs/nfs.h"
#include "fs/fake.h"
#include "fs/cpiofs.h"
#include "bgworker.h"
#include "ut.h"
#include "grp01.h"
#include "vm/mapping2.h"
#include "delegate.h"
#include "threadassert.h"

#include "fileman.h"
#include "proctable.h"

#define MAX_FH  128
#define SPECIAL_HANDLERS 2
#define READ_PAGE_CHUNK 2

// WARNING! double eval!
#define DIV_ROUND_UP_CEXPR(n,d) \
    (((n) + (d) - 1) / (d))

// struct declaration area

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
    bool active; // true if there is IO in progress
    bool pendingdestroy; // true if destroy was called when active was true
    seL4_CPtr active_mtx; // mutex for activity indicator and pending destroy
    uint16_t ch; // clockhand
    struct fileentry fe[MAX_FH];
};

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
};

struct bg_close_param {
    seL4_Word pid;
    int fh;
    seL4_CPtr reply;
};

struct bg_stat_param {
    char* filename;
    size_t filename_len;
    char filename_term;
    seL4_Word pid;
    seL4_CPtr reply;
};

struct bg_readdir_param {
    seL4_Word pid;
    userptr_t buff;
    size_t bufflen;
    size_t pos;
    int fh;
    seL4_CPtr reply;
};

// local variables declaration area
struct filetable ft[MAX_PID];

// used to signal main thread if a process has pending IO while killed
seL4_CPtr io_finish_ep;

struct filehandler* consolehandler;

// local functions declaration area
void send_and_free_reply_cap(ssize_t response, seL4_CPtr reply);
void send_and_free_reply_cap_ex(ssize_t response, size_t extrawords, void* extradata, seL4_CPtr reply);
void bg_fileman_open(void* data);
void bg_fileman_rw(void* data);
void bg_fileman_close(void* data);
void bg_fileman_stat(void* data);
void bg_fileman_readdir(void* data);
int fileman_rw_dispatch(bool read, seL4_Word pid, int fh, seL4_CPtr reply, userptr_t buff, uint32_t len);
ssize_t fileman_write_broker(struct filehandler* fh, ssize_t id, userptr_t ptr, seL4_Word badge, size_t len, off_t offset);
ssize_t fileman_chunked_write_broker(struct filehandler* fh, ssize_t id, userptr_t ptr, seL4_Word badge, size_t len, off_t offset);
ssize_t fileman_read_broker(struct filehandler* fh, ssize_t id, userptr_t ptr, seL4_Word badge, size_t len, off_t offset);
struct filehandler * find_handler(const char* fn);
char* map_user_string(userptr_t ptr, size_t len, seL4_Word badge, char* originalchar);
void unmap_user_string_bg(char* myptr, size_t len, seL4_Word badge, char originalchar);
int find_unused_slot(struct filetable* pft);
void activate_pft(struct filetable* pft);
void pft_activity_finish(seL4_Word pid);

// function definitions area

bool fileman_init(cspace_t* srccspace, seL4_CPtr ipc_ep)
{
    io_finish_ep = cspace_alloc_slot(&cspace);
    ZF_LOGF_IF(!io_finish_ep, "Cannot allocate slot for endpoint");
    ZF_LOGF_IF(cspace_mint(&cspace, io_finish_ep, srccspace, ipc_ep, seL4_AllRights, BADGE_IO_FINISH) != seL4_NoError,
        "Error minting endpoint");

    memset(ft, 0, sizeof(ft));

    nullhandler.open = null_fs_open;
    nullhandler.close = null_fs_close;
    nullhandler.read = null_fs_read;
    nullhandler.write = null_fs_write;
    nullhandler.stat = null_fs_stat;
    nullhandler.opendir = null_fs_opendir;
    nullhandler.gdent = null_fs_dirent;
    nullhandler.closedir = null_fs_closedir;

    #if CONFIG_SOS_LOCAL_FS > 0ul
    defaulthandler.open = cpio_fs_open;
    defaulthandler.close = cpio_fs_close;
    defaulthandler.read = cpio_fs_read;
    defaulthandler.write = cpio_fs_write;
    defaulthandler.stat = cpio_fs_stat;
    defaulthandler.opendir = cpio_fs_opendir;
    defaulthandler.gdent = cpio_fs_dirent;
    defaulthandler.closedir = cpio_fs_closedir;
    #else
    defaulthandler.open = grp01_nfs_open;
    defaulthandler.close = grp01_nfs_close;
    defaulthandler.read = grp01_nfs_read;
    defaulthandler.write = grp01_nfs_write;
    defaulthandler.stat = grp01_nfs_stat;
    defaulthandler.opendir = grp01_nfs_opendir;
    defaulthandler.gdent = grp01_nfs_dirent;
    defaulthandler.closedir = grp01_nfs_closedir;
    #endif
    

    // install special handlers (console)
    memset(specialhandlers, 0, sizeof(specialhandlers));
    specialhandlers[0].name = "console";
    specialhandlers[0].handler.open = console_fs_open;
    specialhandlers[0].handler.close = console_fs_close;
    specialhandlers[0].handler.read = console_fs_read;
    specialhandlers[0].handler.write = console_fs_write;
    specialhandlers[0].handler.stat = null_fs_stat;
    specialhandlers[0].handler.opendir = null_fs_opendir;
    specialhandlers[0].handler.gdent = null_fs_dirent;
    specialhandlers[0].handler.closedir = null_fs_closedir;

    #if CONFIG_SOS_FAKE_PF > 0ul
    specialhandlers[1].name = "fake";
    specialhandlers[1].handler.open = fake_fs_open;
    specialhandlers[1].handler.close = null_fs_close;
    specialhandlers[1].handler.read = fake_fs_read;
    specialhandlers[1].handler.write = fake_fs_write;
    specialhandlers[1].handler.stat = fake_fs_stat;
    specialhandlers[1].handler.opendir = fake_fs_opendir;
    specialhandlers[1].handler.gdent = fake_fs_dirent;
    specialhandlers[1].handler.closedir = null_fs_close;
    #endif

    consolehandler = find_handler("console");
    ZF_LOGF_IF(!consolehandler, "Console handler not found");

    return true;
}

int fileman_create(seL4_Word pid)
{
    // the usual error checking
    if(pid >= MAX_PID)
        return EBADF;
    if(ft[pid].used)
        return EEXIST;

    // create the ntfn for mutex
    if(!ft[pid].active_mtx) {
        if(!alloc_retype(&ft[pid].active_mtx, seL4_NotificationObject, seL4_NotificationBits))
            return ENOMEM;
        seL4_Signal(ft[pid].active_mtx);
    }

    // stdout and stderr should be initialized to console
    ssize_t consoleid = consolehandler->open(pid, "console", O_WRONLY);
    if(consoleid >= 0) {
        for(int i=1; i<=2; ++i) {
            ft[pid].fe[i].used = true;
            ft[pid].fe[i].handler = consolehandler;
            ft[pid].fe[i].id = consoleid;
        }
    } else {
        ZF_LOGE("Console cannot be opened for PID %d. Expect stdout and stderr to not work.", pid);
    }

    // set the flag to indicate that someone is using this PID
    ft[pid].used = true;

    return 0;
}

bool fileman_destroy(seL4_Word pid) {
    struct filetable* pft = ft + pid;
    if(!pft->used)
        return true;
    
    bool carryondestruct = true;
    seL4_Wait(pft->active_mtx, NULL);
    if(pft->active) {
        pft->pendingdestroy = true;
        carryondestruct = false;
    }
    seL4_Signal(pft->active_mtx);

    if(carryondestruct) {
        struct fileentry* cfe = pft->fe;
        for(int i=0; i<MAX_FH; ++i, ++cfe) {
            if(cfe->used) {
                if(cfe->dir)
                    cfe->handler->closedir(pid, cfe->id);
                else
                    cfe->handler->close(pid, cfe->id);
                cfe->used = false;
            }
        }
        pft->active = pft->pendingdestroy = pft->used = false;
        pft->ch = 0;
    }
    return carryondestruct;
}

int fileman_open(seL4_Word pid, seL4_CPtr reply, userptr_t filename, size_t filename_len, bool dir, int mode)
{
    // error checking
    // bad pid
    if((pid >= MAX_PID) || (!ft[pid].used))
        return EBADF * -1;

    struct filetable* pft = ft + pid;
    ZF_LOGF_IF(!pft->used, "PID unused!");

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

    activate_pft(pft);

    bgworker_enqueue_callback(pid, bg_fileman_open, param);
    return 0;
}

int fileman_close(seL4_Word pid, seL4_CPtr reply, int fh)
{
    // basic error check

    if((pid >= MAX_PID) || (!ft[pid].used))
        return 1;
    
    struct filetable* pft = ft + pid;
    ZF_LOGF_IF(!pft->used, "PID unused!");

    if((fh < 0) || fh >= MAX_FH)
        return 1;

    // run in bg. close operation may block when waiting for lock, for example
    struct bg_close_param * param = malloc(sizeof(struct bg_close_param));
    if(!param)
        return ENOMEM * -1;
    param->pid = pid;
    param->fh = fh;
    param->reply = reply;

    activate_pft(pft);

    bgworker_enqueue_callback(pid, bg_fileman_close, param);
    return 0;
}

int fileman_write(seL4_Word pid, int fh, seL4_CPtr reply, userptr_t buff, uint32_t len)
{
    return fileman_rw_dispatch(false, pid, fh, reply, buff, len);
}

int fileman_read(seL4_Word pid, int fh, seL4_CPtr reply, userptr_t buff, uint32_t len)
{
    return fileman_rw_dispatch(true, pid, fh, reply, buff, len);
}

int fileman_rw_dispatch(bool read, seL4_Word pid, int fh, seL4_CPtr reply, userptr_t buff, uint32_t len)
{
    // bad pid
    if((pid >= MAX_PID) || (!ft[pid].used))
        return EBADF * -1;
    
    struct filetable* pft = ft + pid;
    ZF_LOGF_IF(!pft->used, "PID unused!");

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

    activate_pft(pft);

    bgworker_enqueue_callback(pid, bg_fileman_rw, param);
    return 0;
}

int fileman_stat(seL4_Word pid, seL4_CPtr reply, userptr_t filename, size_t filename_len)
{
    if(pid >= MAX_PID)
        return -EINVAL;

    struct filetable* pft = ft + pid;
    ZF_LOGF_IF(!pft->used, "PID unused!");
    
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

    activate_pft(pft);

    bgworker_enqueue_callback(pid, bg_fileman_stat, param);
    return 0;
}

int fileman_readdir(seL4_Word pid, int fh, seL4_CPtr reply, size_t pos, userptr_t buff, size_t bufflen)
{
    if(pid >= MAX_PID)
        return -EINVAL;

    struct filetable* pft = ft + pid;
    ZF_LOGF_IF(!pft->used, "PID unused!");

    struct bg_readdir_param * param = malloc(sizeof(struct bg_readdir_param));
    if(!param)
        return -ENOMEM;
    
    param->pid = pid;
    param->buff = buff;
    param->bufflen = bufflen;
    param->pos = pos;
    param->fh = fh;
    param->reply = reply;

    activate_pft(pft);

    bgworker_enqueue_callback(pid, bg_fileman_readdir, param);
    return 0;
}

void send_and_free_reply_cap(ssize_t response, seL4_CPtr reply)
{
    send_and_free_reply_cap_ex(response, 0, NULL, reply);
}

void send_and_free_reply_cap_ex(ssize_t response, size_t extrawords, void* extradata, seL4_CPtr reply)
{
    ZF_LOGF_IF(extrawords >= seL4_MsgMaxLength, "Extra reply too large");
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1 + extrawords);
    seL4_SetMR(0, response);
    if(extrawords) 
        memcpy(seL4_GetIPCBuffer()->msg + 1, extradata, extrawords * sizeof(seL4_Word));

    seL4_Send(reply, reply_msg);
    delegate_reuse_reply(reply);
}

void bg_fileman_open(void* data)
{
    struct bg_open_param * param = data;
    struct filetable* pft = ft + param->pid;

    // 0 or more = file handle number
    // negative = negative errno convention
    int ret = 0;

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
        handler->opendir(param->pid, param->filename) :
        handler->open(param->pid, param->filename, param->mode);
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
    pft_activity_finish(param->pid);
    unmap_user_string_bg(param->filename, param->filename_len, param->pid,
        param->filename_term);
    send_and_free_reply_cap(ret, param->reply);
    free(param);
}

void bg_fileman_rw(void* data)
{
    struct bg_rw_param * param = data;
    struct filetable* pft = ft + param->pid;
    struct fileentry* pfe = pft->fe + param->fh;

    // 0 or more = number of bytes writen (yes, can be 0!)
    // negative = negative errno convention
    ssize_t ret = 0;

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
        ret = fileman_read_broker(pfe->handler, pfe->id, param->buff, param->pid, param->len, pfe->offset);
    else
        ret = fileman_write_broker(pfe->handler, pfe->id, param->buff, param->pid, param->len, pfe->offset);

    // increment offset if we got a successful read!
    if(ret > 0) 
        pfe->offset += ret;

finish:
    pft_activity_finish(param->pid);
    send_and_free_reply_cap(ret, param->reply);
    free(param);
}

void bg_fileman_close(void* data)
{
    struct bg_close_param * param = data;
    struct filetable* pft = ft + param->pid;
    struct fileentry* pfe = pft->fe + param->fh;

    if(pfe->used) {
        if(pfe->dir)
            pfe->handler->closedir(param->pid, pfe->id);
        else
            pfe->handler->close(param->pid, pfe->id);
        
        pfe->used = false;
    }
    
    //finish:
    pft_activity_finish(param->pid);
    send_and_free_reply_cap(1, param->reply);
    free(param);
}

void bg_fileman_stat(void* data)
{
    struct bg_stat_param * param = data;
    struct filehandler * handler = find_handler(param->filename);
    union {
        sos_stat_t st;
        seL4_Word matcher[DIV_ROUND_UP_CEXPR(sizeof(sos_stat_t), sizeof(seL4_Word))];
    } target = {0};
    ssize_t err = handler->stat(param->pid, param->filename, &target.st);

finish:
    pft_activity_finish(param->pid);
    unmap_user_string_bg(param->filename, param->filename_len, param->pid,
        param->filename_term);
    if(err)
        send_and_free_reply_cap(err, param->reply);
    else
        send_and_free_reply_cap_ex(1, sizeof(target)/sizeof(seL4_Word), target.matcher,
            param->reply);
    free(param);
}

void bg_fileman_readdir(void* data)
{
    struct bg_readdir_param * param = data;
    struct filetable* pft = ft + param->pid;
    struct fileentry* pfe = pft->fe + param->fh;

    // 0 or more = number of bytes writen (e.g. file name length)
    // negative = negative errno convention
    ssize_t ret = 0;

    if(!pfe->used) {
        ret = EBADF * -1;
        goto finish;
    }
    if(!pfe->dir) {
        ret = -EBADF;
        goto finish;
    }

    const char* dent = pfe->handler->gdent(param->pid, pfe->id, param->pos);

    // NULL file name? "return" 0!
    if(!dent)
        goto finish;

    // if we got a string, get the length first
    // if buffer is not enough, let user takes care about the terminating NULL
    ret = MIN(strlen(dent) + 1, param->bufflen);

    // copy to the pointer given to user
    userptr_write_state_t it = delegate_userptr_write_start(param->buff, ret, param->pid);

    if(!it.curr) {
        ret = -EFAULT;
        goto finish;
    }
    // used for unmapping userptr
    void* startptr = (void*)it.curr;

    while(it.curr) {
        memcpy((void*)it.curr, dent, it.remcurr);
        dent += it.remcurr;
        if(!delegate_userptr_write_next(&it)) {
            ret = -EFAULT;
            break;
        }
    }

    delegate_userptr_unmap(startptr);

finish:
    pft_activity_finish(param->pid);
    send_and_free_reply_cap(ret, param->reply);
    free(param);
}

ssize_t fileman_write_broker(struct filehandler* fh, ssize_t id, userptr_t ptr, seL4_Word badge, size_t len, off_t offset)
{
    void* buff = delegate_userptr_read(ptr, len, badge);
    if(!buff) {
        // try chunked write
        return fileman_chunked_write_broker(fh, id, ptr, badge, len, offset);
    }
    
    ssize_t ret = fh->write(badge, id, buff, offset, len);

    delegate_userptr_unmap(buff);

    return ret;
}

ssize_t fileman_chunked_write_broker(struct filehandler* fh, ssize_t id, userptr_t ptr, seL4_Word badge, size_t len, off_t offset)
{
    ssize_t ret = 0;
    while(len) {
        size_t toread = MIN(READ_PAGE_CHUNK * PAGE_SIZE_4K - (ptr % PAGE_SIZE_4K), len);
        void* buff = delegate_userptr_read(ptr, toread, badge);
        if(!buff) {
            if(!ret)
                ret = -EFAULT;
            break;
        }
        ssize_t written = fh->write(badge, id, buff, offset, toread);

        delegate_userptr_unmap(buff);

        // advance position
        ret += written;
        ptr += written;
        len -= written;
        offset += written;

        // maybe EOF reached?
        if(written < toread)
            break;
    }
    return ret;
}

ssize_t fileman_read_broker(struct filehandler* fh, ssize_t id, userptr_t ptr, seL4_Word badge, size_t len, off_t offset)
{
    if(!len)
        return 0;

    userptr_write_state_t it = delegate_userptr_write_start(ptr, len, badge);
    if(!it.curr)
        return -EFAULT;
    
    ssize_t ret = 0;
    void* startptr = (void*)it.curr;

    while(it.curr) {
        ssize_t rd = fh->read(badge, id, (void*)it.curr, ret + offset, it.remcurr);
        if(rd < 0) {
            ZF_LOGE("Filesystem returned an error");
            ret = -EIO;
            break;
        }
        ret += rd;
        if (rd < it.remcurr)
            // EOF!
            break;
        
        if(!delegate_userptr_write_next(&it)) {
            ZF_LOGE("Error incrementing pointer when handling user read request.");
            ret = -EIO;
            break;
        }
    }

    delegate_userptr_unmap(startptr);
    
    return ret;
}

struct filehandler * find_handler(const char* fn)
{
    for(int i=0; i<SPECIAL_HANDLERS; ++i) {
        if(!specialhandlers[i].name)
            break;
        if(strcmp(fn, specialhandlers[i].name) == 0) 
            return &specialhandlers[i].handler;
    }
    
    return &defaulthandler;
}

void unmap_user_string_bg(char* myptr, size_t len, seL4_Word badge, char originalchar)
{
    // WARNING! this function is meant to be called from background thread
    myptr[len] = originalchar;
    delegate_userptr_unmap(myptr);
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

void activate_pft(struct filetable* pft) 
{
    // all process are single threaded so this is impossible
    ZF_LOGF_IF(pft->active, "Attempt to activate an active IO process.");
    pft->active = true;
}

void pft_activity_finish(seL4_Word pid)
{
    assert_non_main_thread();

    bool pendingdestroy;
    struct filetable* pft = ft + pid;
    seL4_Wait(pft->active_mtx, NULL);
    ZF_LOGF_IF(!pft->active, "IO active flag not locked");
    pft->active = false;
    pendingdestroy = pft->pendingdestroy;
    seL4_Signal(pft->active_mtx);

    if(pendingdestroy) {
        seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, pid);
        // this function is expected to be called from a background thread
        seL4_Call(io_finish_ep, msg);
    }
}