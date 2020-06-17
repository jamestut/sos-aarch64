#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <utils/zf_log.h>
#include <utils/zf_log_if.h>
#include <sync/mutex.h>
#include <cspace/cspace.h>

#include "utils.h"
#include "fs/console.h"
#include "bgworker.h"

#include "fileman.h"

#define MAX_PID 128
#define MAX_FH  128
#define SPECIAL_HANDLERS 1

// struct declaration area

struct filehandler
{
    file_open_fn open;
    file_rw_fn read;
    file_rw_fn write;
    file_close_fn close;
};

struct fileentry
{
    bool used;
    struct filehandler * handler;
    int id; // id internal to the file system
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

// structs specific for arguments to bgworker
struct bg_open_param {
    const char* filename;
    seL4_Word pid;
    seL4_CPtr reply;
    int mode;
};

// local variables declaration area

struct filetable ft[MAX_PID];

// local functions declaration area

void bg_fileman_open(void* data);

// function definitions area

bool fileman_init()
{
    memset(ft, 0, sizeof(ft));

    // install special handlers (console)
    specialhandlers[0].name = "console";
    specialhandlers[0].handler.open = console_fs_open;
    specialhandlers[0].handler.close = console_fs_close;
    specialhandlers[0].handler.read = console_fs_read;
    specialhandlers[0].handler.write = console_fs_write;

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

    // by default, stdin/out/err is used
    for(int i=0; i<=2; ++i)
        ft[pid].fe[i].used = true;
    
    // set the flag to indicate that someone is using this PID
    ft[pid].used = true;

    return 0;
}

int fileman_open(seL4_Word pid, seL4_CPtr reply, const char* filename, int mode)
{
    // error checking
    // bad pid
    if((pid >= MAX_PID) || (!ft[pid].used))
        return EBADF;

    // prepare for run the open in background
    struct bg_open_param * param = malloc(sizeof(struct bg_open_param));
    if(!param)
        return ENOMEM;
    param->filename = filename; // WARNING! won't work on multithreaded processes!
    param->mode = mode;
    param->pid = pid;
    param->reply = reply;

    bgworker_enqueue_callback(bg_fileman_open, param);
    return 0;
}

void bg_fileman_open(void* data)
{
    struct bg_open_param * param = data;
    struct filetable* pft = ft + param->pid;

    sync_mutex_lock(&pft->felock);

    // 0 or more = file handle number
    // negative = negative errno convention
    int ret = 0;

    // find unused slot in the process' file table
    int slot = -1;
    for(int i=0; i<MAX_FH; ++i) {
        if(!pft->fe[i].used) 
            slot = i;
        // increment clockhand
        pft->ch = (pft->ch + 1) % MAX_FH;
        
        if(slot >= 0)
            break;
    }
    
    // process file table is full!
    if(slot < 0) {
        ret = EMFILE * -1;
        goto finish;
    }

    // get the handler (console only for the moment)
    struct filehandler * handler = NULL;
    for(int i=0; i<SPECIAL_HANDLERS; ++i) {
        if(strcmp(param->filename, specialhandlers[i].name) == 0) {
            handler = &specialhandlers[i].handler;
            break;
        }
    }
    // we don't have the default handler for now!
    if(!handler) {
        ZF_LOGD("Unsupported file system");
        ret = ENODEV * -1;
        goto finish;
    }

    // try open
    int id = handler->open(param->filename, param->mode);
    if(id < 0) {
        // failure. we expect the opener to return our negative errno model.
        ret = id;
        goto finish;
    }
    
    // OK. assign to process' file table entry
    struct fileentry * pfe = pft->fe + slot;
    pfe->used = true;
    pfe->id = id;
    pfe->handler = handler;

    // and return the slot number
    ret = slot;

finish:
    sync_mutex_unlock(&pft->felock);
    // send to client directly
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, ret);
    seL4_Send(param->reply, reply_msg);
    cspace_free_slot(&cspace, param->reply);
    free(param);
}