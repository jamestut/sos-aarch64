#include <utils/zf_log.h>
#include <utils/zf_log_if.h>
#include <sync/bin_sem.h>
#include <sync/condition_var.h>
#include <grp01/dynaarray.h>

#include "threads.h"
#include "utils.h"
#include "vm/mapping2.h"
#include "delegate.h"

#include "bgworker.h"

bool initialized = false;

// lock free: all processes are single threaded.
typedef struct {
    sos_thread_t* workerthread;
    // used to wake up the corresponding thread!
    seL4_CPtr ntfn;
    bgworker_callback_fn fn;
    void* data;
} bgdata_t;

bgdata_t bgdata[MAX_PID];

/* local functions declarations */
void bgworker_loop(void*);

/* function implementations */
void bgworker_init()
{
    if(initialized)
        return;
    initialized = true;

    // empty the data structure before we begin!
    memset(bgdata, 0, sizeof(bgdata));
}

void bgworker_create(seL4_Word pid)
{
    ZF_LOGF_IF(pid >= MAX_PID, "Wrong PID");

    bgdata_t * bd = bgdata + pid;

    if(!bd->ntfn)
        ZF_LOGF_IF(!alloc_retype(&bd->ntfn, seL4_NotificationObject, seL4_NotificationBits),
            "Error creating notification object for background worker");

    // set notification to 0, so that we can wait for child to finish
    seL4_Poll(bd->ntfn, NULL);
    
    ZF_LOGF_IF(bd->workerthread, "Background worker for PID %d already exists", pid);
    bd->workerthread = spawn(bgworker_loop, bd, "bgworker", BACKEND_HANDLER_BADGE, 0, 0);
}

void bgworker_destroy(seL4_Word pid)
{
    ZF_LOGF("Not implemented!");
}

bool bgworker_enqueue_callback(seL4_Word pid, bgworker_callback_fn fn, void* args)
{
    // if we do this, then we have a bug!
    ZF_LOGF_IF(!initialized, "Backend not initialized!");

    bgdata_t* bd = bgdata + pid;
    ZF_LOGF_IF(!fn, "NULL function passed to background worker");

    bd->fn = fn;
    bd->data = args;
    
    seL4_Signal(bd->ntfn);

    return true;
}

void bgworker_loop(void* data)
{
    bgdata_t* bd = data;

    for(;;) {
        // wait until we asked to wake up
        seL4_Wait(bd->ntfn, NULL);
        // if we got an empty function, bail!
        if(!bd->fn)
            break;

        // otherwise, call it!
        // note that at the end of the called function, it is very likely
        // that the function will reply back to user, thus resuming user's execution.
        // by then, user can then call syscall that requires background worker again, 
        // even before we finished. However, it still doesn't matter as we only have one
        // thread to worry about, and the moment we execute this bd->fn, we don't need
        // the value of bd->fn anymore.
        bd->fn(bd->workerthread->user_ep, bd->data);
    }

    // signal the parent that we've finished doing our business.
    // parent may now destroy the thread associated with this worker.
    seL4_Signal(bd->ntfn);
}
