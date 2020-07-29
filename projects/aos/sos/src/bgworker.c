#include <utils/zf_log.h>
#include <utils/zf_log_if.h>
#include <sync/bin_sem.h>
#include <sync/condition_var.h>
#include <grp01/dynaarray.h>
#include <sos/gen_config.h>

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
    ut_t* ntfn_ut;

    // the queued data
    bgworker_callback_fn fn;
    void* data;
} bgdata_t;

bgdata_t bgdata[CONFIG_SOS_MAX_PID];

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

bool bgworker_create(sos_pid_t pid)
{
    ZF_LOGF_IF(pid >= CONFIG_SOS_MAX_PID, "Wrong PID");

    bgdata_t * bd = bgdata + pid;
    
    if(bd->workerthread)
        // if we already have a thread handle, it means that things was constructed
        // successfully
        return true;

    if(!bd->ntfn) {
        bd->ntfn_ut = alloc_retype(&bd->ntfn, seL4_NotificationObject, seL4_NotificationBits);
        if(!bd->ntfn_ut) {
            ZF_LOGE("Error creating notification for background worker PID %d", pid);
            goto on_error;
        }
    }

    // set notification to 0, so that we can wait for child to finish
    seL4_Poll(bd->ntfn, NULL);
    
    bd->workerthread = spawn(bgworker_loop, bd, "bgworker", 0, 0, 0);
    if(!bd->workerthread) {
        ZF_LOGE("Error creating background thread for PID %d", pid);
        goto on_error;
    }
    return true;

on_error:
    bgworker_destroy(pid);
    return false;
}

void bgworker_destroy(sos_pid_t pid)
{
    bgdata_t * bd = bgdata + pid;

    if(bd->workerthread) {
        thread_destroy(bd->workerthread);
        bd->workerthread = NULL;
    }

    if(bd->ntfn) {
        cap_ut_dealloc(&bd->ntfn, &bd->ntfn_ut);
        bd->ntfn = 0;
        bd->ntfn_ut = NULL;
    }
}

bool bgworker_enqueue_callback(sos_pid_t pid, bgworker_callback_fn fn, void* args)
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
        bd->fn(bd->data);
    }

    // signal the parent that we've finished doing our business.
    // parent may now destroy the thread associated with this worker.
    seL4_Signal(bd->ntfn);
}
