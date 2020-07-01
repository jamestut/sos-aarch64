#include <utils/zf_log.h>
#include <utils/zf_log_if.h>
#include <sync/bin_sem.h>
#include <sync/condition_var.h>
#include <grp01/dynaarray.h>

#include "threads.h"
#include "utils.h"
#include "vm/mapping2.h"

#include "bgworker.h"

#define MAX_QUEUE 16

struct be_item {
    bgworker_callback_fn fn;
    void* data;
};

/* local variables */

bool initialized = false;

// circular queue
struct {
    // empty = prod == cons
    // full  = prod == cons - 1
    uint16_t prod_pos;
    uint16_t cons_pos;
    struct be_item data[MAX_QUEUE];
    sync_bin_sem_t lock;
    sync_cv_t cv;
} cqueue;

/* local functions declarations */
void bgworker_loop(void*);

inline uint16_t inc_pos(uint16_t v);

/* function implementations */
void bgworker_init()
{
    if(initialized)
        return;
    initialized = true;

    // empty the data structure before we begin!
    memset(&cqueue, 0, sizeof(cqueue));

    // init the notifications for the sync objects
    // we'd like to keep the resulting ntfn for the SOS' lifetime,
    // so we'll discard the ref to the resulting the ut_t and also the ntfn itself.
    seL4_CPtr ntfn_lck, ntfn_cv;
    if(!alloc_retype(&ntfn_lck, seL4_NotificationObject, seL4_NotificationBits)) {
        ZF_LOGF("Cannot create notification object for lock.");
    }
    if(!alloc_retype(&ntfn_cv, seL4_NotificationObject, seL4_NotificationBits)) {
        ZF_LOGF("Cannot create notification object for CV.");
    }
    // creating these objects will never fail if the ntfn caps are correct!
    sync_bin_sem_init(&cqueue.lock, ntfn_lck, 1);
    sync_cv_init(&cqueue.cv, ntfn_cv);

    for(int i=0; i<BG_HANDLERS; ++i) {
        if(!spawn(bgworker_loop, NULL, "bgworker_thread", BACKEND_HANDLER_BADGE)) {
            ZF_LOGF("Cannot create backend handler thread (thread %d of %d).", 
                i+1, BG_HANDLERS);
        }
    }
}

bool bgworker_enqueue_callback(bgworker_callback_fn fn, void* args)
{
    // if we do this, then we have a bug!
    ZF_LOGF_IF(!initialized, "Backend not initialized!");

    bool ret;

    sync_bin_sem_wait(&cqueue.lock);
    // we're the producer!
    // only enqueue if we're not full, obviously
    if(inc_pos(cqueue.prod_pos) != cqueue.cons_pos) {
        ret = true;
        // enqueue
        cqueue.data[cqueue.prod_pos].fn = fn;
        cqueue.data[cqueue.prod_pos].data = args;
        cqueue.prod_pos = inc_pos(cqueue.prod_pos);
        // wake up waiter if needed
        sync_cv_signal(&cqueue.cv);
    } else {
        ret = false;
    }
    sync_bin_sem_post(&cqueue.lock);

    return ret;
}

void bgworker_loop(UNUSED void* unused)
{
    // no shutdown condition here. we wait 4ever!
    while(1) {
        sync_bin_sem_wait(&cqueue.lock);
        // check if empty
        while(cqueue.prod_pos == cqueue.cons_pos) {
            sync_cv_wait(&cqueue.lock, &cqueue.cv);
        }
        // we have work to do!
        // dequeue first
        struct be_item data = cqueue.data[cqueue.cons_pos];
        cqueue.cons_pos = inc_pos(cqueue.cons_pos);
        
        // unlock and we shall do the time consuming operation!
        sync_bin_sem_post(&cqueue.lock);
        data.fn(data.data);
    }
}

uint16_t inc_pos(uint16_t v)
{
    return (v + 1) % MAX_QUEUE;
}
