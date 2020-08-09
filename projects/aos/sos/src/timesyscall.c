#include "timesyscall.h"
#include <clock/clock.h>
#include <errno.h>
#include <cspace/cspace.h>
#include <sos/gen_config.h>
#include "utils.h"
#include "maininterface.h"
#include "delegate.h"

#define MSEC_TO_USEC(x) (x * 1000)

static struct {
    uint32_t timer_id;
    seL4_Word reply_obj;
} sleepers[CONFIG_SOS_MAX_PID] = {0};

struct sleeper {
    seL4_CPtr reply;
};

int64_t ts_get_timestamp()
{
    timestamp_t timestamp = get_time() % INT64_MAX;
    if(timestamp)
        return timestamp;
    return 1;
}

void free_sleeper(seL4_Word badge)
{
    sleepers[badge].reply_obj = sleepers[badge].timer_id = 0;
}

void ts_cancel_sleep(seL4_Word badge)
{
    // this function is expected to run on main thread
    // assume that the process has already been killed, which means
    // that we can safely reuse the reply as it is no longer bound
    // to a particular TCB.
    seL4_Word reply = sleepers[badge].reply_obj;
    if(reply)
        sos_reuse_reply(reply);
    free_sleeper(badge);
}

// will run on main thread, so can use malloc/free directly here
static void sleep_callback(UNUSED uint32_t dummy_id, void * data)
{
    seL4_Word badge = (seL4_Word)data;
    
    // reply the msgs
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, 1);
    seL4_Send(sleepers[badge].reply_obj, reply_msg);

    // dont forget to free our sleeper!
    sos_reuse_reply(sleepers[badge].reply_obj);
    free_sleeper(badge);
}

// return 0 on success and negative number for error
int32_t ts_usleep(seL4_Word badge, ssize_t msec, seL4_CPtr reply)
{   
    if(msec <= 0) 
        // no need for sleeping
        return 1;

    // since we're single threaded, it should not be possible for a process
    // to have more than one sleepers
    assert(!sleepers[badge].timer_id);
    sleepers[badge].reply_obj = reply;
    sleepers[badge].timer_id = register_timer(MSEC_TO_USEC(msec), sleep_callback, (void*)badge);
    if(!sleepers[badge].timer_id) {
        ZF_LOGE("Cannot register a timer for sleeper.");
        free_sleeper(badge);
        return ENOMEM * -1;
    }

    return 0;
}
