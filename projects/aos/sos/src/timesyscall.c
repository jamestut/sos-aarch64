#include "timesyscall.h"
#include <clock/clock.h>
#include <errno.h>
#include <cspace/cspace.h>
#include "utils.h"
#include "maininterface.h"
#include "delegate.h"

#define MSEC_TO_USEC(x) (x * 1000)

struct sleeper {
    seL4_CPtr reply;
};

int64_t ts_get_timestamp(){
    timestamp_t timestamp = get_time() % INT64_MAX;
    if(timestamp)
        return timestamp;
    return 1;
}

// will run on main thread, so can use malloc/free directly here
static void sleep_callback(UNUSED uint32_t dummy_id, void * data)
{
    struct sleeper * sleeper = data;
    
    // reply the msgs
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0,0,0,1);
    seL4_SetMR(0, 1);
    seL4_Send(sleeper->reply, reply_msg);

    // dont forget to free our sleeper!
    sos_reuse_reply(sleeper->reply);
    free(sleeper);
}

// return 0 on success and negative number for error
int32_t ts_usleep(ssize_t msec, seL4_CPtr reply)
{   
    if(msec <= 0) 
        // no need for sleeping
        return 1;
    
    uint32_t id;
    struct sleeper * sleeper = malloc(sizeof(struct sleeper));
    
    if (!sleeper) {
       ZF_LOGE("Cannot malloc an entry for sleeper.");
       return ENOMEM * -1;
    }

    // we register a sleeper
    sleeper->reply = reply;

    id = register_timer(MSEC_TO_USEC(msec), sleep_callback, sleeper);
    if(!id) {
        ZF_LOGE("Cannot register a timer for sleeper.");
        free(sleeper);
        return ENOMEM * -1;
    }

    return 0;
}
