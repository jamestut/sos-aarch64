#include "timesyscall.h"
#include <clock/clock.h>
#include <errno.h>
#include <cspace/cspace.h>
#include "utils.h"

#define MSEC_TO_USEC(x) (x * 1000)

struct sleeper {
    seL4_CPtr reply;
    ut_t* reply_ut;
};

int64_t ts_get_timestamp(){
    timestamp_t timestamp = get_time() % INT64_MAX;
    if(timestamp)
        return timestamp;
    return 1;
}

static void sleep_callback(UNUSED uint32_t dummy_id, void * data)
{
    struct sleeper * sleeper = data;
    // reply the msgs
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0,0,0,1);
    
    seL4_SetMR(0, 1);
    // clean up the reply obj
    seL4_Send(sleeper->reply, reply_msg);

    // delete the reply cap and free the ut obj
    cspace_delete(&cspace, sleeper->reply);
    cspace_free_slot(&cspace,sleeper->reply);
    ut_free(sleeper->reply_ut);
    // dont forget to free our sleeper!
    free(sleeper);
}

// return 0 on success and negative number for error
int32_t ts_usleep(ssize_t msec, seL4_CPtr reply, ut_t* reply_ut)
{   
    if(msec < 0) 
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
    sleeper->reply_ut = reply_ut;

    id = register_timer(MSEC_TO_USEC(msec), sleep_callback, sleeper);
    if(!id) {
        ZF_LOGE("Cannot register a timer for sleeper.");
        free(sleeper);
        // TODO put a error no here to show failure on registing timer
        return ENOMEM * -1;
    }

    return 0;
}
