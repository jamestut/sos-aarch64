#include "timesyscall.h"
#include <clock/clock.h>
#include <stdio.h>

int64_t ts_get_timestamp(){
    timestamp_t timestamp = get_time() % INT64_MAX;
    if(timestamp)
        return timestamp;
    return 1;
}
