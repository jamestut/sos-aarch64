#include "timesyscall.h"
#include <clock/clock.h>
#include <stdio.h>
#define INT64_MAX 0x7FFFFFFFFFFFFFFFULL




int64_t ts_get_timestamp(){
    timestamp_t timestamp = get_time();
    // printf("I'm in the time syscall time: %ull\n", timestamp);
    return timestamp % INT64_MAX;
}