#pragma once

#include <stdint.h>
#include <clock/clock.h>
#include <sel4/sel4.h>
#include "ut.h"

#define INT64_MAXNUM 0x7FFFFFFFFFFFFFFFULL

#define MSEC_TO_NSEC(x) (x * 1000)

struct sleeper{
    seL4_CPtr reply;
    ut_t* reply_ut;
};

int64_t ts_get_timestamp();

int32_t ts_usleep(int mesc, seL4_CPtr reply, ut_t* reply_ut);