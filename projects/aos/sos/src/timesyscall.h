#pragma once

#include <stdint.h>
#include <clock/clock.h>
#include <sel4/sel4.h>
#include <sys/types.h>
#include "ut.h"

int64_t ts_get_timestamp();

int32_t ts_usleep(ssize_t msec, seL4_CPtr reply);
