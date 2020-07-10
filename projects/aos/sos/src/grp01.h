# pragma once

#include <stddef.h>
#include <stdint.h>

// contains definitions for group01's SOS assignment

// max no. of processes supported
#define MAX_PID             128

// badge for main thread delegation
#define BADGE_DELEGATE  (0x10000)
// badge for returning reply object
#define BADGE_REPLY_RET (0x10001)

typedef uintptr_t userptr_t;
