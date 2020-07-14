# pragma once

#include <stddef.h>
#include <stdint.h>

// contains definitions for group01's SOS assignment

// max no. of processes supported
#define MAX_PID             128

// max frame number bits. this directly dictates the supported
// amount of memory + pagefile. Can be set to 21 (2^21*4096 = 8 GB)
// before it fires static asserts, especially on shadow page tables.
#define FRAME_TABLE_BITS 21

// badge for main thread delegation
#define BADGE_DELEGATE  (0x10000)
// badge for returning reply object
#define BADGE_REPLY_RET (0x10001)

typedef uintptr_t userptr_t;
