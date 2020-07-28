# pragma once

#include <stddef.h>
#include <stdint.h>

// contains definitions for group01's SOS assignment

// max no. of processes supported
// TODO: GRP01: move to CMake
#define MAX_PID             128

// max char in filename, including NULL terminator
#define MAX_FILENAME       4096

// max frame number bits. this directly dictates the supported
// amount of memory + pagefile. Can be set to 21 (2^21*4096 = 8 GB)
// before it fires static asserts, especially on shadow page tables.
#define FRAME_TABLE_BITS 21

// badge for main thread delegation
#define BADGE_DELEGATE  (0x10000)
// badge for returning reply object
#define BADGE_REPLY_RET (0x10001)
// badge that some background worker will send upon IO completion and a kill is pending
#define BADGE_IO_FINISH (0x10002)

typedef uintptr_t userptr_t;
