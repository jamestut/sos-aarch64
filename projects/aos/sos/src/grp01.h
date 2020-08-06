# pragma once

#include <stddef.h>
#include <stdint.h>
#include <sos/gen_config.h>

// contains definitions for group01's SOS assignment

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
// badge for musl memory allocator delegate operations
#define BADGE_MALLOC    (0x10003)

// badge flag for SOS internal threads
#define BADGE_INT_THRD  (0x20000)

#define SOS_MAX_THREAD (CONFIG_SOS_MAX_PID + CONFIG_SOS_EXTRA_THREADS)

typedef uintptr_t userptr_t;

typedef int16_t sos_pid_t;
#define PID_NS_MAX 0x7FFF
#define INVALID_PID (-1)
_Static_assert(CONFIG_SOS_MAX_PID <= PID_NS_MAX, "Configured PID too large");
