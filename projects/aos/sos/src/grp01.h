# pragma once

#include <stddef.h>
#include <stdint.h>

// contains definitions for group01's SOS assignment

// max no. of processes supported
#define MAX_PID             128

// if this flag is true, then the IPC message must come from our
// internal threads
#define INT_THRD_BADGE_FLAG (0x1000)

// badges for internal threads
#define BACKEND_HANDLER_BADGE   (INT_THRD_BADGE_FLAG + 1)
#define LIBNFS_EVTLOOP_BADGE    (INT_THRD_BADGE_FLAG + 2)

// number of handlers in bgworker
#define BG_HANDLERS         1

typedef uintptr_t userptr_t;
