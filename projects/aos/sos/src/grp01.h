# pragma once

// contains definitions for group01's SOS assignment

// max no. of processes supported
#define MAX_PID             128

// if this flag is true, then the IPC message must come from our
// internal threads
#define INT_THRD_BADGE_FLAG (0x1000)

// number of handlers in bgworker
#define BG_HANDLERS         1

typedef uintptr_t userptr_t;
