#pragma once

#include <sel4/sel4.h>
#include <cspace/cspace.h>
#include <grp01/dynaarray.h>

#include "ut.h"
#include "frame_table.h"
#include "grp01.h"

// contains the definition of the process table structure
// so that we don't have to pass a bazilion of parameters!

typedef struct {
    bool active;

    ut_t *tcb_ut;
    seL4_CPtr tcb;
    ut_t *vspace_ut;
    seL4_CPtr vspace;

    frame_ref_t ipc_buffer_frame;

    frame_ref_t ipc_buffer2_frame;
    
    ut_t *sched_context_ut;
    seL4_CPtr sched_context;

    cspace_t cspace;

    dynarray_t as;
} proctable_t;

extern proctable_t proctable[MAX_PID];
