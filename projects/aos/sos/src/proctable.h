#pragma once

#include <sel4/sel4.h>
#include <cspace/cspace.h>
#include <grp01/dynaarray.h>
#include <sos/gen_config.h>

#include "ut.h"
#include "frame_table.h"
#include "grp01.h"
#include "threads.h"
#include "vm/addrspace.h"

enum procstate {
    PROC_STATE_CONSTRUCTING = 0x01,
    PROC_STATE_PENDING_KILL = 0x02
};

// contains the definition of the process table structure
// so that we don't have to pass a bazilion of parameters!
typedef struct {
    uint8_t active;
    uint8_t state_flag;

    ut_t *tcb_ut;
    seL4_CPtr tcb;
    ut_t *vspace_ut;
    seL4_CPtr vspace;

    frame_ref_t ipc_buffer_frame;
    seL4_CPtr ipc_buffer_mapped_cap;

    ut_t *sched_context_ut;
    seL4_CPtr sched_context;

    seL4_CPtr fault_ep;

    cspace_t cspace;

    dynarray_t as;

    // reference to the thread that will handle kernel activity 
    // for this process.
    sos_thread_t* bgthrd;

    // infos that we'll be giving @ process_status
    size_t file_size;
    char command[N_NAME];
    size_t start_msec;

    struct {
        seL4_Word parent_pid;
        char* filename;
        addrspace_t* scratch;
    } loader_state;
} proctable_t;

extern proctable_t proctable[CONFIG_SOS_MAX_PID];

int find_free_pid(void);

void set_pid_state(seL4_Word pid, bool active);
