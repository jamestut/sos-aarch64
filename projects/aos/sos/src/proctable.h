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

// bitfield for process waitee
#define WAITEE_BF_WORDS ((CONFIG_SOS_MAX_PID + 63) / 64)
typedef uint64_t waitee_bf_t[WAITEE_BF_WORDS];

// doubly linked list node for -1 waitee
typedef struct {
    sos_pid_t prev;
    sos_pid_t next;
} waitee_any_node_t;

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

    // used for waitpid
    seL4_CPtr waitee_reply;
    sos_pid_t wait_target;
    waitee_bf_t waitee_list;

    struct {
        seL4_Word parent_pid;
        char* filename;
        addrspace_t* scratch;
    } loader_state;
} proctable_t;

extern proctable_t proctable[CONFIG_SOS_MAX_PID];

sos_pid_t find_free_pid(void);

void set_pid_state(sos_pid_t pid, bool active);
