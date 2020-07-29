/*
 * Copyright 2019, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(DATA61_GPL)
 */
#pragma once

#include <sel4runtime.h>
#include <threads.h>
#include <cspace/cspace.h>
#include <sos/gen_config.h>
#include "ut.h"
#include "frame_table.h"

extern cspace_t cspace;

typedef struct {
    bool active;

    ut_t *tcb_ut;
    seL4_CPtr tcb;

    ut_t* ipc_buffer_ut;
    seL4_CPtr ipc_buffer_cap;

    ut_t* stack_frame_uts[CONFIG_SOS_INT_THREADS_STACK_PAGES];
    seL4_CPtr stack_frame_caps[CONFIG_SOS_INT_THREADS_STACK_PAGES];

    seL4_CPtr fault_ep;

    ut_t *sched_context_ut;
    seL4_CPtr sched_context;

    seL4_Word badge;

    void* tls_memory;
    uintptr_t tls_base;
} sos_thread_t;

typedef void thread_main_f(void *);

extern __thread sos_thread_t *current_thread;

void init_threads(seL4_CPtr ep, seL4_CPtr sched_ctrl_start_, seL4_CPtr sched_ctrl_end_);
sos_thread_t *thread_create(thread_main_f function, void *arg, const char* name, seL4_Word badge, bool resume, seL4_CPtr ep, seL4_Word prio);
int thread_suspend(sos_thread_t *thread);
int thread_resume(sos_thread_t *thread);
void thread_destroy(sos_thread_t* thread);

// badge will be used for badging fault endpoint
sos_thread_t *spawn(thread_main_f function, void *arg, const char* name, seL4_Word badge, seL4_CPtr ep, seL4_Word prio);
