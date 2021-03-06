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
#include "threads.h"

#include <grp01/bitfield.h>
#include <stdlib.h>
#include <utils/util.h>
#include <sel4runtime.h>
#include <aos/debug.h>
#include <cspace/cspace.h>
#include <sos/gen_config.h>
#include <setjmp.h>

#include "ut.h"
#include "vmem_layout.h"
#include "utils.h"
#include "threadassert.h"
#include "vm/mapping2.h"

#define SOS_THREAD_PRIORITY     (0)

#define SOS_THRD_IDX(thrd_ref) ((thrd_ref) - threads)

#define SOS_THRD_IPC_BUFF_VADDR(thrd_ref) (SOS_IPC_BUFFER + PAGE_SIZE_4K * SOS_THRD_IDX(thrd_ref))

// add one guard page
#define SOS_THRD_STACK_BOTTOM(thrd_ref) ((SOS_STACK + SOS_STACK_PAGES * PAGE_SIZE_4K) + \
    SOS_THRD_IDX(thrd_ref) * PAGE_SIZE_4K * (CONFIG_SOS_INT_THREADS_STACK_PAGES + 1))

#define SOS_THRD_STACK_TOP(thrd_ref) (SOS_THRD_STACK_BOTTOM((thrd_ref) + 1))

sos_thread_t threads[SOS_MAX_THREAD] = {0};
#define SOS_THREADS_BF_WORDS ((SOS_MAX_THREAD + 63) / 64)
static uint64_t threads_usage[SOS_THREADS_BF_WORDS] = {0};

__thread sos_thread_t *current_thread = NULL;

static seL4_CPtr sched_ctrl_start;
static seL4_CPtr sched_ctrl_end;

static seL4_CPtr ipc_ep;

static void set_thread_active(int index, bool active);

void init_threads(seL4_CPtr ep, seL4_CPtr sched_ctrl_start_, seL4_CPtr sched_ctrl_end_)
{
    ipc_ep = ep;
    sched_ctrl_start = sched_ctrl_start_;
    sched_ctrl_end = sched_ctrl_end_;

    set_thread_active(0, true);
}

static bool alloc_stack(sos_thread_t* thread, bool is_system, seL4_Word system_stack_pages, uintptr_t* sp, uintptr_t* stack_base)
{
    static uintptr_t curr_stack = SOS_STACK + SOS_STACK_PAGES * PAGE_SIZE_4K;

    uint32_t stack_pages = is_system ? system_stack_pages : CONFIG_SOS_INT_THREADS_STACK_PAGES;

    // add a guard page
    *stack_base = curr_stack += PAGE_SIZE_4K;
    // sp is the top of the stack
    *sp = (curr_stack += stack_pages * PAGE_SIZE_4K);

    for (int i = 0; i < stack_pages; i++) {
        // only bookkeep ut if the thread is not system (ephemeral)
        ut_t* system_frame_ut;
        seL4_CPtr system_frame_cap;

        ut_t** frame_ut_ptr;
        seL4_CPtr* frame_cap_ptr;

        if(!is_system) {
            frame_ut_ptr = thread->stack_frame_uts + i;
            frame_cap_ptr = thread->stack_frame_caps + i;

            // already have a frame allocated here.
            if(*frame_ut_ptr)
                continue;
        } else {
            frame_ut_ptr = &system_frame_ut;
            frame_cap_ptr = &system_frame_cap;
        }

        *frame_ut_ptr = alloc_retype(frame_cap_ptr, seL4_ARM_SmallPageObject, seL4_PageBits);
        if (*frame_ut_ptr == NULL) {
            ZF_LOGE("Failed to allocate stack page");
            return false;
        }

        seL4_Error err = map_frame(&cspace, *frame_cap_ptr, seL4_CapInitThreadVSpace,
                                *sp - (i + 1) * PAGE_SIZE_4K, seL4_AllRights, seL4_ARM_Default_VMAttributes);
        if (err != seL4_NoError) {
            ZF_LOGE("Failed to map stack");
            cap_ut_dealloc(frame_cap_ptr, frame_ut_ptr);
            return false;
        }
    }
    return true;
}

int thread_suspend(sos_thread_t *thread)
{
    return seL4_TCB_Suspend(thread->tcb);
}

int thread_resume(sos_thread_t *thread)
{
    return seL4_TCB_Resume(thread->tcb);
}

/* trampoline code for newly started thread */
static void thread_trampoline(sos_thread_t *thread, thread_main_f *function, void *arg)
{
    sel4runtime_set_tls_base(thread->tls_base);
    void* ipcbuff_vaddr = SOS_THRD_IPC_BUFF_VADDR(thread);
    seL4_SetIPCBuffer((seL4_IPCBuffer *) ipcbuff_vaddr);
    current_thread = thread;
    function(arg);
    thread_suspend(thread);
}

void thread_wrap(void)
{
    longjmp(current_thread->jump_on_fault.ret, 1);
}

/*
 * Spawn a new kernel (SOS) thread to execute function with arg
 */
sos_thread_t *thread_create(thread_main_f function, void *arg, const char* name, bool resume, seL4_CPtr ep, seL4_Word prio, bool is_system, seL4_Word system_stack_pages)
{
    assert_main_thread();
    seL4_Word err;

    // find empty TCB slot
    sos_thread_t* new_thread = NULL;
    int thread_idx = bitfield_first_free(SOS_THREADS_BF_WORDS, threads_usage);
    // make sure that we never ever use the "sentinel" thread
    assert(thread_idx > 0);
    if(thread_idx < SOS_MAX_THREAD)
        new_thread = threads + thread_idx;
    
    if (new_thread == NULL) {
        ZF_LOGE("Cannot allocate new thread");
        return NULL;
    }

    seL4_Word badge = BADGE_INT_THRD + thread_idx;

    // instead of a counter that increase monotically, we propose something like this!
    seL4_Word curr_ipc_buf = SOS_THRD_IPC_BUFF_VADDR(new_thread);

    set_thread_active(thread_idx, true);
    new_thread->badge = badge;

    /* Create an IPC buffer */
    if(!new_thread->ipc_buffer_ut) {
        new_thread->ipc_buffer_ut = alloc_retype(&new_thread->ipc_buffer_cap,
                                                seL4_ARM_SmallPageObject, seL4_PageBits);
        if (new_thread->ipc_buffer_ut == NULL) {
            ZF_LOGE("Failed to alloc ipc buffer ut");
            goto on_error;
        }

        /* Map in the IPC buffer for the thread */
        err = map_frame(&cspace, new_thread->ipc_buffer_cap, seL4_CapInitThreadVSpace, curr_ipc_buf,
            seL4_AllRights, seL4_ARM_Default_VMAttributes);
        if (err != 0) {
            ZF_LOGE("Unable to map IPC buffer for user app");
            cap_ut_dealloc(&new_thread->ipc_buffer_cap, &new_thread->ipc_buffer_ut);
            goto on_error;
        }
    }

    /* Set up TLS for the new thread */
    new_thread->tls_memory = malloc(sel4runtime_get_tls_size());
    if (new_thread->tls_memory == NULL) {
        ZF_LOGE("Failed to alloc memory for tls");
        goto on_error;
    }
    new_thread->tls_base = sel4runtime_write_tls_image(new_thread->tls_memory);
    if (new_thread->tls_base == (uintptr_t) NULL) {
        ZF_LOGE("Failed to write tls image");
        goto on_error;
    }

    /* allocate a new slot in the target cspace which we will mint a badged endpoint cap into --
     * the badge is used to identify the process, which will come in handy when you have multiple
     * processes. */
    // system threads won't have a fault ep: if they fault, SOS will crash
    if(!is_system) {
        new_thread->fault_ep = cspace_alloc_slot(&cspace);
        if (new_thread->fault_ep == seL4_CapNull) {
            ZF_LOGE("Failed to alloc user ep slot");
            goto on_error;
        }

        /* now mutate the cap, thereby setting the badge */
        err = cspace_mint(&cspace, new_thread->fault_ep, &cspace, ep, seL4_AllRights,
                                    badge);
        if (err) {
            cspace_free_slot(&cspace, new_thread->fault_ep);
            new_thread->fault_ep = 0;
            ZF_LOGE("Failed to mint user ep");
            goto on_error;
        }
    } else
        new_thread->fault_ep = 0;

    /* Create a new TCB object */
    new_thread->tcb_ut = alloc_retype(&new_thread->tcb, seL4_TCBObject, seL4_TCBBits);
    if (new_thread->tcb_ut == NULL) {
        ZF_LOGE("Failed to alloc tcb ut");
        goto on_error;
    }

    /* Configure the TCB */
    err = seL4_TCB_Configure(new_thread->tcb,
                             cspace.root_cnode, seL4_NilData,
                             seL4_CapInitThreadVSpace, seL4_NilData, curr_ipc_buf,
                             new_thread->ipc_buffer_cap);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure new TCB");
        goto on_error;
    }

    /* Create scheduling context */
    new_thread->sched_context_ut = alloc_retype(&new_thread->sched_context,
                                                seL4_SchedContextObject,
                                                seL4_MinSchedContextBits);
    if (new_thread->sched_context_ut == NULL) {
        ZF_LOGE("Failed to alloc sched context ut");
        goto on_error;
    }

    /* Configure the scheduling context to use the second core with budget equal to period */
    seL4_CPtr sched_ctrl;
    if (sched_ctrl_start + 1 < sched_ctrl_end) {
        sched_ctrl = sched_ctrl_start + 1;
    } else {
        sched_ctrl = sched_ctrl_start;
    }
    err = seL4_SchedControl_Configure(sched_ctrl, new_thread->sched_context,
                                      US_IN_MS, US_IN_MS, 0, 0);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure scheduling context");
        goto on_error;
    }

    /* bind sched context, set fault endpoint and priority
     * In MCS, fault end point needed here should be in current thread's cspace.
     * NOTE this will use the unbadged ep unlike above, you might want to mint it with a badge
     * so you can identify which thread faulted in your fault handler */
    err = seL4_TCB_SetSchedParams(new_thread->tcb, seL4_CapInitThreadTCB, prio,
                                  prio, new_thread->sched_context,
                                  new_thread->fault_ep);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to set scheduling params");
        goto on_error;
    }

    /* Provide a name for the thread -- Helpful for debugging */
    NAME_THREAD(new_thread->tcb, name);

    /* set up the stack */
    // sp is top of the stack
    if(!new_thread->sp) {
        if (!alloc_stack(new_thread, is_system, system_stack_pages, &new_thread->sp, &new_thread->stack_base)) {
            new_thread->sp = 0;
            goto on_error;
        }
    }

    /* set initial context */
    seL4_UserContext context = {
        .pc = (seL4_Word) thread_trampoline,
        .sp = new_thread->sp,
        .x0 = (seL4_Word) new_thread,
        .x1 = (seL4_Word) function,
        .x2 = (seL4_Word) arg,
    };
    ZF_LOGD(resume ? "Starting new sos thread at %p\n"
            : "Created new thread starting at %p\n", (void *) context.pc);
    fflush(NULL);
    err = seL4_TCB_WriteRegisters(new_thread->tcb, resume, 0, 6, &context);
    if (err != seL4_NoError) {
        ZF_LOGE("Failed to write registers");
        goto on_error;
    }
    return new_thread;

on_error:
    thread_destroy(new_thread);
    return NULL;
}

void thread_destroy(sos_thread_t* thread)
{
    // we won't free stack and IPC buffers here: we'll reuse them.
    assert_main_thread();

    int thread_idx = SOS_THRD_IDX(thread);

    if(!thread || !GET_BMP(threads_usage, thread_idx))
        return;

    set_thread_active(thread_idx, false);
    
    thread->jump_on_fault.enabled = false;

    if(thread->tcb)
        cap_ut_dealloc(&thread->tcb, &thread->tcb_ut);
    
    if(thread->fault_ep) {
        cspace_delete(&cspace, thread->fault_ep);
        cspace_free_slot(&cspace, thread->fault_ep);
        thread->fault_ep = 0;
    }

    if(thread->sched_context) 
        cap_ut_dealloc(&thread->sched_context, &thread->sched_context_ut);

    if(thread->tls_memory) {
        free(thread->tls_memory);
        thread->tls_memory = NULL;
    }
}

sos_thread_t *spawn(thread_main_f function, void *arg, const char* name, seL4_Word prio)
{
    return thread_create(function, arg, name, true, ipc_ep, prio, false, 0);
}

sos_thread_t *spawn_system(thread_main_f function, void *arg, const char* name, seL4_CPtr ep, seL4_Word prio, seL4_Word stack_pages)
{
    return thread_create(function, arg, name, true, ep ? ep : ipc_ep, prio, true, stack_pages);
}

static void set_thread_active(int index, bool active)
{
    assert(GET_BMP(threads_usage, index) != active);
    TOGGLE_BMP(threads_usage, index);
}
