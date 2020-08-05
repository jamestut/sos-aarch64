#include "procman.h"
#include "threadassert.h"
#include "procsyscall.h"
#include "proctable.h"
#include "utils.h"
#include "grp01.h"
#include "maininterface.h"
#include "vmem_layout.h"
#include "vm/addrspace.h"
#include "vm/mapping2.h"
#include "elfload.h"
#include "delegate.h"
#include <clock/clock.h>
#include <stdbool.h>
#include <aos/debug.h>
#include <elf/elf.h>
#include <utils/zf_log_if.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sel4runtime/auxv.h>
#include <grp01/bitfield.h>

#define USER_PRIORITY               (0)

static seL4_CPtr ep;
static seL4_CPtr sched_ctrl_start;
static seL4_CPtr sched_ctrl_end;

// processes that wait upon -1
// worst case is when all processes are waiting for -1.
// entry 0 is both head and sentinel.
// - next = first waitee (0 if none)
// - prev = last waitee (0 if none)
waitee_any_node_t waitee_any[CONFIG_SOS_MAX_PID] = {0};

extern dynarray_t scratchas;

bool setup_scratch_space(sos_pid_t pid, size_t filesize);

void notify_waitee(sos_pid_t waitee, sos_pid_t target);

void init_process_starter(seL4_CPtr ep_, seL4_CPtr sched_ctrl_start_, seL4_CPtr sched_ctrl_end_)
{
    ep = ep_;
    sched_ctrl_start = sched_ctrl_start_;
    sched_ctrl_end = sched_ctrl_end_;
}

sos_pid_t create_process(sos_pid_t parent_pid, char *app_name)
{
    invalidate_proc_list_cache();

    assert_main_thread();
    // find process table to use
    sos_pid_t ptidx = find_free_pid();
    if(ptidx < 0)
        return -1;

    proctable_t* pt = proctable + ptidx;
    set_pid_state(ptidx, true);
    pt->state_flag = PROC_STATE_CONSTRUCTING;

    dynarray_init(&pt->as, sizeof(addrspace_t));
    // in case we need to map something
    addrspace_t newas;
    
    /* Create a VSpace */
    pt->vspace_ut = alloc_retype(&pt->vspace, seL4_ARM_PageGlobalDirectoryObject,
                                              seL4_PGDBits);
    if (pt->vspace_ut == NULL) {
        goto on_error;
    }

    // create mapping bookkeeping object for vspace
    grp01_map_init(ptidx, pt->vspace);

    /* assign the vspace to an asid pool */
    seL4_Error err = seL4_ARM_ASIDPool_Assign(seL4_CapInitThreadASIDPool, pt->vspace);
    if (err != seL4_NoError) {
        ZF_LOGE("Failed to assign asid pool");
        goto on_error;
    }

    /* Create a simple 1 level CSpace */
    int cerr = cspace_create_one_level(&cspace, &pt->cspace);
    if (cerr != CSPACE_NOERROR) {
        ZF_LOGE("Failed to create cspace");
        goto on_error;
    }

    /* Create an IPC buffer */
    pt->ipc_buffer_frame = alloc_frame();
    if (pt->ipc_buffer_frame == 0) {
        ZF_LOGE("Failed to alloc ipc buffer frame");
        goto on_error;
    }
    // avoid the TCB buffer to get paged out!
    frame_set_pin(pt->ipc_buffer_frame, true);
    
    /* allocate a new slot in the target cspace which we will mint a badged endpoint cap into --
     * the badge is used to identify the process, which will come in handy when you have multiple
     * processes. */
    // no need for bookeepping because cspace_destroy will erase this
    seL4_CPtr user_ep = cspace_alloc_slot(&pt->cspace);
    if (user_ep == seL4_CapNull) {
        ZF_LOGE("Failed to alloc user ep slot");
        goto on_error;
    }

    /* now mutate the cap, thereby setting the badge */
    err = cspace_mint(&pt->cspace, user_ep, &cspace, ep, seL4_AllRights, ptidx);
    if (err) {
        ZF_LOGE("Failed to mint user ep");
        goto on_error;
    }

    /* Create a new TCB object */
    pt->tcb_ut = alloc_retype(&pt->tcb, seL4_TCBObject, seL4_TCBBits);
    if (pt->tcb_ut == NULL) {
        ZF_LOGE("Failed to alloc tcb ut");
        goto on_error;
    }

    /* Configure the TCB */
    pt->ipc_buffer_mapped_cap = cspace_alloc_slot(&cspace);
    if(pt->ipc_buffer_mapped_cap == 0) {
        ZF_LOGE("Failed to allocate slot for IPC buffer");
        goto on_error;
    }

    // copy buffer page and map it to child app
    err = cspace_copy(&cspace, pt->ipc_buffer_mapped_cap, frame_table_cspace(), frame_page(pt->ipc_buffer_frame), seL4_AllRights);
    if(err) {
        cspace_free_slot(&cspace, pt->ipc_buffer_mapped_cap);
        pt->ipc_buffer_mapped_cap = 0;
        ZF_LOGE("Failed to copy IPC buffer cap");
        goto on_error;
    }
    err = seL4_TCB_Configure(pt->tcb,
                             pt->cspace.root_cnode, seL4_NilData,
                             pt->vspace, seL4_NilData, PROCESS_IPC_BUFFER,
                             pt->ipc_buffer_mapped_cap);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure new TCB");
        goto on_error;
    }

    /* Create scheduling context */
    pt->sched_context_ut = alloc_retype(&pt->sched_context, seL4_SchedContextObject,
                                                     seL4_MinSchedContextBits);
    if (pt->sched_context_ut == NULL) {
        ZF_LOGE("Failed to alloc sched context ut");
        goto on_error;
    }

    /* Configure the scheduling context to use the first core with budget equal to period */
    err = seL4_SchedControl_Configure(sched_ctrl_start, pt->sched_context, US_IN_MS, US_IN_MS, 0, 0);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure scheduling context");
        goto on_error;
    }

    // badged fault endpoint
    pt->fault_ep = cspace_alloc_slot(&cspace);
    if(pt->fault_ep == seL4_CapNull) {
        ZF_LOGE("Unable to create slot for badged fault endpoint");
        goto on_error;
    }
    err = cspace_mint(&cspace, pt->fault_ep, &cspace, ep, seL4_AllRights, ptidx);
    if(err != seL4_NoError) {
        ZF_LOGE("Error minting fault endpoint: %d", err);
        cspace_free_slot(&cspace_free_slot, pt->fault_ep);
        pt->fault_ep = 0;
        goto on_error;
    }

    /* bind sched context, set fault endpoint and priority
     * In MCS, fault end point needed here should be in current thread's cspace.
     * NOTE this will use the unbadged ep unlike above, you might want to mint it with a badge
     * so you can identify which thread faulted in your fault handler */
    err = seL4_TCB_SetSchedParams(pt->tcb, seL4_CapInitThreadTCB, seL4_MinPrio, USER_PRIORITY,
                                  pt->sched_context, pt->fault_ep);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to set scheduling params");
        goto on_error;
    }

    // add IPC buffer to user's AS region
    newas.attr.type = AS_NORMAL;
    newas.attr.data = 0;
    newas.begin = PROCESS_IPC_BUFFER;
    newas.end = PROCESS_IPC_BUFFER + PAGE_SIZE_4K;
    newas.perm = seL4_AllRights;
    addrspace_add(&pt->as, newas, false, NULL);

    /* Map in the IPC buffer for the thread */
    // free_on_delete is false: we'll free the frame table manually upon process destruction.
    err = grp01_map_frame(ptidx, pt->ipc_buffer_frame, false, false, PROCESS_IPC_BUFFER,
                    seL4_AllRights, seL4_ARM_Default_VMAttributes);
    if (err != 0) {
        ZF_LOGE("Unable to map IPC buffer for user app");
        goto on_error;
    }

    // create filetable
    if(fileman_create(ptidx)) {
        ZF_LOGE("Unable to allocate file table.");
        goto on_error;
    }

    /* Provide a name for the thread -- Helpful for debugging */
    NAME_THREAD(pt->tcb, app_name);

    pt->loader_state.filename = app_name;
    pt->loader_state.parent_pid = parent_pid;

    // fill in some info
    pt->start_msec = get_time();
    strncpy(pt->command, app_name, N_NAME);
    pt->command[N_NAME - 1] = 0;

    // create background worker for this app.
    if(!bgworker_create(ptidx)) {
        ZF_LOGE("Unable to spawn SOS' thread for user app");
        goto on_error;
    }

    return ptidx;

on_error:
    pt->state_flag = 0;
    destroy_process(ptidx);
    return -1;
}

static int stack_write(seL4_Word *mapped_stack, int index, uintptr_t val)
{
    mapped_stack[index] = val;
    return index - 1;
}

/* set up System V ABI compliant stack, so that the process can
 * start up and initialise the C library */
static uintptr_t init_process_stack(sos_pid_t badge, elf_t *elf_file)
{
    // we assume that caller give the sane badge value here!
    proctable_t* pt = proctable + badge;

    // create the stack region
    addrspace_t stackas;
    stackas.end = PROCESS_STACK_TOP;
    stackas.begin = PROCESS_STACK_TOP - PROCESS_STACK_MIN_PAGES * PAGE_SIZE_4K;
    stackas.perm = seL4_CapRights_new(false, false, true, true);
    stackas.attr.type = AS_STACK;

    // map this stack region to process' address space
    if(addrspace_add(&pt->as, stackas, false, NULL) != AS_ADD_NOERR) {
        ZF_LOGE("Error adding stack address space region to process.");
        return 0;
    }

    /* Create a stack frame */
    frame_ref_t initial_stack = delegate_alloc_frame();
    if(!initial_stack) {
        ZF_LOGE("Failed to allocate initial stack");
        return 0;
    }

    /* find the vsyscall table */
    uintptr_t sysinfo = *((uintptr_t *) elf_getSectionNamed(elf_file, "__vsyscall", NULL));
    if (sysinfo == 0) {
        ZF_LOGE("could not find syscall table for c library");
        return 0;
    }

    /* Map in the initial stack frame for the user app */
    seL4_Error err = delegate_map_frame(badge, initial_stack, true, false,
                               PROCESS_STACK_TOP - PAGE_SIZE_4K, seL4_AllRights, 
                               seL4_ARM_Default_VMAttributes);
    if (err != 0) {
        ZF_LOGE("Unable to map stack for user app");
        return 0;
    }

    int index = -2;
    // FT: no pin needed. there is no other frame_data/frame_page until this 
    // function finishes.
    void *local_stack_top = delegate_frame_data(initial_stack) + PAGE_SIZE_4K;
    if(!local_stack_top) {
        ZF_LOGE("Memory full when setting up process stack");
        return 0;
    }

    /* null terminate the aux vectors */
    index = stack_write(local_stack_top, index, 0);
    index = stack_write(local_stack_top, index, 0);

    /* write the aux vectors */
    index = stack_write(local_stack_top, index, PAGE_SIZE_4K);
    index = stack_write(local_stack_top, index, AT_PAGESZ);

    index = stack_write(local_stack_top, index, sysinfo);
    index = stack_write(local_stack_top, index, AT_SYSINFO);

    index = stack_write(local_stack_top, index, PROCESS_IPC_BUFFER);
    index = stack_write(local_stack_top, index, AT_SEL4_IPC_BUFFER_PTR);

    /* null terminate the environment pointers */
    index = stack_write(local_stack_top, index, 0);

    /* we don't have any env pointers - skip */

    /* null terminate the argument pointers */
    index = stack_write(local_stack_top, index, 0);

    /* no argpointers - skip */

    /* set argc to 0 */
    stack_write(local_stack_top, index, 0);

    /* adjust the initial stack top (for return value) */
    uintptr_t stack_top = PROCESS_STACK_TOP;
    stack_top += (index * sizeof(seL4_Word));

    /* the stack *must* remain aligned to a double word boundary,
     * as GCC assumes this, and horrible bugs occur if this is wrong */
    assert(index % 2 == 0);
    assert(stack_top % (sizeof(seL4_Word) * 2) == 0);

    return stack_top;
}

bool start_process_load_elf(sos_pid_t new_pid)
{
    // we need main thread to be able to handle fault
    assert_non_main_thread();

    proctable_t* pt = proctable + new_pid;
    assert(pt->state_flag & PROC_STATE_CONSTRUCTING);
    seL4_Word parent_pid = pt->loader_state.parent_pid;

    // check file size
    sos_filehandle_t fh;
    fh.fh = find_handler(pt->loader_state.filename);
    sos_stat_t filestat;
    ssize_t ioerr = fh.fh->stat(parent_pid, pt->loader_state.filename, &filestat);
    if(ioerr < 0 || !filestat.st_size)
        return false;
    pt->file_size = filestat.st_size;

    if(filestat.st_size > MAX_FILE_BACK_SIZE) {
        ZF_LOGE("ELF file too large.");
        return false;
    }

    // open the file
    fh.id = fh.fh->open(parent_pid, pt->loader_state.filename, O_RDONLY);
    if(fh.id < 0) {
        ZF_LOGE("Error opening ELF file");
        return false;
    }

    // allocate file-backed scratch space
    uintptr_t scratch_base = delegate_allocate_sos_scratch(filestat.st_size);
    if(!scratch_base) {
        ZF_LOGE("Error allocating scratch space for loading ELF");
        goto error_01;
    }

    if(!delegate_file_backed_sos_map(&fh, scratch_base, filestat.st_size)) {
        ZF_LOGE("Failed to map scratch space");
        goto error_02;
    }

    // parse the executable file
    elf_t elf_file = {};
    /* Ensure that the file is an elf file. */
    if (elf_newFile(scratch_base, filestat.st_size, &elf_file)) {
        ZF_LOGE("Invalid elf file");
        goto error_02;
    }

    uintptr_t sp = init_process_stack(new_pid, &elf_file);
    if(!sp)
        // process_destroy will take care of the mapped frames here
        goto error_02;

    if(elf_load(new_pid, &elf_file))
        goto error_02;

    // initial registers for stack and entrypoint
    seL4_UserContext context = {
        .pc = elf_getEntryPoint(&elf_file),
        .sp = sp,
    };

    // load finishes. unmap scratch space
    fh.fh->close(parent_pid, fh.id);
    delegate_free_sos_scratch(scratch_base);

    // go!
    seL4_Error err = seL4_TCB_WriteRegisters(pt->tcb, 1, 0, 2, &context);
    ZF_LOGE_IF(err, "Failed to write registers");

    pt->state_flag ^= PROC_STATE_CONSTRUCTING;

    return err == seL4_NoError;

error_02: // go here if error after allocating scratch
    delegate_free_sos_scratch(scratch_base);
error_01: // go here if error after opening file
    fh.fh->close(parent_pid, fh.id);
    return false;
}

void destroy_process(sos_pid_t pid)
{
    invalidate_proc_list_cache();
    
    assert_main_thread();
    proctable_t* pt = proctable + pid;
    assert(pt->active);
    if(pt->state_flag & (PROC_STATE_CONSTRUCTING | PROC_STATE_PENDING_KILL)) {
        // the ELF loading stage when finishes will call the 3rd stage
        // the 3rd stage, which will be executed in main thread, should
        // check this flag first before proceeding.
        pt->state_flag |= PROC_STATE_PENDING_KILL;
        return;
    }

    if(!fileman_destroy(pid)) {
        // fileman itself will schedule a deletion later
        pt->state_flag |= PROC_STATE_PENDING_KILL;
        return;
    }

    // we assume that nonzero fields have valid values and need to be destroyed/freed
    // therefore it is crucial not to left any values nonzero.
    pt->state_flag = 0;

    if(pt->fault_ep) {
        cspace_delete(&cspace, pt->fault_ep);
        cspace_free_slot(&cspace, pt->fault_ep);
        pt->fault_ep = 0;
    }

    // free scheduling context
    if(pt->sched_context)
        cap_ut_dealloc(&pt->sched_context, &pt->sched_context_ut);

    // free TCB
    if(pt->tcb)
        cap_ut_dealloc(&pt->tcb, &pt->tcb_ut);

    // tear down user's cspace
    if(pt->cspace.bootstrap) {
        cspace_destroy(&pt->cspace);
        memset(&pt->cspace, 0, sizeof(pt->cspace));
    }
    
    // tear down vspace
    if(pt->vspace) {
        grp01_map_destroy(pid);
        cap_ut_dealloc(&pt->vspace, &pt->vspace_ut);
    }

    // free IPC buffer's mapping on user's side
    if(pt->ipc_buffer_mapped_cap) {
        cspace_delete(&cspace, pt->ipc_buffer_mapped_cap);
        cspace_free_slot(&cspace, pt->ipc_buffer_mapped_cap);
        pt->ipc_buffer_mapped_cap = 0;
    }

    // free IPC buffer
    if(pt->ipc_buffer_frame) {
        free_frame(pt->ipc_buffer_frame);
        pt->ipc_buffer_frame = 0;
    }

    // reuse reply buffer if process is waiting on something
    if(pt->waitee_reply) {
        // remove this process from target's waitee list
        if(pt->wait_target < 0) {
            waitee_any[waitee_any[pid].prev].next = waitee_any[pid].next;
            waitee_any[waitee_any[pid].next].prev = waitee_any[pid].prev;
            memset(waitee_any + pid, 0, sizeof(waitee_any_node_t));
        } else {
            assert(GET_BMP(proctable[pt->wait_target].waitee_list, pid));
            TOGGLE_BMP(proctable[pt->wait_target].waitee_list, pid);
        }
        // reuse reply
        sos_reuse_reply(pt->waitee_reply);
        pt->wait_target = pt->waitee_reply = 0;
    }
    
    // finally:
    // we only set the fields here to zero. callers are expected
    // to clean up the user mapping and the scratch address space.
    if(pt->loader_state.filename)
        memset(&pt->loader_state, 0, sizeof(pt->loader_state));

    *pt->command = 0;
    pt->file_size = 0;
    dynarray_destroy(&pt->as);
    bgworker_destroy(pid);
    set_pid_state(pid, false);

    // notify a single waitee from any waitee
    if(waitee_any->prev) {
        notify_waitee(waitee_any->next, pid);
        waitee_any_node_t* curr = waitee_any + waitee_any->next;
        waitee_any->next = curr->next;
        waitee_any[curr->next].prev = curr->prev;
        memset(curr, 0, sizeof(waitee_any_node_t));
    }
    
    // notify all targeted waitee
    sos_pid_t tg_waitee;
    while((tg_waitee = bitfield_first_used(WAITEE_BF_WORDS, pt->waitee_list)) > 0) {
        notify_waitee(tg_waitee, pid);
        TOGGLE_BMP(pt->waitee_list, tg_waitee);
    }
}

void notify_waitee(sos_pid_t waitee, sos_pid_t target)
{
    proctable_t* pt = proctable + waitee;
    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, target);
    seL4_Send(pt->waitee_reply, msginfo);
    sos_reuse_reply(pt->waitee_reply);
    pt->waitee_reply = pt->wait_target = 0;
}
