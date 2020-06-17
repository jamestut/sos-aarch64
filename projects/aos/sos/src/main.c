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
#include <autoconf.h>
#include <utils/util.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <errno.h>

#include <cspace/cspace.h>
#include <aos/sel4_zf_logif.h>
#include <aos/debug.h>

#include <clock/clock.h>
#include <cpio/cpio.h>
#include <elf/elf.h>
#include <serial/serial.h>

#include <sel4runtime.h>
#include <sel4runtime/auxv.h>

#include <sossysnr.h>

#include "bootstrap.h"
#include "irq.h"
#include "network.h"
#include "frame_table.h"
#include "drivers/uart.h"
#include "ut.h"
#include "vmem_layout.h"
#include "mapping.h"
#include "elfload.h"
#include "syscalls.h"
#include "tests.h"
#include "utils.h"
#include "threads.h"

// GRP01: for testing M01
#include "libclocktest.h"

// GRP01: M2
#include "fileman.h"
#include "bgworker.h"

#include <aos/vsyscall.h>

/*
 * To differentiate between signals from notification objects and and IPC messages,
 * we assign a badge to the notification object. The badge that we receive will
 * be the bitwise 'OR' of the notification object badge and the badges
 * of all pending IPC messages.
 *
 * All badged IRQs set high bet, then we use uniqe bits to
 * distinguish interrupt sources.
 */
#define IRQ_EP_BADGE         BIT(seL4_BadgeBits - 1ul)
#define IRQ_IDENT_BADGE_BITS MASK(seL4_BadgeBits - 1ul)

#define TTY_NAME             "tty_test"
#define TTY_PRIORITY         (0)
#define TTY_EP_BADGE         (101)

/* The number of additional stack pages to provide to the initial
 * process */
#define INITIAL_PROCESS_EXTRA_STACK_PAGES 4

/*
 * A dummy starting syscall
 */
#define SOS_SYSCALL0 0

/* The linker will link this symbol to the start address  *
 * of an archive of attached applications.                */
extern char _cpio_archive[];
extern char _cpio_archive_end[];
extern char __eh_frame_start[];
/* provided by gcc */
extern void (__register_frame)(void *);

/* root tasks cspace */
cspace_t cspace;

static seL4_CPtr sched_ctrl_start;
static seL4_CPtr sched_ctrl_end;

/* the one process we start */
static struct {
    ut_t *tcb_ut;
    seL4_CPtr tcb;
    ut_t *vspace_ut;
    seL4_CPtr vspace;

    ut_t *ipc_buffer_ut;
    seL4_CPtr ipc_buffer;

    ut_t *ipc_buffer_large_ut;
    seL4_CPtr ipc_buffer_large;
    seL4_CPtr ipc_buffer_large_local;
    void* ipc_buffer_large_ptr;

    ut_t *sched_context_ut;
    seL4_CPtr sched_context;

    cspace_t cspace;

    ut_t *stack_ut;
    seL4_CPtr stack;
} tty_test_process;


void handle_syscall(UNUSED seL4_Word badge, UNUSED int num_args, seL4_CPtr reply)
{

    /* get the first word of the message, which in the SOS protocol is the number
     * of the SOS "syscall". */
    seL4_Word syscall_number = seL4_GetMR(0);

    // store whatever the handler returns, and pass to app if non zero.
    seL4_Word handler_ret = ENOSYS;

    /* Process system call */
    switch (syscall_number) {
    case SOS_SYSCALL_OPEN:
        // hard limit for string values
        if(seL4_GetMR(1) >= PAGE_SIZE_4K)
            handler_ret = ENAMETOOLONG;
        else {
            char * fn = tty_test_process.ipc_buffer_large_ptr;
            fn[seL4_GetMR(1)] = 0;
            handler_ret = fileman_open(badge, reply, fn, seL4_GetMR(2));
        }
        break;
    case 555:
    {
        // TODO: GRP01 just for debug. remove this.
        char* test = tty_test_process.ipc_buffer_large_ptr;
        break;
    }
    default:
        ZF_LOGE("Unknown syscall %lu\n", syscall_number);
    }

    // reply if handler_ret is not 0. otherwise, we assume that the handler will
    // reply at some later point
    if(handler_ret) {
        seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, handler_ret);
        seL4_Send(reply, reply_msg);
        /* in MCS kernel, reply object is meant to be reused rather than freed */
        /* Free the slot we allocated for the reply - it is now empty, as the reply
         * capability was consumed by the send. */
        cspace_free_slot(&cspace, reply);
    }
}

NORETURN void syscall_loop(seL4_CPtr ep)
{
    seL4_CPtr reply;

    while (1) {
        /* Create reply object */
        // we'll need to realloc a new reply object, as the old one may take a while
        // to be replied.
        // TODO: GRP01 avoid UT leak
        // TODO: GRP01 do not reallocate if a codepath doesn't use the reply object,
        //             such as sos_handle_irq_notification
        ut_t *reply_ut = alloc_retype(&reply, seL4_ReplyObject, seL4_ReplyBits);
        if (reply_ut == NULL) {
            ZF_LOGF("Failed to alloc reply object ut");
        }
        ut_free(reply_ut);

        seL4_Word badge = 0;
        /* Block on ep, waiting for an IPC sent over ep, or
         * a notification from our bound notification object */
        seL4_MessageInfo_t message = seL4_Recv(ep, &badge, reply);
        /* Awake! We got a message - check the label and badge to
         * see what the message is about */
        seL4_Word label = seL4_MessageInfo_get_label(message);

        if (badge & IRQ_EP_BADGE) {
            /* It's a notification from our bound notification
             * object! */
            sos_handle_irq_notification(&badge);
        } else if (label == seL4_Fault_NullFault) {
            /* It's not a fault or an interrupt, it must be an IPC
             * message from tty_test! */
            handle_syscall(badge, seL4_MessageInfo_get_length(message) - 1, reply);
        } else {
            /* some kind of fault */
            debug_print_fault(message, TTY_NAME);
            /* dump registers too */
            debug_dump_registers(tty_test_process.tcb);

            ZF_LOGF("The SOS skeleton does not know how to handle faults!");
        }
    }
}

static int stack_write(seL4_Word *mapped_stack, int index, uintptr_t val)
{
    mapped_stack[index] = val;
    return index - 1;
}

/* set up System V ABI compliant stack, so that the process can
 * start up and initialise the C library */
static uintptr_t init_process_stack(cspace_t *cspace, seL4_CPtr local_vspace, elf_t *elf_file)
{
    /* Create a stack frame */
    tty_test_process.stack_ut = alloc_retype(&tty_test_process.stack, seL4_ARM_SmallPageObject, seL4_PageBits);
    if (tty_test_process.stack_ut == NULL) {
        ZF_LOGE("Failed to allocate stack");
        return 0;
    }

    /* virtual addresses in the target process' address space */
    uintptr_t stack_top = PROCESS_STACK_TOP;
    uintptr_t stack_bottom = PROCESS_STACK_TOP - PAGE_SIZE_4K;
    /* virtual addresses in the SOS's address space */
    void *local_stack_top  = (seL4_Word *) SOS_SCRATCH;
    uintptr_t local_stack_bottom = SOS_SCRATCH - PAGE_SIZE_4K;

    /* find the vsyscall table */
    uintptr_t sysinfo = *((uintptr_t *) elf_getSectionNamed(elf_file, "__vsyscall", NULL));
    if (sysinfo == 0) {
        ZF_LOGE("could not find syscall table for c library");
        return 0;
    }

    /* Map in the stack frame for the user app */
    seL4_Error err = map_frame(cspace, tty_test_process.stack, tty_test_process.vspace, stack_bottom,
                               seL4_AllRights, seL4_ARM_Default_VMAttributes);
    if (err != 0) {
        ZF_LOGE("Unable to map stack for user app");
        return 0;
    }

    /* allocate a slot to duplicate the stack frame cap so we can map it into our address space */
    seL4_CPtr local_stack_cptr = cspace_alloc_slot(cspace);
    if (local_stack_cptr == seL4_CapNull) {
        ZF_LOGE("Failed to alloc slot for stack");
        return 0;
    }

    /* copy the stack frame cap into the slot */
    err = cspace_copy(cspace, local_stack_cptr, cspace, tty_test_process.stack, seL4_AllRights);
    if (err != seL4_NoError) {
        cspace_free_slot(cspace, local_stack_cptr);
        ZF_LOGE("Failed to copy cap");
        return 0;
    }

    /* map it into the sos address space */
    err = map_frame(cspace, local_stack_cptr, local_vspace, local_stack_bottom, seL4_AllRights,
                    seL4_ARM_Default_VMAttributes);
    if (err != seL4_NoError) {
        cspace_delete(cspace, local_stack_cptr);
        cspace_free_slot(cspace, local_stack_cptr);
        return 0;
    }

    int index = -2;

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

    /* adjust the initial stack top */
    stack_top += (index * sizeof(seL4_Word));

    /* the stack *must* remain aligned to a double word boundary,
     * as GCC assumes this, and horrible bugs occur if this is wrong */
    assert(index % 2 == 0);
    assert(stack_top % (sizeof(seL4_Word) * 2) == 0);

    /* unmap our copy of the stack */
    err = seL4_ARM_Page_Unmap(local_stack_cptr);
    assert(err == seL4_NoError);

    /* delete the copy of the stack frame cap */
    err = cspace_delete(cspace, local_stack_cptr);
    assert(err == seL4_NoError);

    /* mark the slot as free */
    cspace_free_slot(cspace, local_stack_cptr);

    /* Exend the stack with extra pages */
    for (int page = 0; page < INITIAL_PROCESS_EXTRA_STACK_PAGES; page++) {
        stack_bottom -= PAGE_SIZE_4K;
        frame_ref_t frame = alloc_frame();
        if (frame == NULL_FRAME) {
            ZF_LOGE("Couldn't allocate additional stack frame");
            return 0;
        }

        /* allocate a slot to duplicate the stack frame cap so we can map it into the application */
        seL4_CPtr frame_cptr = cspace_alloc_slot(cspace);
        if (local_stack_cptr == seL4_CapNull) {
            free_frame(frame);
            ZF_LOGE("Failed to alloc slot for stack extra stack frame");
            return 0;
        }

        /* copy the stack frame cap into the slot */
        err = cspace_copy(cspace, frame_cptr, cspace, frame_page(frame), seL4_AllRights);
        if (err != seL4_NoError) {
            cspace_free_slot(cspace, frame_cptr);
            free_frame(frame);
            ZF_LOGE("Failed to copy cap");
            return 0;
        }

        err = map_frame(cspace, frame_cptr, tty_test_process.vspace, stack_bottom,
                        seL4_AllRights, seL4_ARM_Default_VMAttributes);
        if (err != 0) {
            cspace_delete(cspace, frame_cptr);
            cspace_free_slot(cspace, frame_cptr);
            free_frame(frame);
            ZF_LOGE("Unable to map extra stack frame for user app");
            return 0;
        }
    }

    return stack_top;
}

/* Start the first process, and return true if successful
 *
 * This function will leak memory if the process does not start successfully.
 * TODO: avoid leaking memory once you implement real processes, otherwise a user
 *       can force your OS to run out of memory by creating lots of failed processes.
 */
bool start_first_process(char *app_name, seL4_CPtr ep)
{
    /* Create a VSpace */
    tty_test_process.vspace_ut = alloc_retype(&tty_test_process.vspace, seL4_ARM_PageGlobalDirectoryObject,
                                              seL4_PGDBits);
    if (tty_test_process.vspace_ut == NULL) {
        return false;
    }

    /* assign the vspace to an asid pool */
    seL4_Word err = seL4_ARM_ASIDPool_Assign(seL4_CapInitThreadASIDPool, tty_test_process.vspace);
    if (err != seL4_NoError) {
        ZF_LOGE("Failed to assign asid pool");
        return false;
    }

    /* Create a simple 1 level CSpace */
    err = cspace_create_one_level(&cspace, &tty_test_process.cspace);
    if (err != CSPACE_NOERROR) {
        ZF_LOGE("Failed to create cspace");
        return false;
    }

    /* Create an IPC buffer */
    tty_test_process.ipc_buffer_ut = alloc_retype(&tty_test_process.ipc_buffer, seL4_ARM_SmallPageObject,
                                                  seL4_PageBits);
    if (tty_test_process.ipc_buffer_ut == NULL) {
        ZF_LOGE("Failed to alloc ipc buffer ut");
        return false;
    }
    // create 2nd IPC buffer for passing large data
    tty_test_process.ipc_buffer_large_ut = alloc_retype(&tty_test_process.ipc_buffer_large, seL4_ARM_SmallPageObject,
        seL4_PageBits);
    if (tty_test_process.ipc_buffer_large_ut == NULL) {
        ZF_LOGE("Failed to alloc large ipc buffer ut");
        return false;
    }
    // create another copy of this buffer, so that we can map it for ourself!
    tty_test_process.ipc_buffer_large_local = cspace_alloc_slot(&cspace);
    if(tty_test_process.ipc_buffer_large_local == seL4_CapNull) {
        ZF_LOGE("Failed to allocate the 2nd large ipc frame cspace slot");
        return false;
    }
    err = cspace_copy(&cspace, tty_test_process.ipc_buffer_large_local, &cspace, tty_test_process.ipc_buffer_large, seL4_AllRights);
    if(err != 0) {
        ZF_LOGE("Failed to copy large ipc frame capability");
        return false;
    }

    /* allocate a new slot in the target cspace which we will mint a badged endpoint cap into --
     * the badge is used to identify the process, which will come in handy when you have multiple
     * processes. */
    seL4_CPtr user_ep = cspace_alloc_slot(&tty_test_process.cspace);
    if (user_ep == seL4_CapNull) {
        ZF_LOGE("Failed to alloc user ep slot");
        return false;
    }

    /* now mutate the cap, thereby setting the badge */
    err = cspace_mint(&tty_test_process.cspace, user_ep, &cspace, ep, seL4_AllRights, TTY_EP_BADGE);
    if (err) {
        ZF_LOGE("Failed to mint user ep");
        return false;
    }

    /* Create a new TCB object */
    tty_test_process.tcb_ut = alloc_retype(&tty_test_process.tcb, seL4_TCBObject, seL4_TCBBits);
    if (tty_test_process.tcb_ut == NULL) {
        ZF_LOGE("Failed to alloc tcb ut");
        return false;
    }

    /* Configure the TCB */
    err = seL4_TCB_Configure(tty_test_process.tcb,
                             tty_test_process.cspace.root_cnode, seL4_NilData,
                             tty_test_process.vspace, seL4_NilData, PROCESS_IPC_BUFFER,
                             tty_test_process.ipc_buffer);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure new TCB");
        return false;
    }

    /* Create scheduling context */
    tty_test_process.sched_context_ut = alloc_retype(&tty_test_process.sched_context, seL4_SchedContextObject,
                                                     seL4_MinSchedContextBits);
    if (tty_test_process.sched_context_ut == NULL) {
        ZF_LOGE("Failed to alloc sched context ut");
        return false;
    }

    /* Configure the scheduling context to use the first core with budget equal to period */
    err = seL4_SchedControl_Configure(sched_ctrl_start, tty_test_process.sched_context, US_IN_MS, US_IN_MS, 0, 0);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure scheduling context");
        return false;
    }

    /* bind sched context, set fault endpoint and priority
     * In MCS, fault end point needed here should be in current thread's cspace.
     * NOTE this will use the unbadged ep unlike above, you might want to mint it with a badge
     * so you can identify which thread faulted in your fault handler */
    err = seL4_TCB_SetSchedParams(tty_test_process.tcb, seL4_CapInitThreadTCB, seL4_MinPrio, TTY_PRIORITY,
                                  tty_test_process.sched_context, ep);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to set scheduling params");
        return false;
    }

    /* Provide a name for the thread -- Helpful for debugging */
    NAME_THREAD(tty_test_process.tcb, app_name);

    /* parse the cpio image */
    ZF_LOGI("\nStarting \"%s\"...\n", app_name);
    elf_t elf_file = {};
    unsigned long elf_size;
    size_t cpio_len = _cpio_archive_end - _cpio_archive;
    char *elf_base = cpio_get_file(_cpio_archive, cpio_len, app_name, &elf_size);
    if (elf_base == NULL) {
        ZF_LOGE("Unable to locate cpio header for %s", app_name);
        return false;
    }
    /* Ensure that the file is an elf file. */
    if (elf_newFile(elf_base, elf_size, &elf_file)) {
        ZF_LOGE("Invalid elf file");
        return -1;
    }

    /* set up the stack */
    seL4_Word sp = init_process_stack(&cspace, seL4_CapInitThreadVSpace, &elf_file);

    /* load the elf image from the cpio file */
    err = elf_load(&cspace, tty_test_process.vspace, &elf_file);
    if (err) {
        ZF_LOGE("Failed to load elf image");
        return false;
    }

    /* Map in the IPC buffer for the thread */
    err = map_frame(&cspace, tty_test_process.ipc_buffer, tty_test_process.vspace, PROCESS_IPC_BUFFER,
                    seL4_AllRights, seL4_ARM_Default_VMAttributes);
    if (err != 0) {
        ZF_LOGE("Unable to map IPC buffer for user app");
        return false;
    }

    // extra page for large data that has to be passed thru IPC
    err = map_frame(&cspace, tty_test_process.ipc_buffer_large, tty_test_process.vspace, PROCESS_IPC_BUFFER + PAGE_SIZE_4K,
                    seL4_AllRights, seL4_ARM_Default_VMAttributes);
    if (err != 0) {
        ZF_LOGE("Unable to map larger IPC buffer for user app");
        return false;
    }
    // also map it to ourself!
    // TODO: GRP01 do not hardcode the value like this for the next milestones!
    // WARNING! seL4 "might" not support 64 bit mem management, as the vaddr argument 
    // in seL4_ARM_Page_Map only accepts seL4_Word
    tty_test_process.ipc_buffer_large_ptr = (void*)(SOS_IPC_BUFFER + PAGE_SIZE_4K);
    err = map_frame(&cspace, tty_test_process.ipc_buffer_large_local, seL4_CapInitThreadVSpace,
        (seL4_Word)tty_test_process.ipc_buffer_large_ptr, seL4_AllRights, seL4_ARM_Default_VMAttributes);
    if (err != 0) {
        ZF_LOGE("Unable to map larger IPC buffer for SOS itself");
        return false;
    }

    // create filetable
    if(fileman_create(TTY_EP_BADGE)) {
        ZF_LOGE("Unable to allocate file table.");
        return false;
    }

    /* Start the new process */
    seL4_UserContext context = {
        .pc = elf_getEntryPoint(&elf_file),
        .sp = sp,
    };
    printf("Starting ttytest at %p\n", (void *) context.pc);
    err = seL4_TCB_WriteRegisters(tty_test_process.tcb, 1, 0, 2, &context);
    ZF_LOGE_IF(err, "Failed to write registers");
    return err == seL4_NoError;
}

/* Allocate an endpoint and a notification object for sos.
 * Note that these objects will never be freed, so we do not
 * track the allocated ut objects anywhere
 */
static void sos_ipc_init(seL4_CPtr *ipc_ep, seL4_CPtr *ntfn)
{
    /* Create an notification object for interrupts */
    ut_t *ut = alloc_retype(ntfn, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!ut, "No memory for notification object");

    /* Bind the notification object to our TCB */
    seL4_Error err = seL4_TCB_BindNotification(seL4_CapInitThreadTCB, *ntfn);
    ZF_LOGF_IFERR(err, "Failed to bind notification object to TCB");

    /* Create an endpoint for user application IPC */
    ut = alloc_retype(ipc_ep, seL4_EndpointObject, seL4_EndpointBits);
    ZF_LOGF_IF(!ut, "No memory for endpoint");
}

/* called by crt */
seL4_CPtr get_seL4_CapInitThreadTCB(void)
{
    return seL4_CapInitThreadTCB;
}

/* tell muslc about our "syscalls", which will bve called by muslc on invocations to the c library */
void init_muslc(void)
{
    muslcsys_install_syscall(__NR_set_tid_address, sys_set_tid_address);
    muslcsys_install_syscall(__NR_writev, sys_writev);
    muslcsys_install_syscall(__NR_exit, sys_exit);
    muslcsys_install_syscall(__NR_rt_sigprocmask, sys_rt_sigprocmask);
    muslcsys_install_syscall(__NR_gettid, sys_gettid);
    muslcsys_install_syscall(__NR_getpid, sys_getpid);
    muslcsys_install_syscall(__NR_tgkill, sys_tgkill);
    muslcsys_install_syscall(__NR_tkill, sys_tkill);
    muslcsys_install_syscall(__NR_exit_group, sys_exit_group);
    muslcsys_install_syscall(__NR_ioctl, sys_ioctl);
    muslcsys_install_syscall(__NR_mmap, sys_mmap);
    muslcsys_install_syscall(__NR_brk,  sys_brk);
    muslcsys_install_syscall(__NR_clock_gettime, sys_clock_gettime);
    muslcsys_install_syscall(__NR_nanosleep, sys_nanosleep);
    muslcsys_install_syscall(__NR_getuid, sys_getuid);
    muslcsys_install_syscall(__NR_getgid, sys_getgid);
    muslcsys_install_syscall(__NR_openat, sys_openat);
    muslcsys_install_syscall(__NR_close, sys_close);
    muslcsys_install_syscall(__NR_socket, sys_socket);
    muslcsys_install_syscall(__NR_bind, sys_bind);
    muslcsys_install_syscall(__NR_listen, sys_listen);
    muslcsys_install_syscall(__NR_connect, sys_connect);
    muslcsys_install_syscall(__NR_accept, sys_accept);
    muslcsys_install_syscall(__NR_sendto, sys_sendto);
    muslcsys_install_syscall(__NR_recvfrom, sys_recvfrom);
    muslcsys_install_syscall(__NR_readv, sys_readv);
    muslcsys_install_syscall(__NR_getsockname, sys_getsockname);
    muslcsys_install_syscall(__NR_getpeername, sys_getpeername);
    muslcsys_install_syscall(__NR_fcntl, sys_fcntl);
    muslcsys_install_syscall(__NR_setsockopt, sys_setsockopt);
    muslcsys_install_syscall(__NR_getsockopt, sys_getsockopt);
    muslcsys_install_syscall(__NR_ppoll, sys_ppoll);
    muslcsys_install_syscall(__NR_madvise, sys_madvise);
}

NORETURN void *main_continued(UNUSED void *arg)
{
    /* Initialise other system compenents here */
    seL4_CPtr ipc_ep, ntfn;
    sos_ipc_init(&ipc_ep, &ntfn);
    sos_init_irq_dispatch(
        &cspace,
        seL4_CapIRQControl,
        ntfn,
        IRQ_EP_BADGE,
        IRQ_IDENT_BADGE_BITS
    );
    frame_table_init(&cspace, seL4_CapInitThreadVSpace);

    // GRP01: init OS parts here
    fileman_init();

    /* run sos initialisation tests */
    run_tests(&cspace);

    /* Map the timer device (NOTE: this is the same mapping you will use for your timer driver -
     * sos uses the watchdog timers on this page to implement reset infrastructure & network ticks,
     * so touching the watchdog timers here is not recommended!) */
    void *timer_vaddr = sos_map_device(&cspace, PAGE_ALIGN_4K(TIMER_MAP_BASE), PAGE_SIZE_4K);

    /* Initialise the network hardware. (meson ethernet for now) */
    #ifdef CONFIG_PLAT_ODROIDC2
    // TODO: reenable ethernet (this is disabled to make debugging quicker)
    // printf("Network init\n");
    // network_init(&cspace, timer_vaddr, ntfn);
    #endif

    /* Initialises the timer */
    printf("Timer init\n");
    start_timer(timer_vaddr);
    /* You will need to register an IRQ handler for the timer here.
     * See "irq.h". */

    // GRP01: for testing M01
    //libclocktest_begin();
    // we expect this to do nothing for non odroidc2
    //libclocktest_manual_action();

    /* Start the user application */
    printf("Start first process\n");
    bool success = start_first_process(TTY_NAME, ipc_ep);
    ZF_LOGF_IF(!success, "Failed to start first process");

    printf("\nSOS entering syscall loop\n");
    init_threads(ipc_ep, sched_ctrl_start, sched_ctrl_end);
    bgworker_init();
    syscall_loop(ipc_ep);
}
/*
 * Main entry point - called by crt.
 */
int main(void)
{
    init_muslc();

    /* register the location of the unwind_tables -- this is required for
     * backtrace() to work */
    __register_frame(&__eh_frame_start);

    seL4_BootInfo *boot_info = sel4runtime_bootinfo();

    debug_print_bootinfo(boot_info);

    printf("\nSOS Starting...\n");

    NAME_THREAD(seL4_CapInitThreadTCB, "SOS:root");

    sched_ctrl_start = boot_info->schedcontrol.start;
    sched_ctrl_end = boot_info->schedcontrol.end;

    /* Initialise the cspace manager, ut manager and dma */
    sos_bootstrap(&cspace, boot_info);

    /* switch to the real uart to output (rather than seL4_DebugPutChar, which only works if the
     * kernel is built with support for printing, and is much slower, as each character print
     * goes via the kernel)
     *
     * NOTE we share this uart with the kernel when the kernel is in debug mode. */
    // meson UART only
    #ifdef CONFIG_PLAT_ODROIDC2
    uart_init(&cspace);
    update_vputchar(uart_putchar);
    #endif

    /* test print */
    printf("SOS Started!\n");

    /* allocate a bigger stack and switch to it -- we'll also have a guard page, which makes it much
     * easier to detect stack overruns */
    seL4_Word vaddr = SOS_STACK;
    for (int i = 0; i < SOS_STACK_PAGES; i++) {
        seL4_CPtr frame_cap;
        ut_t *frame = alloc_retype(&frame_cap, seL4_ARM_SmallPageObject, seL4_PageBits);
        ZF_LOGF_IF(frame == NULL, "Failed to allocate stack page");
        seL4_Error err = map_frame(&cspace, frame_cap, seL4_CapInitThreadVSpace,
                                   vaddr, seL4_AllRights, seL4_ARM_Default_VMAttributes);
        ZF_LOGF_IFERR(err, "Failed to map stack");
        vaddr += PAGE_SIZE_4K;
    }

    utils_run_on_stack((void *) vaddr, main_continued, NULL);

    UNREACHABLE();
}


