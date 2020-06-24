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

#include "grp01.h"
#include "grp01/dynaarray.h"

// GRP01: M1
#include "libclocktest.h"
#include "fakes/timer.h"
// GRP01: M2
#include "fs/console.h"
#include "fileman.h"
#include "bgworker.h"
#include "timesyscall.h"
// GRP01: M3
#include "vm/mapping2.h"
#include "vm/addrspace.h"
#include "vm/syshandlers.h"
#include "vm/faulthandler.h"

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
#define INITIAL_PROCESS_EXTRA_STACK_PAGES 16

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

/* process table */
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

proctable_t proctable[MAX_PID];

void handle_syscall(seL4_Word badge, seL4_CPtr reply, ut_t* reply_ut)
{

    /* get the first word of the message, which in the SOS protocol is the number
     * of the SOS "syscall". */
    seL4_Word syscall_number = seL4_GetMR(0);

    // store whatever the handler returns, and pass to app if non zero.
    seL4_Word handler_ret = ENOSYS;

    // check if badge corresponds to a valid process table entry
    proctable_t* pt = NULL;
    if(badge == 0 || badge >= MAX_PID) {
        handler_ret = ESRCH;
        goto finish;
    }
    else {
        pt = proctable + badge;
        if(!pt->active) {
            handler_ret = ESRCH;
            goto finish;
        }
    }

    /* Process system call */
    switch (syscall_number) {
    case SOS_SYSCALL_OPEN:
        // hard limit for string values
        if(seL4_GetMR(1) >= PAGE_SIZE_4K)
            handler_ret = ENAMETOOLONG * -1;
        else {
            char * fn = frame_data(pt->ipc_buffer2_frame);
            fn[seL4_GetMR(1)] = 0;
            handler_ret = fileman_open(badge, reply, reply_ut, fn, seL4_GetMR(2));
        }
        break;
    
    case SOS_SYSCALL_CLOSE:
        handler_ret = fileman_close(badge, reply, reply_ut, seL4_GetMR(1));
        break;
    
    case SOS_SYSCALL_READ:
        if(seL4_GetMR(1) >= PAGE_SIZE_4K)
            handler_ret = EMSGSIZE * -1;
        else
            handler_ret = fileman_read(badge, seL4_GetMR(1), reply, reply_ut, 
                frame_data(pt->ipc_buffer2_frame), seL4_GetMR(2));
        break;

    case SOS_SYSCALL_WRITE:
        if(seL4_GetMR(1) >= PAGE_SIZE_4K)
            handler_ret = EMSGSIZE * -1;
        else 
            handler_ret = fileman_write(badge, seL4_GetMR(1), reply, reply_ut, 
                frame_data(pt->ipc_buffer2_frame), seL4_GetMR(2));
        break;

    case SOS_SYSCALL_BRK:
        handler_ret = handle_brk(&pt->as, seL4_GetMR(1));
        break;

    case SOS_SYSCALL_USLEEP:
        handler_ret = ts_usleep(seL4_GetMR(1), reply, reply_ut);
        break;
    
    case SOS_SYSCALL_TIMESTAMP:
        handler_ret = ts_get_timestamp();
        break;

    case SOS_SYSCALL_UNIMPLEMENTED:
        // just print this message as specified :)
        puts("system call not implemented");
        handler_ret = 1;
        break;
        
    default:
        ZF_LOGE("Unknown syscall %lu\n", syscall_number);
    }

    // reply if handler_ret is not 0. otherwise, we assume that the handler will
    // reply at some later point
finish:
    if(handler_ret) {
        seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, handler_ret);
        seL4_Send(reply, reply_msg);
        /* in MCS kernel, reply object is meant to be reused rather than freed */
        // however, for this version, we'll delete them manually to simplify things
        cspace_delete(&cspace, reply);
        cspace_free_slot(&cspace, reply);
        ut_free(reply_ut);
    }
}

void handle_fault(seL4_Word badge, seL4_MessageInfo_t message, seL4_CPtr reply, ut_t* reply_ut)
{
    seL4_Fault_tag_t fault = seL4_MessageInfo_get_label(message);
    char msgbuff[32];

    bool resume = false;

    if(badge >= 1 && badge < MAX_PID) {
        proctable_t* pt = proctable + badge;
        // must be from our processes!
        if(!pt->active) {
            snprintf(msgbuff, sizeof(msgbuff)-1, "invalid_%lu", badge);
            ZF_LOGE("Received invalid fault with badge: %ld", badge);
            debug_print_fault(message, msgbuff);
        } else {
            switch(fault) {
                case seL4_Fault_NullFault:
                    break;
                case seL4_Fault_VMFault:
                    // if vm_fault returns false, vm_fault will debug print the cause instead :)
                    if(vm_fault(&message, badge, pt->vspace, &pt->as))
                        resume = true;
                    break;
                default:
                    snprintf(msgbuff, sizeof(msgbuff)-1, "proc_%lu", badge);
                    debug_print_fault(message, msgbuff);
                    ZF_LOGE("Fault not handled. Offending thread will be suspended indefinitely.");
                    break;
            }
        }
    } else {
        debug_print_fault(message, "unknown_thread");
        ZF_LOGE("This fault will not be handled!");
    }

    if(resume) {
        seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 0);
        seL4_Send(reply, msg);
        cspace_delete(&cspace, reply);
        cspace_free_slot(&cspace, reply);
        ut_free(reply_ut);
    }
}

NORETURN void syscall_loop(seL4_CPtr ep)
{
    seL4_CPtr reply = 0;
    ut_t * reply_ut = NULL;

    while (1) {
        /* Create reply object */
        // we'll need to realloc a new reply object, as the old one may take a while
        // to be replied and we have to serve new requests.
        // only reallocate reply object if the previous code path didn't use it
        if(!reply_ut) {
            reply_ut = alloc_retype(&reply, seL4_ReplyObject, seL4_ReplyBits);
            if (reply_ut == NULL) {
                ZF_LOGF("Failed to alloc reply object ut");
            }
        }

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
            // pass the reply_ut also so that we can tell ut that the reply object is no
            // longer used
            handle_syscall(badge, reply, reply_ut);
            // indicate to the next loop that we used this reply object
            reply_ut = NULL;
        } else {
            handle_fault(badge, message, reply, reply_ut);
            // indicate to the next loop that we used this reply object
            reply_ut = NULL;
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
static uintptr_t init_process_stack(seL4_Word badge, cspace_t *cspace, seL4_CPtr local_vspace, elf_t *elf_file)
{
    // we assume that caller give the sane badge value here!
    proctable_t* pt = proctable + badge;

    // create the stack region
    addrspace_t stackas;
    stackas.end = PROCESS_STACK_TOP;
    stackas.begin = PROCESS_STACK_TOP - INITIAL_PROCESS_EXTRA_STACK_PAGES * PAGE_SIZE_4K;
    stackas.perm = seL4_CapRights_new(false, false, true, true);
    stackas.attr.type = AS_NORMAL;

    // map this stack region to process' address space
    if(addrspace_add(&pt->as, stackas) != AS_ADD_NOERR) {
        ZF_LOGE("Error adding stack address space region to process.");
        return 0;
    }

    /* Create a stack frame */
    frame_ref_t initial_stack = alloc_frame();
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
    seL4_Error err = grp01_map_frame(badge, initial_stack, true, pt->vspace,
                               PROCESS_STACK_TOP - PAGE_SIZE_4K, seL4_AllRights, 
                               seL4_ARM_Default_VMAttributes);
    if (err != 0) {
        ZF_LOGE("Unable to map stack for user app");
        return 0;
    }

    int index = -2;
    void *local_stack_top = frame_data(initial_stack) + PAGE_SIZE_4K;

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

/* Start the first process, and return true if successful
 *
 * This function will leak memory if the process does not start successfully.
 * TODO: avoid leaking memory once you implement real processes, otherwise a user
 *       can force your OS to run out of memory by creating lots of failed processes.
 */
bool start_first_process(char *app_name, seL4_CPtr ep)
{
    // find process table to use. right now it is hardcoded!
    proctable_t* pt = proctable + TTY_EP_BADGE;
    pt->active = true;

    // initialize some data structure
    dynarray_init(&pt->as, sizeof(addrspace_t));
    
    /* Create a VSpace */
    pt->vspace_ut = alloc_retype(&pt->vspace, seL4_ARM_PageGlobalDirectoryObject,
                                              seL4_PGDBits);
    if (pt->vspace_ut == NULL) {
        return false;
    }

    // create mapping bookkeeping object for vspace
    ZF_LOGF_IF(!grp01_map_init(TTY_EP_BADGE, pt->vspace), "Error allocating mapping bookkepping object.");

    /* assign the vspace to an asid pool */
    seL4_Error err = seL4_ARM_ASIDPool_Assign(seL4_CapInitThreadASIDPool, pt->vspace);
    if (err != seL4_NoError) {
        ZF_LOGE("Failed to assign asid pool");
        return false;
    }

    /* Create a simple 1 level CSpace */
    int cerr = cspace_create_one_level(&cspace, &pt->cspace);
    if (cerr != CSPACE_NOERROR) {
        ZF_LOGE("Failed to create cspace");
        return false;
    }

    /* Create an IPC buffer */
    pt->ipc_buffer_frame = alloc_frame();
    if (pt->ipc_buffer_frame == 0) {
        ZF_LOGE("Failed to alloc ipc buffer frame");
        return false;
    }
    // create 2nd IPC buffer for passing large data
    pt->ipc_buffer2_frame = alloc_frame();
    if(pt->ipc_buffer2_frame == 0) {
        ZF_LOGE("Failed to alloc large ipc buffer");
    }
    
    /* allocate a new slot in the target cspace which we will mint a badged endpoint cap into --
     * the badge is used to identify the process, which will come in handy when you have multiple
     * processes. */
    seL4_CPtr user_ep = cspace_alloc_slot(&pt->cspace);
    if (user_ep == seL4_CapNull) {
        ZF_LOGE("Failed to alloc user ep slot");
        return false;
    }

    /* now mutate the cap, thereby setting the badge */
    err = cspace_mint(&pt->cspace, user_ep, &cspace, ep, seL4_AllRights, TTY_EP_BADGE);
    if (err) {
        ZF_LOGE("Failed to mint user ep");
        return false;
    }

    /* Create a new TCB object */
    pt->tcb_ut = alloc_retype(&pt->tcb, seL4_TCBObject, seL4_TCBBits);
    if (pt->tcb_ut == NULL) {
        ZF_LOGE("Failed to alloc tcb ut");
        return false;
    }

    /* Configure the TCB */
    // TODO: GRP01: if not working, copy cap to tty_test's cspace!
    // GRP01: test
    seL4_CPtr pipcb = cspace_alloc_slot(&cspace);
    err = cspace_copy(&cspace, pipcb, frame_table_cspace(), frame_page(pt->ipc_buffer_frame), seL4_AllRights);
    err = seL4_TCB_Configure(pt->tcb,
                             pt->cspace.root_cnode, seL4_NilData,
                             pt->vspace, seL4_NilData, PROCESS_IPC_BUFFER,
                             pipcb);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure new TCB");
        return false;
    }

    /* Create scheduling context */
    pt->sched_context_ut = alloc_retype(&pt->sched_context, seL4_SchedContextObject,
                                                     seL4_MinSchedContextBits);
    if (pt->sched_context_ut == NULL) {
        ZF_LOGE("Failed to alloc sched context ut");
        return false;
    }

    /* Configure the scheduling context to use the first core with budget equal to period */
    err = seL4_SchedControl_Configure(sched_ctrl_start, pt->sched_context, US_IN_MS, US_IN_MS, 0, 0);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure scheduling context");
        return false;
    }

    // badged fault endpoint
    seL4_CPtr fault_ep = cspace_alloc_slot(&cspace);
    if(fault_ep == seL4_CapNull) {
        ZF_LOGE("Unable to create slot for badged fault endpoint");
        return false;
    }
    err = cspace_mint(&cspace, fault_ep, &cspace, ep, seL4_AllRights, TTY_EP_BADGE);
    if(err != seL4_NoError) {
        ZF_LOGE("Error minting fault endpoint: %d", err);
        return false;
    }

    /* bind sched context, set fault endpoint and priority
     * In MCS, fault end point needed here should be in current thread's cspace.
     * NOTE this will use the unbadged ep unlike above, you might want to mint it with a badge
     * so you can identify which thread faulted in your fault handler */
    err = seL4_TCB_SetSchedParams(pt->tcb, seL4_CapInitThreadTCB, seL4_MinPrio, TTY_PRIORITY,
                                  pt->sched_context, fault_ep);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to set scheduling params");
        return false;
    }

    /* Provide a name for the thread -- Helpful for debugging */
    NAME_THREAD(pt->tcb, app_name);

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
    seL4_Word sp = init_process_stack(TTY_EP_BADGE, &cspace, seL4_CapInitThreadVSpace, &elf_file);

    /* load the elf image from the cpio file */
    // also pass the address space region dynamic array
    err = elf_load(TTY_EP_BADGE, &cspace, pt->vspace, &elf_file, &pt->as);
    if (err) {
        ZF_LOGE("Failed to load elf image");
        return false;
    }

    /* Map in the IPC buffer for the thread */
    err = grp01_map_frame(TTY_EP_BADGE, pt->ipc_buffer_frame, true, pt->vspace, PROCESS_IPC_BUFFER,
                    seL4_AllRights, seL4_ARM_Default_VMAttributes);
    if (err != 0) {
        ZF_LOGE("Unable to map IPC buffer for user app");
        return false;
    }

    // extra page for large data that has to be passed thru IPC
    err = grp01_map_frame(TTY_EP_BADGE, pt->ipc_buffer2_frame, true, pt->vspace, PROCESS_IPC_BUFFER + PAGE_SIZE_4K,
                    seL4_AllRights, seL4_ARM_Default_VMAttributes);
    if (err != 0) {
        ZF_LOGE("Unable to map larger IPC buffer for user app");
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
    err = seL4_TCB_WriteRegisters(pt->tcb, 1, 0, 2, &context);
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
    grp01_map_bookkeep_init();
    memset(proctable, 0, sizeof(proctable));

    /* run sos initialisation tests */
    run_tests(&cspace);

    /* Map the timer device (NOTE: this is the same mapping you will use for your timer driver -
     * sos uses the watchdog timers on this page to implement reset infrastructure & network ticks,
     * so touching the watchdog timers here is not recommended!) */
    void *timer_vaddr = sos_map_device(&cspace, PAGE_ALIGN_4K(TIMER_MAP_BASE), PAGE_SIZE_4K);

    /* Initialise the network hardware. (meson ethernet for now) */
    #ifdef CONFIG_PLAT_ODROIDC2
    // TODO: reenable ethernet (this is disabled to make debugging quicker)
    printf("Network init\n");
    network_init(&cspace, timer_vaddr, ntfn);
    #endif

    /* Initialises the timer */
    printf("Timer init\n");
    start_timer(timer_vaddr);
    /* You will need to register an IRQ handler for the timer here.
     * See "irq.h". */

    // init file systems
    console_fs_init();

    /* Start the user application */
    printf("Start first process\n");
    bool success = start_first_process(TTY_NAME, ipc_ep);
    ZF_LOGF_IF(!success, "Failed to start first process");

    printf("\nSOS entering syscall loop\n");
    init_threads(ipc_ep, sched_ctrl_start, sched_ctrl_end);

    // start anything that have to run separate threads here
    bgworker_init();
    //start_fake_timer();

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


