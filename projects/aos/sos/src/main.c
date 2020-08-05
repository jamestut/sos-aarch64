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
#include <sos/gen_config.h>
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
#include <serial/serial.h>

#include <sel4runtime.h>
#include <sel4runtime/auxv.h>

#include <sync/mutex.h>

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
#include "threadassert.h"
#include "grp01/dynaarray.h"
#include "fs/fake.h"
#include "fs/cpiofs.h"

// GRP01: M1
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
// GRP01: M4
#include "delegate.h"
#include "fs/nfs.h"
// GRP01: rearch
#include "proctable.h"
// GRP01: M6
#include "procman.h"
#include "procsyscall.h"
#include "maininterface.h"

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

#define FIRST_PROC_NAME             "sosh"

/* The linker will link this symbol to the start address  *
 * of an archive of attached applications.                */
extern char _cpio_archive[];
extern char _cpio_archive_end[];
extern char __eh_frame_start[];
/* provided by gcc */
extern void (__register_frame)(void *);

/* root tasks cspace */
cspace_t cspace;

/* scratch address space */
dynarray_t scratchas;

static seL4_CPtr sched_ctrl_start;
static seL4_CPtr sched_ctrl_end;

// for debugging
uintptr_t main_ipc_buff;

// reply objects
#define REPLY_OBJ_COUNT ((CONFIG_SOS_MAX_PID)*2)
#define REPLY_POS_INC(x) (((x) + 1) % REPLY_OBJ_COUNT)
#define REPLY_OBJ_FULL (REPLY_POS_INC(replyobjs.prodpos) == replyobjs.conspos)
#define REPLY_OBJ_EMPTY (replyobjs.prodpos == replyobjs.conspos)

struct {
    seL4_CPtr data[REPLY_OBJ_COUNT];
    uint16_t prodpos;
    uint16_t conspos;
} replyobjs = {0};

bool handle_syscall(seL4_Word badge, seL4_Word msglen, seL4_CPtr reply)
{

    /* get the first word of the message, which in the SOS protocol is the number
     * of the SOS "syscall". */
    seL4_Word syscall_number = seL4_GetMR(0);

    // store whatever the handler returns, and pass to app if non zero.
    seL4_Word handler_ret = ENOSYS;

    // check if badge corresponds to a valid process table entry
    proctable_t* pt = NULL;
    if(badge == 0 || badge >= CONFIG_SOS_MAX_PID) {
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
        handler_ret = fileman_open(badge, reply, 
            seL4_GetMR(1), seL4_GetMR(2), false, seL4_GetMR(3));
        break;
    
    case SOS_SYSCALL_CLOSE:
        handler_ret = fileman_close(badge, reply, seL4_GetMR(1));
        break;
    
    case SOS_SYSCALL_READ:
        handler_ret = fileman_read(badge, seL4_GetMR(1), reply, 
            seL4_GetMR(2), seL4_GetMR(3));
        break;

    case SOS_SYSCALL_WRITE: 
        handler_ret = fileman_write(badge, seL4_GetMR(1), reply, 
            seL4_GetMR(2), seL4_GetMR(3));
        break;

    case SOS_SYSCALL_STAT:
        handler_ret = fileman_stat(badge, reply, seL4_GetMR(1),
            seL4_GetMR(2));
        break;

    case SOS_SYSCALL_OPENDIR:
        handler_ret = fileman_open(badge, reply, 
            seL4_GetMR(1), seL4_GetMR(2), true, 0);
        break;

    case SOS_SYSCALL_DIRREAD:
        handler_ret = fileman_readdir(badge, seL4_GetMR(1), reply,
            seL4_GetMR(2), seL4_GetMR(3), seL4_GetMR(4));
        break;

    case SOS_SYSCALL_MMAP:
        handler_ret = handle_mmap(&pt->as, seL4_GetMR(1), seL4_GetMR(2), seL4_GetMR(3), 
            seL4_GetMR(4), seL4_GetMR(5), seL4_GetMR(6));
        break;

    case SOS_SYSCALL_MUNMAP:
        handler_ret = handle_munmap(&pt->as, badge, pt->vspace, seL4_GetMR(1), seL4_GetMR(2));
        break;

    case SOS_SYSCALL_BRK:
        handler_ret = handle_brk(&pt->as, badge, pt->vspace, seL4_GetMR(1));
        break;

    case SOS_SYSCALL_GROW_STACK:
        handler_ret = handle_grow_stack(&pt->as, badge, pt->vspace, seL4_GetMR(1));
        break;

    case SOS_SYSCALL_USLEEP:
        handler_ret = ts_usleep(seL4_GetMR(1), reply);
        break;
    
    case SOS_SYSCALL_TIMESTAMP:
        handler_ret = ts_get_timestamp();
        break;

    case SOS_SYSCALL_MY_ID:
        handler_ret = badge;
        break;

    case SOS_SYSCALL_LIST_PROC:
        handler_ret = proc_list(badge, seL4_GetMR(1), seL4_GetMR(2));
        break;

    case SOS_SYSCALL_PROC_NEW:
        handler_ret = user_new_proc(badge, seL4_GetMR(1), seL4_GetMR(2), reply);
        break;

    case SOS_SYSCALL_PROC_DEL:
        handler_ret = user_delete_proc(seL4_GetMR(1));
        break;

    case SOS_SYSCALL_WAITPID:
        handler_ret = user_wait_proc(badge, seL4_GetMR(1), reply);
        break;

    case SOS_SYSCALL_UNIMPLEMENTED:
        // just print this message as specified :)
        puts("system call not implemented");
        handler_ret = ENOSYS;
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
    }
    // if we've replied, returns true, so that syscall_loop knows that it can reuse the 
    // reply object
    return handler_ret;
}

void handle_fault(seL4_Word badge, seL4_MessageInfo_t message, seL4_CPtr reply)
{
    seL4_Fault_tag_t fault = seL4_MessageInfo_get_label(message);
    char msgbuff[32];
    snprintf(msgbuff, sizeof(msgbuff)-1, "thrd_badge_%lu", badge);

    bool resume = false;

    if(badge >= 1 && badge < CONFIG_SOS_MAX_PID) {
        proctable_t* pt = proctable + badge;
        // must be from our processes!
        if(!pt->active) {
            snprintf(msgbuff, sizeof(msgbuff)-1, "invalid_%lu", badge);
            ZF_LOGE("Received invalid fault with badge: %ld", badge);
            debug_print_fault(message, msgbuff);
        } else {
            switch(fault) {
                case seL4_Fault_NullFault:
                    resume = true;
                    break;
                case seL4_Fault_VMFault:
                    // if vm_fault returns false, vm_fault will debug print the cause instead :)
                    if(vm_fault(&message, badge))
                        resume = true;
                    break;
                default:
                    debug_print_fault(message, msgbuff);
                    ZF_LOGW("Received fault %d from process %d, which is not handled.", fault, badge);
                    break;
            }
        }
    } else if (badge == 0) {
        // special case if SOS itself is faulting
        switch(fault) {
            case seL4_Fault_NullFault:
                resume = true;
                break;
            case seL4_Fault_VMFault:
                if(!sos_vm_fault(&message))
                    ZF_LOGF("Unhandled VM fault on SOS thread");
                resume = true;
                break;
            default:
                ZF_LOGF("Unknown SOS fault: %d", fault);
        }
    } else {
        debug_print_fault(message, msgbuff);
        ZF_LOGF("Unknown fault from badge %d. Don't know what to do!", badge);
    }

    if(resume) {
        seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 0);
        seL4_Send(reply, msg);
    } else {
        if(!badge) {
            // this means that one of our thread is faulting. this is fatal!
            ZF_LOGF("SOS thread unhandled fault. Aborting.");
        } else {
            printf("Process %d will be killed.\n", badge);
            destroy_process(badge);
        }
    }
}

NORETURN void syscall_loop(seL4_CPtr ep)
{
    // cons == prod     : empty
    // prod == cons - 1 : full
    replyobjs.prodpos = REPLY_OBJ_COUNT - 1;
    replyobjs.conspos = 0; 

    while (1) {
        // it is impossible that the reply object is full, as there is at most
        // number of processes + 1 outstanding threads. all background thread handlers
        // are expected to return the reply object after they finished.
        ZF_LOGF_IF(REPLY_OBJ_EMPTY, "Reply object array is empty @ syscall_loop!");

        /* Create reply object if needed */
        seL4_CPtr* reply = replyobjs.data + replyobjs.conspos;
        if(!*reply) 
            ZF_LOGF_IF(!alloc_retype(reply, seL4_ReplyObject, seL4_ReplyBits),
                "Cannot allocate reply object");
            
        seL4_Word badge = 0;
        /* Block on ep, waiting for an IPC sent over ep, or
         * a notification from our bound notification object */
        seL4_MessageInfo_t message = seL4_Recv(ep, &badge, *reply);
        /* Awake! We got a message - check the label and badge to
         * see what the message is about */
        seL4_Word label = seL4_MessageInfo_get_label(message);
        seL4_Word msglen = seL4_MessageInfo_get_length(message);

        if (badge & IRQ_EP_BADGE) {
            /* It's a notification from our bound notification
             * object! */
            sos_handle_irq_notification(&badge);
        } else if (label == seL4_Fault_NullFault) {
            switch(badge)
            {
                case BADGE_IO_FINISH:
                    ZF_LOGI("carrying on pending process destroy for PID %d", seL4_GetMR(0));
                    if(proctable[seL4_GetMR(0)].state_flag & PROC_STATE_PENDING_KILL)
                        proctable[seL4_GetMR(0)].state_flag ^= PROC_STATE_PENDING_KILL;
                    destroy_process(seL4_GetMR(0));
                    break;
                case BADGE_DELEGATE:
                    handle_delegate_req(badge, msglen, *reply);
                    break;
                case BADGE_REPLY_RET:
                    // we trust whoever send us this!
                    sos_reuse_reply(seL4_GetMR(0));
                    // reply!
                    message = seL4_MessageInfo_new(0, 0, 0, 0);
                    seL4_Send(*reply, message);
                    break;
                default:
                    // handle_syscall returns false if it needs the reply object later
                    if(!handle_syscall(badge, msglen, *reply)) 
                        replyobjs.conspos = REPLY_POS_INC(replyobjs.conspos);
            }
        } else {
            handle_fault(badge, message, *reply);
        }
    }
}

void sos_reuse_reply(seL4_CPtr reply)
{
    assert_main_thread();
    ZF_LOGF_IF(REPLY_OBJ_FULL, "Reply object array is full on REPLY_RET");
    replyobjs.data[replyobjs.prodpos] = reply;
    replyobjs.prodpos = REPLY_POS_INC(replyobjs.prodpos);
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

void scratchas_init(void)
{
    // preallocate scratchas
    dynarray_init(&scratchas, sizeof(addrspace_t));
    ZF_LOGF_IF(!dynarray_resize(&scratchas, 8), "Cannot allocate array for scratch address space.");
}

void start_first_process(void* param)
{
    seL4_Word pid = (proctable_t*)param - proctable;
    if(!start_process_load_elf(pid)) 
        ZF_LOGF("Failed to start initial process.");
}

NORETURN void *main_continued(UNUSED void *arg)
{
    main_ipc_buff = seL4_GetIPCBuffer();
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

    // fill in SOS' own process data!
    set_pid_state(0, true);
    proctable[0].vspace = seL4_CapInitThreadVSpace;
    strncpy(proctable[0].command, "<SOS system>", N_NAME);

    // GRP01: init OS parts here
    delegate_init(&cspace, ipc_ep);
    scratchas_init();
    fileman_init(&cspace, ipc_ep);
    init_threads(ipc_ep, sched_ctrl_start, sched_ctrl_end);
    init_process_starter(ipc_ep, sched_ctrl_start, sched_ctrl_end);
    proc_syscall_init(&cspace, ipc_ep);
    bgworker_init();
    start_fake_timer();
    grp01_map_bookkeep_init();
    grp01_map_init(0, seL4_CapInitThreadVSpace);

    /* run sos initialisation tests */
    run_tests(&cspace);

    /* Map the timer device (NOTE: this is the same mapping you will use for your timer driver -
     * sos uses the watchdog timers on this page to implement reset infrastructure & network ticks,
     * so touching the watchdog timers here is not recommended!) */
    void *timer_vaddr = sos_map_device(&cspace, PAGE_ALIGN_4K(TIMER_MAP_BASE), PAGE_SIZE_4K);

    /* Initialise the network hardware. (meson ethernet for now) */
    #ifdef CONFIG_PLAT_ODROIDC2
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
    cpio_fs_init();

    #if CONFIG_SOS_FAKE_PF > 0ul
    fake_fs_init(CONFIG_SOS_FAKE_PF_SIZE);
    #endif

    #if CONFIG_SOS_LOCAL_FS > 0ul
    #else
    grp01_nfs_init();
    #endif
    
    frame_table_init_page_file();

    // TBH this is here just for the sake of loading ELF/1st process!
    ZF_LOGF_IF(!bgworker_create(0), "Cannot create SOS background worker");

    /* Start the user application */
    printf("Start first process\n");

    int first_pid = create_process(0, FIRST_PROC_NAME);
    ZF_LOGF_IF(first_pid <= 0, "Failed to bootstrap initial process.");
    bgworker_enqueue_callback(0, start_first_process, proctable + first_pid);

    printf("\nSOS entering syscall loop\n");

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


