#include "procsyscall.h"
#include "proctable.h"
#include "procman.h"
#include "bgworker.h"
#include "delegate.h"
#include "utils.h"
#include "vm/mapping2.h"
#include <sos.h>
#include <errno.h>
#include <utils/arith.h>
#include <sos/gen_config.h>
#include <grp01/bitfield.h>

static bool proclist_valid = false;
static uint32_t proclist_count = 0;
static sos_process_t proclist[CONFIG_SOS_MAX_PID];
static seL4_CPtr io_finish_ep;

extern waitee_any_node_t waitee_any[CONFIG_SOS_MAX_PID];

struct user_start_process_bg_param {
    seL4_CPtr reply;
    sos_pid_t pid;
    uint16_t filename_termpos;
    char filename_term;
};

_Static_assert(BIT(sizeof(uint16_t)*8) > CONFIG_SOS_MAX_FILENAME, "Filename length must fit in uint16_t");

void refresh_proclist(void);

void user_start_process_bg(void* param);

void proc_syscall_init(cspace_t* srccspace, seL4_CPtr ipc_ep)
{
    io_finish_ep = cspace_alloc_slot(&cspace);
    ZF_LOGF_IF(!io_finish_ep, "Cannot allocate slot for endpoint");
    ZF_LOGF_IF(cspace_mint(&cspace, io_finish_ep, srccspace, ipc_ep, seL4_AllRights, BADGE_IO_FINISH) != seL4_NoError,
        "Error minting endpoint");
}

int proc_list(seL4_Word pid, userptr_t dest, size_t buffcount)
{
    assert(pid < CONFIG_SOS_MAX_PID);

    int ret;
    if(!proclist_valid)
        refresh_proclist();

    uint32_t objectcount = MIN(proclist_count, buffcount);
    uint32_t size = objectcount * sizeof(sos_process_t);

    userptr_write_state_t it = userptr_write_start(dest, size, pid);
    if(!it.curr) 
        return -EFAULT;
    void* startptr = it.curr;

    uint8_t* src = proclist;

    while(it.curr) {
        memcpy((void*)it.curr, src, it.remcurr);
        src += it.remcurr;
        if(!userptr_write_next(&it)) {
            ret = -EFAULT;
            break;
        }
    }
    userptr_unmap(startptr);

    ret = objectcount;
    return ret;
}

int user_new_proc(seL4_Word pid, userptr_t p_filename, size_t p_filename_len, seL4_CPtr reply)
{
    assert(pid < CONFIG_SOS_MAX_PID);

    char originalterm;
    char* filename = map_user_string(p_filename, p_filename_len, pid, &originalterm);
    if(!filename)
        return -EFAULT;
    
    int newpid;
    newpid = create_process(pid, filename);
    assert(newpid);
    if(newpid < 0)
        goto error;

    // schedule background worker to proceed loading ELF
    struct user_start_process_bg_param* param = malloc(sizeof(struct user_start_process_bg_param));
    if(!param)
        goto error;
    
    param->pid = newpid;
    param->reply = reply;
    param->filename_term = originalterm;
    param->filename_termpos = p_filename_len;

    bgworker_enqueue_callback(pid, user_start_process_bg, param);
    return 0;

error: // go here if error after successfully mapped user string
    filename[p_filename_len - 1] = originalterm;
    userptr_unmap(filename);
    return -ESRCH;
}

seL4_Word user_delete_proc(seL4_Word targetpid)
{
    if(!targetpid || targetpid >= CONFIG_SOS_MAX_PID)
        return -ESRCH;
    
    proctable_t* pt = proctable + targetpid;
    if(!pt->active)
        return -ESRCH;

    // process destruction might be pending because the target process is doing IO
    // however, even in such cases, we will return back ASAP to the calling process.
    destroy_process(targetpid);

    return 1;
}

seL4_Word user_wait_proc(seL4_Word badge, seL4_Word targetpid_, seL4_CPtr reply)
{
    sos_pid_t targetpid = (int64_t)targetpid_;
    if(!targetpid || targetpid >= CONFIG_SOS_MAX_PID)
        return -ESRCH;

    // set target
    if(targetpid < 0) {
        // any
        waitee_any_node_t* owner = waitee_any + badge; 
        waitee_any_node_t* tail = waitee_any + waitee_any->prev;
        waitee_any->prev = tail->next = badge;
        owner->next = 0;
        owner->prev = waitee_any->prev;
    } else {
        // targetted
        proctable_t* pt = proctable + targetpid;
        if(!pt->active)
            return -ESRCH;
        assert(!GET_BMP(pt->waitee_list, badge));
        TOGGLE_BMP(pt->waitee_list, badge);
    }

    // set this process as a waitee
    proctable_t* mypt = proctable + badge;
    mypt->wait_target = targetpid;
    mypt->waitee_reply = reply;
    return 0;
}

void invalidate_proc_list_cache()
{
    proclist_valid = false;
}

void refresh_proclist()
{
    proclist_count = 0;
    for(uint32_t i = 0; i < CONFIG_SOS_MAX_PID; ++i) {
        proctable_t* pt = proctable + i;
        if(pt->active) {
            sos_process_t* pl = proclist + proclist_count++;
            pl->pid = i;
            strncpy(pl->command, pt->command, N_NAME - 1);
            pl->command[N_NAME - 1] = 0;
            pl->size = pt->file_size;
            pl->stime = pt->start_msec;
        }
    }
    proclist_valid = true;
}

void user_start_process_bg(void* pparam)
{
    struct user_start_process_bg_param* param = pparam;
    proctable_t* pt = proctable + param->pid;
    bool success = start_process_load_elf(param->pid);

    pt->loader_state.filename[param->filename_termpos - 1] = param->filename_term;
    delegate_userptr_unmap(pt->loader_state.filename);
    
    if(!success)
        delegate_destroy_process(param->pid);

    seL4_CPtr reply = param->reply;
    uint32_t newpid = param->pid;
    free(param);

    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, success ? newpid : -ESRCH);
    seL4_Send(reply, msg);

    delegate_reuse_reply(reply);

    if(pt->state_flag & PROC_STATE_PENDING_KILL) {
        seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, param->pid);
        seL4_Call(io_finish_ep, msg);
    }
}