#include "procsyscall.h"
#include "proctable.h"
#include "procman.h"
#include "bgworker.h"
#include "delegate.h"
#include "vm/mapping2.h"
#include <sos.h>
#include <errno.h>
#include <utils/arith.h>

static bool proclist_valid = false;
static uint32_t proclist_count = 0;
static sos_process_t proclist[MAX_PID];

struct user_start_process_bg_param {
    seL4_CPtr reply;
    uint16_t pid;
    uint16_t filename_termpos;
    char filename_term;
};

_Static_assert(BIT(sizeof(uint16_t)*8) > MAX_FILENAME, "Filename length must fit in uint16_t");

void refresh_proclist(void);

void user_start_process_bg(void* param);

int proc_list(seL4_Word pid, userptr_t dest, size_t buffcount)
{
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
    if(!param) {
        destroy_process(newpid);
        goto error;
    }
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

void invalidate_proc_list_cache()
{
    proclist_valid = false;
}

void refresh_proclist()
{
    proclist_count = 0;
    for(uint32_t i = 0; i < MAX_PID; ++i) {
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
    
    if(!success)
        destroy_process(param->pid);

    pt->loader_state.filename[param->filename_termpos - 1] = param->filename_term;
    delegate_userptr_unmap(pt->loader_state.filename);

    seL4_CPtr reply = param->reply;
    uint32_t newpid = param->pid;
    free(param);

    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, success ? newpid : -ESRCH);
    seL4_Send(reply, msg);

    delegate_reuse_reply(reply);
}