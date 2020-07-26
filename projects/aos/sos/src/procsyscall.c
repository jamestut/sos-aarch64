#include "procsyscall.h"
#include "proctable.h"
#include "vm/mapping2.h"
#include <sos.h>
#include <errno.h>
#include <utils/arith.h>

static bool proclist_valid = false;
static uint32_t proclist_count = 0;
static sos_process_t proclist[MAX_PID];

void refresh_proclist(void);

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
