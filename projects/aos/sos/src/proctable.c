#include "proctable.h"
#include <assert.h>
#include <grp01/bitfield.h>

proctable_t proctable[MAX_PID] = {0};

static int free_pt_clockhand = 0;

// for faster free lookup
uint64_t proctable_bf[MAX_PID/sizeof(uint64_t)] = {0};

int find_free_pid(void) {
    for(int ret = 0; ret < MAX_PID; ++ret) {
        free_pt_clockhand = (free_pt_clockhand + 1) % MAX_PID;
        if(!proctable[free_pt_clockhand].active) 
            return free_pt_clockhand;
    }
    return -1;
}

void set_pid_state(seL4_Word pid, bool active) {
    // assume that pid passed here is correct!
    assert(proctable[pid].active != active);
    proctable[pid].active = active;
    TOGGLE_BMP(proctable_bf, pid);
}
