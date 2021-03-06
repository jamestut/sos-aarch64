#include "proctable.h"
#include <assert.h>
#include <grp01/bitfield.h>

proctable_t proctable[CONFIG_SOS_MAX_PID] = {0};

static sos_pid_t free_pt_clockhand = 0;

// for faster free lookup
uint64_t proctable_bf[CONFIG_SOS_MAX_PID/sizeof(uint64_t)] = {0};

sos_pid_t find_free_pid(void) {
    for(int ret = 0; ret < CONFIG_SOS_MAX_PID; ++ret) {
        free_pt_clockhand = (free_pt_clockhand + 1) % CONFIG_SOS_MAX_PID;
        if(!proctable[free_pt_clockhand].active) 
            return free_pt_clockhand;
    }
    return INVALID_PID;
}

void set_pid_state(sos_pid_t pid, bool active) {
    // assume that pid passed here is correct!
    assert(proctable[pid].active != active);
    proctable[pid].active = active;
    TOGGLE_BMP(proctable_bf, pid);
}
