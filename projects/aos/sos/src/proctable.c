#include "proctable.h"
#include <assert.h>
#include <grp01/bitfield.h>

proctable_t proctable[MAX_PID] = {0};

// for faster free lookup
uint64_t proctable_bf[MAX_PID/sizeof(uint64_t)] = {0};

int find_free_pid(void) {
    return bitfield_first_free(MAX_PID/sizeof(uint64_t), proctable_bf);
}

void set_pid_state(seL4_Word pid, bool active) {
    // assume that pid passed here is correct!
    assert(proctable[pid].active != active);
    proctable[pid].active = active;
    TOGGLE_BMP(proctable_bf, pid);
}
