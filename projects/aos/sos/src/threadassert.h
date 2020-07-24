#pragma once

#include <stdint.h>
#include <assert.h>
#include <sel4/sel4.h>

extern uintptr_t main_ipc_buff;

inline static void assert_main_thread(void) {
    assert(seL4_GetIPCBuffer() == main_ipc_buff);
}

inline static void assert_non_main_thread(void) {
    assert(seL4_GetIPCBuffer() != main_ipc_buff);
}
