#pragma once

#include <stdint.h>
#include <assert.h>
#include <sel4/sel4.h>

extern uintptr_t main_ipc_buff;

inline static bool is_main_thread(void) {
    return seL4_GetIPCBuffer() == main_ipc_buff;
}

inline static void assert_main_thread(void) {
    assert(is_main_thread());
}

inline static void assert_non_main_thread(void) {
    assert(!is_main_thread());
}
