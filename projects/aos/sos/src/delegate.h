#pragma once

// all function whose name starts with delegate_ will IPC to main thread
// if called from a different thread, and performs the requested action there.

#include <stddef.h>
#include <sel4/sel4.h>
#include <sys/time.h>
#include <nfsc/libnfs.h>

#include "grp01.h"
#include "sel4/sel4_arch/types.h"
#include "vm/mapping2.h"

// to be called by main!
void delegate_init(cspace_t* srccspace, seL4_CPtr ipc_ep);

void handle_delegate_req(seL4_Word badge, seL4_Word msglen, seL4_CPtr reply);

// ---- non main threads should call these functions (those that begins w/ delegate_) ----
void delegate_do_nothing(void);

void* delegate_userptr_read(userptr_t src, size_t len, seL4_Word badge);

userptr_write_state_t delegate_userptr_write_start(userptr_t src, size_t len, seL4_Word badge);

bool delegate_userptr_write_next(userptr_write_state_t* it);

void delegate_userptr_unmap(void* sosaddr);

void delegate_free_cap(seL4_CPtr cap, bool del_cap, bool free_slot);

void delegate_free_ut(ut_t* ut);

void delegate_reuse_reply(seL4_CPtr reply);
