#pragma once

// all function calls here will be delegated to main thread
// by the means of using IPC request

#include <stddef.h>
#include <sel4/sel4.h>
#include "grp01.h"
#include "vm/mapping2.h"

// to be called by main!
void handle_delegate_req(seL4_Word badge, seL4_Word msglen, seL4_CPtr reply, ut_t* reply_ut);

// ---- non main threads should call these functions (those that begins w/ delegate_) ----
void delegate_do_nothing(seL4_CPtr ep);

void* delegate_malloc(seL4_CPtr ep, size_t sz);

void delegate_free(seL4_CPtr ep, void* ptr);

void* delegate_userptr_read(seL4_CPtr ep, userptr_t src, size_t len, seL4_Word badge, seL4_CPtr vspace);

userptr_write_state_t delegate_userptr_write_start(seL4_CPtr ep, userptr_t src, size_t len, dynarray_t* userasarr, seL4_Word badge, seL4_CPtr vspace);

bool delegate_userptr_write_next(seL4_CPtr ep, userptr_write_state_t* it);

void delegate_userptr_unmap(seL4_CPtr ep, void* sosaddr);

void delegate_free_cap(seL4_CPtr ep, seL4_CPtr cap, bool del_cap, bool free_slot);

void delegate_free_ut(seL4_CPtr ep, ut_t* ut);
