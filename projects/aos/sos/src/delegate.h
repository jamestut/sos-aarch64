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

frame_ref_t delegate_alloc_frame(void);

void delegate_free_frame(frame_ref_t frame_ref);

bool delegate_frame_set_pin(frame_ref_t frame_ref, bool pin);

void* delegate_frame_data(frame_ref_t frame_ref);

seL4_Error delegate_map_frame(seL4_Word badge, frame_ref_t frameref, bool free_frame_on_delete, bool unpin_on_unmap,
                     seL4_Word vaddr, seL4_CapRights_t rights, seL4_ARM_VMAttributes attr);

frame_ref_t delegate_get_frame(seL4_Word badge, seL4_Word vaddr);

uintptr_t delegate_allocate_sos_scratch(size_t size);

bool delegate_file_backed_sos_map(sos_filehandle_t* fh, uintptr_t base, size_t size_bytes);

void delegate_free_sos_scratch(uintptr_t base);

void delegate_destroy_process(seL4_CPtr pid);
