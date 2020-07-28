#pragma once

#include "grp01.h"
#include <cspace/cspace.h>
#include <sel4/sel4.h>

void proc_syscall_init(cspace_t* srccspace, seL4_CPtr ipc_ep);

void invalidate_proc_list_cache();

int proc_list(seL4_Word pid, userptr_t dest, size_t buffcount);

int user_new_proc(seL4_Word pid, userptr_t p_filename, size_t p_filename_len, seL4_CPtr reply);

seL4_Word user_delete_proc(seL4_Word targetpid);
