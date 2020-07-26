#pragma once

#include "grp01.h"
#include <sel4/sel4.h>

void invalidate_proc_list_cache();

int proc_list(seL4_Word pid, userptr_t dest, size_t buffcount);
