#pragma once

#include "grp01.h"
#include <sel4/sel4.h>
#include <stdbool.h>

void init_process_starter(seL4_CPtr ep_, seL4_CPtr sched_ctrl_start_, seL4_CPtr sched_ctrl_end_);

// Find an empty PCB and bootstrap it. Returns PID if successful, or -1 if failed.
// The second stage must be executed if successful for the process creation
// to complete.
sos_pid_t create_process(sos_pid_t parent_pid, char *app_name);

// Load elf to the specified PCB and start process. Must be run from background thread so that main thread
// can load the chunks from ELF file upon page fault.
// @param parent_pid the parent of PID that wanted to start the process. This should match with 
//                   the background worker's ID that execute this function.
bool start_process_load_elf(sos_pid_t new_pid);

void destroy_process(sos_pid_t pid);
