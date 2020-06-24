#pragma once

#include <stdbool.h>
#include <sel4/sel4.h>
#include <cspace/cspace.h>

// initialize mapping with bookkeeping
void grp01_map_bookkeep_init(void);

// Initialize a bookeeping structure for mapping frames.
bool grp01_map_init(seL4_Word badge, seL4_CPtr vspace);

// destroy the bookeeping structure for mapping frames, as well as destroying 
// the intermediate page tables created by the grp01_map_frame function.
void grp01_map_destroy(seL4_Word badge);

// map a frame given by the frame capability to the given vspace, on SOS' behalf (SOS' cspace).
// @return 0 on success
seL4_Error grp01_map_frame(seL4_Word badge, seL4_CPtr frame_cap, seL4_CPtr vspace, seL4_Word vaddr, seL4_CapRights_t rights,
                     seL4_ARM_VMAttributes attr);
