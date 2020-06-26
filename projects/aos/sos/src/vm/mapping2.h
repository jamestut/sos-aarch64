#pragma once

#include <stdbool.h>
#include <sel4/sel4.h>
#include <cspace/cspace.h>
#include "../frame_table.h"
#include "../grp01.h"

// initialize mapping with bookkeeping
void grp01_map_bookkeep_init(void);

// Initialize a bookeeping structure for mapping frames.
bool grp01_map_init(seL4_Word badge, seL4_CPtr vspace);

// destroy the bookeeping structure for mapping frames, as well as destroying 
// the intermediate page tables created by the grp01_map_frame function.
void grp01_map_destroy(seL4_Word badge);

// map a frame given by the frame capability to the given vspace, on SOS' behalf (SOS' cspace).
// @return 0 on success
seL4_Error grp01_map_frame(seL4_Word badge, frame_ref_t frameref, bool free_frame_on_delete, seL4_CPtr vspace, seL4_Word vaddr, seL4_CapRights_t rights,
                     seL4_ARM_VMAttributes attr);

// unmap a virtual address range from vspace.
// @param vaddrbegin page-aligned beginning of the frame to unmap
// @param vaddrend   page-aligned end of the frame to unmap, exclusive
seL4_Error grp01_unmap_frame(seL4_Word badge, seL4_CPtr vspace, seL4_Word vaddrbegin, seL4_Word vaddrend);

// @return 0 on lookup failure (e.g. wrong region / unmapped frame)
frame_ref_t grp01_get_frame(seL4_Word badge, seL4_CPtr vspace, seL4_Word vaddr);

// @return 0 on failure, or pointer to the beginning of the buffer on success
void* userptr_read(userptr_t src, size_t len, seL4_Word badge, seL4_CPtr vspace);

void userptr_unmap(void* sosaddr);
