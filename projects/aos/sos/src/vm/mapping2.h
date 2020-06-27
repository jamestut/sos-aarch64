#pragma once

#include <stdbool.h>
#include <sel4/sel4.h>
#include <cspace/cspace.h>
#include "addrspace.h"
#include "../frame_table.h"
#include "../grp01.h"

typedef union {
    uint64_t i64;
    uint16_t arr[4];
    struct {
        uint16_t pt;
        uint16_t pd;
        uint16_t pud;
        uint16_t pgd;
    } str;
} pd_indices_t;

typedef struct {
    // remaining bytes for this page
    uint16_t remcurr;
    // remaining bytes overall
    size_t remall;
    // pointer to SOS' vaddr. If 0, then this data structure is invalid.
    uintptr_t curr;
    // fields related to userapp
    seL4_Word pid;
    seL4_CapRights_t userasperm;

    pd_indices_t useridx;
} userptr_write_state_t;

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
// @param full       if true, all touched intermediary pages and shadow tables associated with the vspace
//                   will be torn off.
seL4_Error grp01_unmap_frame(seL4_Word badge, seL4_CPtr vspace, seL4_Word vaddrbegin, seL4_Word vaddrend, bool full);

// @return 0 on lookup failure (e.g. wrong region / unmapped frame)
frame_ref_t grp01_get_frame(seL4_Word badge, seL4_CPtr vspace, seL4_Word vaddr);

// "copy-in" from user's vspace
// @return 0 on failure, or pointer to the beginning of the buffer on success
void* userptr_read(userptr_t src, size_t len, seL4_Word badge, seL4_CPtr vspace);

userptr_write_state_t userptr_write_start(userptr_t src, size_t len, dynarray_t* useras, seL4_Word badge, seL4_CPtr vspace);

// @return false if error occured (e.g. cannot map frame)
//         otherwise, return true, even if no action is carried
bool userptr_write_next(userptr_write_state_t* it);

// Unmap and destroy the scratch address space that contains the given pointer.
void userptr_unmap(void* sosaddr);
