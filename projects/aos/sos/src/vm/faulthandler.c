#include "faulthandler.h"
#include "addrspace.h"
#include "mapping2.h"
#include "../utils.h"
#include "../frame_table.h"
#include "../proctable.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <utils/zf_log_if.h>
#include <utils/arith.h>

bool vm_fault(seL4_MessageInfo_t* tag, seL4_Word badge)
{
    // we assume that all arguments passed here is sane!

    // find out more about the fault
    seL4_Fault_t fault = seL4_getFault(*tag);
    uintptr_t faultaddr = (uintptr_t)seL4_Fault_VMFault_get_Addr(fault);
    uintptr_t currip = (uintptr_t)seL4_Fault_VMFault_get_IP(fault);
    bool prefetchfault = seL4_Fault_VMFault_get_PrefetchFault(fault);
    bool write = seL4_GetMR(seL4_VMFault_FSR) & BIT(6);
    
    // process data
    dynarray_t* asarr = &proctable[badge].as;

    // first, find the address space region
    int asidx = addrspace_find(asarr, faultaddr);
    if(asidx < 0) {
        ZF_LOGE("VM: %s fault%s @ %p (IP %p) of process %ld.", 
            (write ? "Write" : "Read"), (prefetchfault ? " (exec)" : ""), faultaddr, currip, badge);
        return false;
    }
    addrspace_t* as = ((addrspace_t*)asarr->data) + asidx;

    // check if we're writing and allowed to write / read and allowed to read
    if(write && !seL4_CapRights_get_capAllowWrite(as->perm)) {
        ZF_LOGE("Write fault on no-write region.");
        return false;
    } else if(!write && !seL4_CapRights_get_capAllowRead(as->perm)) {
        ZF_LOGE("Read fault on no-read region.");
        return false;
    }

    seL4_Error err;
    
    // first, try remapping the page. parameter frame_ref of 0 will trigger remapping.
    err = grp01_map_frame(badge, 0, true, ROUND_DOWN(faultaddr, PAGE_SIZE_4K), as->perm, seL4_ARM_Default_VMAttributes);
    if(err != seL4_NoError) {
        // need to allocate a new frame
        frame_ref_t frame = alloc_empty_frame();
        if(!frame) {
            ZF_LOGE("Cannot allocate a frame.");
            return false;
        }

        // and map it!
        err = grp01_map_frame(badge, frame, true, ROUND_DOWN(faultaddr, PAGE_SIZE_4K), as->perm, seL4_ARM_Default_VMAttributes);
        if(err != seL4_NoError) {
            ZF_LOGE("Error mapping frame to target vaddr: %d", err);
            free_frame(frame);
            return false;
        }
    }
    return true;
}
