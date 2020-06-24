#include "faulthandler.h"
#include "addrspace.h"
#include "mapping2.h"
#include "../utils.h"
#include "../frame_table.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <utils/zf_log_if.h>
#include <utils/arith.h>

bool vm_fault(seL4_MessageInfo_t* tag, seL4_Word badge, seL4_CPtr vspace, dynarray_t* asarr)
{
    // we assume that all arguments passed here is sane!

    // find out more about the fault
    seL4_Fault_t fault = seL4_getFault(*tag);
    uintptr_t faultaddr = (uintptr_t)seL4_Fault_VMFault_get_Addr(fault);
    uintptr_t currip = (uintptr_t)seL4_Fault_VMFault_get_IP(fault);
    uintptr_t prefetchfault = seL4_Fault_VMFault_get_PrefetchFault(fault);
    bool write = seL4_GetMR(seL4_VMFault_FSR) & BIT(6);

    // first, find the address space region
    int asidx = addrspace_find(asarr, faultaddr);
    if(asidx < 0) {
        ZF_LOGE("Fault address does not belong to any of the app's region.");
        return false;
    }
    addrspace_t* as = ((addrspace_t*)asarr->data) + asidx;

    // check if we're writing and allowed to write
    if(write && !seL4_CapRights_get_capAllowWrite(as->perm)) {
        ZF_LOGE("Write fault on read only region.");
        return false;
    }

    // else, it should be a valid translation
    // TODO: GRP01 bookkeep the allocated frame
    // TODO: GRP01 support mmap
    frame_ref_t frame = alloc_frame();
    if(!frame) {
        ZF_LOGE("Cannot allocate a frame.");
        return false;
    }
    // zero out the frame
    memset(frame_data(frame), 0, PAGE_SIZE_4K);

    seL4_Error err;

    // and map it!
    err = grp01_map_frame(badge, frame, true, vspace, ROUND_DOWN(faultaddr, PAGE_SIZE_4K), as->perm, seL4_ARM_Default_VMAttributes);
    if(err != seL4_NoError) {
        ZF_LOGE("Error mapping frame to target vaddr: %d", err);
        return false;
    }

    return true;
}
