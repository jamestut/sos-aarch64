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

extern sos_thread_t threads[SOS_MAX_THREAD];

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
    err = grp01_map_frame(badge, 0, true, false, ROUND_DOWN(faultaddr, PAGE_SIZE_4K), as->perm, seL4_ARM_Default_VMAttributes);
    if(err != seL4_NoError) {
        // need to allocate a new frame
        frame_ref_t frame = alloc_empty_frame();
        if(!frame) {
            ZF_LOGE("Cannot allocate a frame.");
            return false;
        }

        // and map it!
        err = grp01_map_frame(badge, frame, true, false, ROUND_DOWN(faultaddr, PAGE_SIZE_4K), as->perm, seL4_ARM_Default_VMAttributes);
        if(err != seL4_NoError) {
            ZF_LOGE("Error mapping frame to target vaddr: %d", err);
            return false;
        }
    }
    return true;
}

bool sos_vm_fault(seL4_Word badge, seL4_MessageInfo_t* tag)
{
    // special case if it is one of SOS' thread that is faulting
    // we'll only do remapping here
    seL4_Fault_t fault = seL4_getFault(*tag);
    uintptr_t faultaddr = (uintptr_t)seL4_Fault_VMFault_get_Addr(fault);
    uintptr_t currip = (uintptr_t)seL4_Fault_VMFault_get_IP(fault);
    bool prefetchfault = seL4_Fault_VMFault_get_PrefetchFault(fault);
    bool write = seL4_GetMR(seL4_VMFault_FSR) & BIT(6);
    
    bool success = false;

    if(faultaddr) {
        seL4_Error err;
        err = grp01_map_frame(0, 0, true, false, ROUND_DOWN(faultaddr, PAGE_SIZE_4K), seL4_AllRights, seL4_ARM_Default_VMAttributes);
        success = err == seL4_NoError;
    }

    if(!success) {
        int thrdidx = badge & (BADGE_INT_THRD - 1);
        sos_thread_t* currthrd = threads + thrdidx;
        if(currthrd->jump_on_fault.enabled) {
            ZF_LOGW("SOS VM fault cannot be handled, but thread %d provides jump target.", thrdidx);
            currthrd->jump_on_fault.enabled = false;

            seL4_UserContext regtgt = {
                .pc = (seL4_Word)thread_wrap,
                // 128 bytes for "emergency stack", give or take :)
                .sp = currthrd->stack_base + 128 
            };

            // the resumption will be done upon reply
            if(seL4_TCB_WriteRegisters(currthrd->tcb, false, 0, 2, &regtgt) != seL4_NoError) {
                ZF_LOGF("Failure to write TCB registers for continuation");
                return false;
            }
            success = true;
        } else {
            ZF_LOGE("SOS VM fault: %s fault%s @ %p (IP %p).", 
                (write ? "Write" : "Read"), (prefetchfault ? " (exec)" : ""), faultaddr, currip);
        }
    }

    return success;
}
