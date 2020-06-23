#include "../vmem_layout.h"
#include "../utils.h"
#include <utils/zf_log_if.h>
#include "syshandlers.h"
#include "addrspace.h"
#include <errno.h>
#include <sel4/sel4.h>
#include <utils/arith.h>

ssize_t handle_brk(dynarray_t* arr, size_t brksz)
{
    // for request of 0, return the END of the heap segment

    if(brksz >= (PROCESS_HEAP_SIZE + PROCESS_HEAP))
        return ENOMEM * -1;
    if(brksz && brksz < PROCESS_HEAP)
        return EINVAL * -1;

    seL4_CapRights_t rights = seL4_CapRights_new(false, false, true, true);

    // find the section that *might* contain the heap
    int section_id = addrspace_find(arr, PROCESS_HEAP);
    addrspace_t* as = arr->data;

    // if a section is found, make sure it is THE heap
    if(section_id >= 0) {
        // if this happens, which should never happens, then very likely
        // the loaded ELF is mallicious. we might as well reject its request for heap!
        if(as[section_id].attr.type != AS_HEAP)
            return ENOMEM * -1;
    }

    // basically the heap here is of size 0, therefore end == start
    if(brksz == 0 && section_id < 0)
        return PROCESS_HEAP;

    uintptr_t ret = PROCESS_HEAP;

    if(section_id < 0) {
        // no heap section found. create one!
        addrspace_t heapas;
        heapas.begin = PROCESS_HEAP;
        ret = heapas.end = ROUND_UP(brksz, PAGE_SIZE_4K);
        heapas.attr.type = AS_HEAP;
        heapas.perm = rights;
        
        if(addrspace_add(arr, heapas) != AS_ADD_NOERR) {
            ZF_LOGE("Failed to add heap address space section.");
            return ENOMEM * -1;
        }
    } else {
        // adjust the size of the existing region
        as += section_id;
        
        if(!brksz)
            ret = as->end;
        else if(brksz < as->end)
            // TODO: GRP01 support reduce break
            return EINVAL * -1;
        else
            ret = as->end = ROUND_UP(brksz, PAGE_SIZE_4K);
    }

    return ret;
}
