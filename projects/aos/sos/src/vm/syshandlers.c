#include "../vmem_layout.h"
#include "../utils.h"
#include "syshandlers.h"
#include "addrspace.h"
#include "mapping2.h"
#include <utils/zf_log_if.h>
#include <errno.h>
#include <sel4/sel4.h>
#include <utils/arith.h>
#include <sys/mman.h>
#include <grp01/misc.h>

#define MMAP_SUPPORTED_FLAGS (MAP_ANON | MAP_PRIVATE)
#define PROCESS_STACK_ABSOLUTE_MIN_PAGES 2

ssize_t handle_brk(dynarray_t* arr, seL4_Word badge, seL4_CPtr vspace, uintptr_t target)
{
    // for request of 0, return the END of the heap segment

    if(target >= (PROCESS_HEAP_SIZE + PROCESS_HEAP))
        return ENOMEM * -1;
    if(target && target < PROCESS_HEAP)
        return EINVAL * -1;

    seL4_CapRights_t rights = seL4_CapRights_new(false, false, true, true);

    // find the section that *might* contain the heap
    int32_t section_id = addrspace_find(arr, PROCESS_HEAP);
    addrspace_t* asarr = arr->data;

    // if a section is found, make sure it is THE heap
    if(section_id >= 0) {
        // if this happens, which should never happens, then very likely
        // the loaded ELF is mallicious. we might as well reject its request for heap!
        if(asarr[section_id].attr.type != AS_HEAP)
            return ENOMEM * -1;
    }

    // basically the heap currently allocated is of size 0, therefore end == start
    if(target == 0 && section_id < 0)
        return PROCESS_HEAP;

    uintptr_t ret = PROCESS_HEAP;
    target = ROUND_UP(target, PAGE_SIZE_4K);

    if(section_id < 0) {
        // no heap section found. create one!
        addrspace_t heapas;
        heapas.begin = PROCESS_HEAP;
        ret = heapas.end = target;
        heapas.attr.type = AS_HEAP;
        heapas.perm = rights;

        // will return an error if it overlaps with another region
        if(addrspace_add(arr, heapas, false, NULL) != AS_ADD_NOERR) {
            ZF_LOGE("Failed to add heap address space section.");
            return ENOMEM * -1;
        }
    } else {
        addrspace_t* heapas = asarr + section_id;
        
        target = ROUND_UP(target, PAGE_SIZE_4K);
        if(!target)
            // just return the current break size
            ret = heapas->end;
        else if(target <= heapas->end) {
            // see if we have to reduce the heap section
            if(target < heapas->end) {
                // indeed!
                ZF_LOGE_IF(grp01_unmap_frame(badge, target, heapas->end, false) != seL4_NoError,
                    "Unmapping frames from shrunk heap brk failed.");
                ret = heapas->end = target;
                
                if(target == heapas->begin)
                    // remove the section altogether!
                    addrspace_remove(arr, section_id);
            } else
                ret = heapas->end;
        }
        else {
            // enlarge heap. ensure that we don't clash!
            if(section_id < arr->used) {
                if(target > ((addrspace_t*)arr->data)[section_id+1].begin)
                    return ENOMEM * -1;
            }
            // OK
            ret = heapas->end = target;
        }
    }

    return ret;
}

ssize_t handle_mmap(dynarray_t* asarr, uintptr_t addr, size_t len, int prot, 
    int flags, UNUSED int fd, UNUSED off_t offset)
{
    // we won't support user's specified address
    // at the moment, we only support anon files
    if(addr || !len || !(prot & (PROT_READ | PROT_WRITE)))
        return EINVAL * -1;

    // check flags
    // no support for non anon mmaps
    // MAP_PRIVATE specified or not, it will always private!
    if(!(flags & MAP_ANON))
        return EINVAL * -1;
    // make sure that unsupported flags doesn't get passed
    if(flags & ~MMAP_SUPPORTED_FLAGS)
        return EINVAL * -1;

    // check if size is larger than the largest possible size
    if(len > (VMEM_TOP - PROCESS_MMAP))
        return ENOMEM * -1;

    addrspace_t* as = asarr->data;
    
    // find the region for mmap, starting from the last region
    addrspace_t mmapas;
    mmapas.begin = PROCESS_MMAP;
    mmapas.attr.type = AS_MMAP;
    mmapas.attr.data = -1; // anon
    mmapas.perm = seL4_CapRights_new(false, false, CBOOL(prot & PROT_READ), CBOOL(prot & PROT_WRITE));
    
    // try to use the region after the last
    if(as[asarr->used - 1].end > mmapas.begin) 
        mmapas.begin = as[asarr->used - 1].end;
    // check if it would fit to our addrspace
    mmapas.end = ROUND_UP(mmapas.begin + len - 1, PAGE_SIZE_4K);
    if(mmapas.end >= VMEM_TOP) {
        // maybe we don't have a free space @ the end.
        // try finding in middle regions.
        int first_mmap = addrspace_find(asarr, PROCESS_MMAP);
        if(first_mmap < 0)
            // then we have nowhere to go!
            return ENOMEM * -1;
        // let's hope that we might find something
        bool found = false;
        for(uint32_t i = first_mmap; i < asarr->used - 1; ++i) {
            mmapas.begin = as[i].end;
            mmapas.end = ROUND_UP(mmapas.begin + len - 1, PAGE_SIZE_4K);
            if(mmapas.end <= as[i+1].begin) {
                // this is it!
                found = true;
                break;
            }
        }
        if(!found)
            return ENOMEM * -1;
    }

    // try adding the region
    if(addrspace_add(asarr, mmapas, false, NULL) != AS_ADD_NOERR)
        return ENOMEM * -1;

    // OK!
    return mmapas.begin;
}

ssize_t handle_munmap(dynarray_t* asarr, seL4_Word badge, seL4_CPtr vspace, 
    uintptr_t vaddr, size_t len)
{
    if(vaddr % PAGE_SIZE_4K)
        return -EINVAL;
    int asidx = addrspace_find(asarr, vaddr);
    if(asidx < 0)
        return -EINVAL;
    addrspace_t* as = ((addrspace_t*)asarr->data) + asidx;
    if(as->attr.type != AS_MMAP)
        return -EINVAL;

    // if len is not page aligned and is smaller than the region's space,
    // we'll reject it
    bool deletewhole = false;
    if(len >= (as->end - as->begin))
        deletewhole = true;
    
    if(!deletewhole && (len % PAGE_SIZE_4K))
        return -EINVAL;

    // these suboperations should never ever returns an error unless we have bug!
    if(deletewhole) {
        // easy! just delete the entire AS!
        ZF_LOGF_IF(grp01_unmap_frame(badge, as->begin, as->end, false) != seL4_NoError,
            "Fatal unmap error!");
        addrspace_remove(asarr, asidx);
    } else {
        ZF_LOGF_IF(grp01_unmap_frame(badge, vaddr, vaddr + len, false) != seL4_NoError,
            "Fatal unmap error!");
        
        // require 1 more AS? or is resizing enough?
        if(vaddr == as->begin) 
            as->begin += len;
        else if((vaddr + len) == as->end)
            as->end -= len;
        else {
            addrspace_t as2;
            as2 = *as;
            as->end = vaddr;
            as2.begin = vaddr + len;
            // it's difficult to rollback if we got an error here. We think it is better
            // to panic instead!
            ZF_LOGF_IF(addrspace_add(asarr, as2, false, NULL) != AS_ADD_NOERR, "Error adding AS");
        }
    }
    
    return 1;
}

ssize_t handle_grow_stack(dynarray_t* asarr, seL4_Word badge, seL4_CPtr vspace, ssize_t bypage)
{
    // find the stack by looking the vaddr of the bottom of the 1st page
    uintptr_t vaddr = PROCESS_STACK_TOP - PAGE_SIZE_4K;
    int asidx = addrspace_find(asarr, vaddr);
    if(asidx < 0)
        return -1;

    // truncate max (to prevent integer overflow)
    if(bypage > PROCESS_STACK_MAX_PAGES)
        bypage = PROCESS_STACK_MAX_PAGES;
    
    addrspace_t* as = ((addrspace_t*)asarr->data);
    addrspace_t* stackas = as + asidx;
    // ensure that it is the stack
    if(stackas->attr.type != AS_STACK)
        return -1;

    ssize_t numpages = (stackas->end - stackas->begin) >> seL4_PageBits;
    // do not modify if request is too large (or 0)
    if(!bypage || (bypage > (VMEM_TOP >> seL4_PageBits)))
        return numpages;

    numpages += bypage;

    // truncate min
    if(numpages < PROCESS_STACK_ABSOLUTE_MIN_PAGES)
        numpages = PROCESS_STACK_ABSOLUTE_MIN_PAGES;

    uintptr_t newbegin = stackas->end - (numpages << seL4_PageBits);
    // check for region collision
    if(asidx) {
        if(as[asidx - 1].end > newbegin)
            newbegin = as[asidx - 1].end + 1; // add a guard page!
        numpages = (stackas->end - newbegin) >> seL4_PageBits;
    }
    
    // truncate stack size if it is more than what we're willing!
    if (numpages > PROCESS_STACK_MAX_PAGES)
        numpages = PROCESS_STACK_MAX_PAGES;
    
    // resize
    newbegin = stackas->end - (numpages << seL4_PageBits);
    if(newbegin > stackas->begin) {
        // shrink!
        ZF_LOGE_IF(grp01_unmap_frame(badge, stackas->begin, newbegin, false) != seL4_NoError,
            "Unmapping frames from shrunk stack failed.");
    }
    stackas->begin = newbegin;
    return numpages;
}
