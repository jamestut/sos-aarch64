#include "addrspace.h"
#include <string.h>
#include <grp01/binsearch.h>
#include <utils/builtin.h>
#include <utils/zf_log.h>
#include <utils/zf_log_if.h>

// comparator functions
// compare given vaddress and the address space. 0 if vaddr is contained inside address space.
int comp_vaddr(const void* a, const void* b);

// compare given address space and another address space. 0 if overlaps.
int comp_as(const void* a, const void* b);

addrspace_add_errors addrspace_add(dynarray_t* arr, addrspace_t as)
{
    if(as.end <= as.begin)
        return AS_ADD_INVALIDARG;

    addrspace_t* aslist = arr->data;
    int pos = binary_search(aslist, &as, sizeof(addrspace_t), arr->used, comp_as, true);
    ZF_LOGF_IF(pos < 0, "Negative closest match"); // should never happen
    
    bool overlap = false;
    if((uint32_t)pos < arr->used)
        overlap = comp_as(&as, aslist + pos) == 0;

    if(overlap) {
        // check permission
        if(memcmp(&as.perm, &aslist[pos].perm, sizeof(seL4_CapRights_t)))
            return AS_ADD_CLASH;
        // merge region if possible
        // extend the end if possible
        if(as.end > aslist[pos].end) {
            if((uint32_t)pos >= arr->used || as.end < aslist[pos+1].begin)
                aslist[pos].end = as.end;
            else
                return AS_ADD_CLASH;
        }
        // extend the beginning if possible
        if(as.begin < aslist[pos].begin) {
            // remember, end is exclusive. VPN pointed by end is not used by that region.
            if(pos == 0 || as.begin >= aslist[pos-1].end)
                aslist[pos].begin = as.begin;
            else
                return AS_ADD_CLASH;
        }
    } else {
        // insert!
        if(arr->capacity < (arr->used + 1)) {
            if(!dynarray_resize(arr, arr->used + 1))
                return AS_ADD_NOMEM;
            // after reallocation, pointer may change
            aslist = arr->data;
        }
        // binary insert
        if(pos < arr->used)
            memmove(aslist + pos + 1, aslist + pos, (arr->used - pos) * sizeof(addrspace_t));
        aslist[pos] = as;
        ++arr->used;
    }
    // success
    return AS_ADD_NOERR;
}

int addrspace_find(dynarray_t* arr, uintptr_t vaddr)
{
    return binary_search(arr->data, &vaddr, sizeof(addrspace_t), arr->used, comp_vaddr, false);
}

int comp_vaddr(const void* a, const void* b)
{
    uintptr_t vaddr = *((uintptr_t*)a);
    const addrspace_t* as = b;
    if(vaddr < as->begin)
        return -1;
    if (vaddr >= as->end)
        return 1;
    return 0;
}

int comp_as(const void* a, const void* b)
{
    const addrspace_t* _a = a;
    const addrspace_t* _b = b;
    // the addrspace_add guarantees that as.end > as.begin
    if(_a->begin >= _b->end)
        return 1;
    if(_a->end <= _b->begin)
        return -1;
    // overlap (either partial or full)
    return 0;
}
