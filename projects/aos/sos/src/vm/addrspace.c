#include "addrspace.h"
#include "../utils.h"
#include <string.h>
#include <grp01/binsearch.h>
#include <utils/builtin.h>
#include <utils/zf_log.h>
#include <utils/zf_log_if.h>

// compile time sanity checks!
static_assert(sizeof(struct addrspace_attr) == 8);

// comparator functions
// compare given vaddress and the address space. 0 if vaddr is contained inside address space.
int comp_vaddr(const void* a, const void* b);

// compare given address space and another address space. 0 if overlaps.
int comp_as(const void* a, const void* b);

addrspace_add_errors addrspace_add(dynarray_t* arr, addrspace_t as, bool allowoverlap, uint32_t* index)
{
    if(as.end <= as.begin)
        return AS_ADD_INVALIDARG;
    if(arr->used == 0x7FFFFFFF)
        return AS_ADD_NOMEM;

    addrspace_t* aslist = arr->data;
    int pos = binary_search(aslist, &as, sizeof(addrspace_t), arr->used, comp_as, true);
    ZF_LOGF_IF(pos < 0, "Negative closest match"); // should never happen
    
    bool overlap = false;
    if((uint32_t)pos < arr->used)
        overlap = comp_as(&as, aslist + pos) == 0;

    if(overlap) {
        if(!allowoverlap)
            return AS_ADD_CLASH;
        // check permission and attribute
        if(memcmp(&as.perm, &aslist[pos].perm, sizeof(seL4_CapRights_t)) || 
            memcmp(&as.attr, &aslist[pos].perm, sizeof(struct addrspace_attr)))
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
    if(index)
        *index = pos;
    return AS_ADD_NOERR;
}

void addrspace_remove(dynarray_t* arr, uint32_t index)
{
    ZF_LOGF_IF(index >= arr->used, "Out of bound");
    addrspace_t* as = arr->data;
    memmove(as + index, as + index + 1, (arr->used - index - 1) * sizeof(addrspace_t));
    --arr->used;
}

int addrspace_find(dynarray_t* arr, uintptr_t vaddr)
{
    // 0th page is always invalid!
    if(vaddr < PAGE_SIZE_4K)
        return -1;
    return binary_search(arr->data, &vaddr, sizeof(addrspace_t), arr->used, comp_vaddr, false);
}

int addrspace_find_overlap(dynarray_t* arr, addrspace_t as)
{
    return binary_search(arr->data, &as, sizeof(addrspace_t), arr->used, comp_as, false);
}

uintptr_t addrspace_find_free_reg(dynarray_t* arr, size_t size, uintptr_t bottom, uintptr_t top)
{
    if(arr->used == 0) {
        // check if our entire addrspace can be used to fit this request!
        if(size < (top - bottom))
            return bottom;
    } else {
        // find an empty region, starting from rearmost!
        for(int i = arr->used - 1; i >= 0; --i) {
            uintptr_t ret = ((addrspace_t*)arr->data)[i].end;
            if(size < (top - ret))
                return ret;
            top = ((addrspace_t*)arr->data)[i].begin;
        }
    }
    // fail
    return 0;
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
