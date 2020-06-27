#pragma once

#include <stdint.h>
#include <stddef.h>
#include <sel4/sel4.h>
#include <grp01/dynaarray.h>

typedef enum {
    // normal action upon fault: page in, or create new zero frame
    AS_NORMAL = 0,
    // same as above, but indicates that this was created from brk
    AS_HEAP = 1,
    // same as above, but indicates that this was designated for stack
    AS_STACK = 2,
    // may have a special action on fault depending on the "data" field
    AS_MMAP = 3
    //AS_SHARED
} addrspace_type;

struct addrspace_attr {
    addrspace_type type : 4;
    size_t data : 60; // interpretation depends on type
};

struct addrspace {
    uintptr_t begin; // begin VPN, inclusive
    uintptr_t end; // end VPN, exclusive
    struct addrspace_attr attr;
    seL4_CapRights_t perm;
};

typedef struct addrspace addrspace_t;

typedef enum {
    AS_ADD_NOERR = 0,
    AS_ADD_NOMEM, // if we can't enlarge the dynamic array
    AS_ADD_CLASH, // if overlaps with the existing section and different permissions
    AS_ADD_INVALIDARG
} addrspace_add_errors;

// add the address space to the designated dynamic array that contains the address space,
// while maintaining the sorted order.
addrspace_add_errors addrspace_add(dynarray_t* arr, addrspace_t as, bool allowoverlap, uint32_t* idx);

// remove the address space, while maintaining the sorted order.
// it is the caller's responsibility to unmap frames associated with the region.
void addrspace_remove(dynarray_t* arr, uint32_t index);

int addrspace_find(dynarray_t* arr, uintptr_t vaddr);

// @return if an address space overlaps with one or more results, returns index of one of them.
//         else, returns -1
int addrspace_find_overlap(dynarray_t* arr, addrspace_t as);

