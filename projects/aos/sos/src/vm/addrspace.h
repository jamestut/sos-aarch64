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
    // has a special action on fault
    AS_MMAP = 2
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
addrspace_add_errors addrspace_add(dynarray_t* arr, addrspace_t as);

int addrspace_find(dynarray_t* arr, uintptr_t vaddr);
