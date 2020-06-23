#pragma once

#include <stdint.h>
#include <sel4/sel4.h>
#include <grp01/dynaarray.h>

struct addrspace {
    uintptr_t begin; // begin VPN, inclusive
    uintptr_t end; // end VPN, exclusive
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
