#pragma once

#include <grp01/dynaarray.h>
#include <stddef.h>
#include <sys/types.h>

// @return negative errno
ssize_t handle_brk(dynarray_t* arr, seL4_Word badge, seL4_CPtr vspace, uintptr_t target);

// @return negative errno
ssize_t handle_mmap(dynarray_t* as, uintptr_t addr, size_t len, int prot, 
    int flags, int fd, off_t offset);

// @return 1 on success, or negative errno
ssize_t handle_munmap(dynarray_t* as, seL4_Word badge, seL4_CPtr vspace, 
    uintptr_t vaddr, size_t len);

ssize_t handle_grow_stack(dynarray_t* as, seL4_Word badge, seL4_CPtr vspace, ssize_t bypage);
