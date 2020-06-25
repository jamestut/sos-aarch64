#pragma once

#include <grp01/dynaarray.h>
#include <stddef.h>
#include <sys/types.h>

// @return negative errno
ssize_t handle_brk(dynarray_t* as, size_t brksz);

// @return negative errno
ssize_t handle_mmap(dynarray_t* as, uintptr_t addr, size_t len, int prot, 
    int flags, int fd, off_t offset);

ssize_t handle_grow_stack(dynarray_t* as, size_t bypage);
