#pragma once

#include <grp01/dynaarray.h>
#include <stddef.h>
#include <sys/types.h>

// @return negative errno
ssize_t handle_brk(dynarray_t* as, size_t brksz);
