#pragma once

#include <sys/types.h>
#include <sel4/sel4.h>

void grp01_nfs_init();

ssize_t grp01_nfs_open(seL4_CPtr ep, const char* fn, int mode);

ssize_t grp01_nfs_read(seL4_CPtr ep, ssize_t id, void* ptr, off_t offset, size_t len);

ssize_t grp01_nfs_write(seL4_CPtr ep, ssize_t id, void* ptr, off_t offset, size_t len);

void grp01_nfs_close(seL4_CPtr ep, ssize_t id);

ssize_t grp01_nfs_getdirent(seL4_CPtr ep, int pos, const char* path, size_t nbyte, size_t *entry_size);