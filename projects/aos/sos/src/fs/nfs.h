#pragma once

#include <sys/types.h>
#include <sel4/sel4.h>
#include <sos.h>

void grp01_nfs_init();

ssize_t grp01_nfs_open(seL4_CPtr ep, const char* fn, int mode);

ssize_t grp01_nfs_read(seL4_CPtr ep, ssize_t id, void* ptr, off_t offset, size_t len);

ssize_t grp01_nfs_write(seL4_CPtr ep, ssize_t id, void* ptr, off_t offset, size_t len);

ssize_t grp01_nfs_stat(seL4_CPtr ep, char* path, sos_stat_t* out);

ssize_t grp01_nfs_opendir(seL4_CPtr ep, char* path);

const char* grp01_nfs_dirent(seL4_CPtr ep, ssize_t id, size_t pos);

void grp01_nfs_closedir(seL4_CPtr ep, ssize_t id);

void grp01_nfs_close(seL4_CPtr ep, ssize_t id);
