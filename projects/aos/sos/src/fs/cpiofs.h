#pragma once

#include <sys/types.h>
#include <sel4/sel4.h>
#include <sos.h>

void cpio_fs_init();

ssize_t cpio_fs_open(seL4_Word pid, const char* fn, int mode);

ssize_t cpio_fs_read(seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len);

ssize_t cpio_fs_write(seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len);

ssize_t cpio_fs_stat(seL4_Word pid, char* path, sos_stat_t* out);

ssize_t cpio_fs_opendir(seL4_Word pid, char* path);

const char* cpio_fs_dirent(seL4_Word pid, ssize_t id, size_t pos);

void cpio_fs_closedir(seL4_Word pid, ssize_t id);

void cpio_fs_close(seL4_Word pid, ssize_t id);
