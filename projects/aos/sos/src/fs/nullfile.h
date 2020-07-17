#pragma once

#include <stdint.h>
#include <sys/types.h>
#include <sos.h>

ssize_t null_fs_open(seL4_Word pid, const char* fn, int mode);

ssize_t null_fs_read(seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len);

ssize_t null_fs_write(seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len);

ssize_t null_fs_stat(seL4_Word pid, char* path, sos_stat_t* out);

ssize_t null_fs_opendir(seL4_Word pid, char* path);

const char* null_fs_dirent(seL4_Word pid, ssize_t id, size_t idx);

void null_fs_closedir(seL4_Word pid, ssize_t id);

void null_fs_close(seL4_Word pid, ssize_t id);
