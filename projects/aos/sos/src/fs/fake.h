#pragma once

#include <stdint.h>
#include <sys/types.h>
#include <sos.h>

void fake_fs_init(size_t capacity);

ssize_t fake_fs_stat(seL4_Word pid, char* path, sos_stat_t* out);

ssize_t fake_fs_opendir(seL4_Word pid, char* path);

const char* fake_fs_dirent(seL4_Word pid, ssize_t id, size_t pos);

ssize_t fake_fs_open(seL4_Word pid, const char* fn, int mode);

void fake_fs_close(seL4_Word pid, ssize_t id);

ssize_t fake_fs_read(seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len);

ssize_t fake_fs_write(seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len);
