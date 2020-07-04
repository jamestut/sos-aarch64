#pragma once

#include <stdint.h>
#include <sys/types.h>
#include <sos.h>

void console_fs_init(void);

ssize_t console_fs_open(seL4_CPtr ep, const char* fn, int mode);

ssize_t console_fs_read(seL4_CPtr ep, ssize_t id, void* ptr, off_t offset, size_t len);

ssize_t console_fs_write(seL4_CPtr ep, ssize_t id, void* ptr, off_t offset, size_t len);

void console_fs_close(seL4_CPtr ep, ssize_t id);
