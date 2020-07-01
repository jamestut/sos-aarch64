#pragma once

#include <stdint.h>
#include <sys/types.h>

void console_fs_init(void);

ssize_t console_fs_open(const char* fn, int mode);

ssize_t console_fs_read(ssize_t id, void* ptr, size_t len);

ssize_t console_fs_write(ssize_t id, void* ptr, size_t len);

void console_fs_close(ssize_t id);
