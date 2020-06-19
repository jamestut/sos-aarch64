#pragma once

#include <stdint.h>

void console_fs_init(void);

int console_fs_open(const char* fn, int mode);

ssize_t console_fs_read(int id, void* ptr, size_t len);

ssize_t console_fs_write(int id, void* ptr, size_t len);

void console_fs_close(int id);
