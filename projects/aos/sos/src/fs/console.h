#pragma once

#include <stdint.h>

int console_fs_open(const char* fn, int mode);

int32_t console_fs_read(int id, void* ptr, uint32_t len);

int32_t console_fs_write(int id, void* ptr, uint32_t len);

void console_fs_close(int id);
