#pragma once

#include <stdint.h>

int null_fs_open(const char* fn, int mode);

ssize_t null_fs_read(int id, void* ptr, size_t len);

ssize_t null_fs_write(int id, void* ptr, size_t len);

void null_fs_close(int id);
