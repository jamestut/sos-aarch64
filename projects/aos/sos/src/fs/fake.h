#pragma once

#include <stdint.h>
#include <sys/types.h>
#include <sos.h>

ssize_t fake_fs_stat(seL4_CPtr ep, char* path, sos_stat_t* out);

ssize_t fake_fs_opendir(seL4_CPtr ep, char* path);

const char* fake_fs_dirent(seL4_CPtr ep, ssize_t id, size_t pos);
