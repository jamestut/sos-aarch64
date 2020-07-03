#include <fcntl.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "../fileman.h"
#include "nullfile.h"

enum perm {
    PERM_RD = 1,
    PERM_WR = 2
};

ssize_t null_fs_open(UNUSED seL4_CPtr ep, UNUSED const char* fn, int mode)
{
    // pretty much copy of console
    switch(mode) {
        case O_RDONLY:
            return PERM_RD;
        case O_WRONLY:
            return PERM_WR;
        case O_RDWR:
            return PERM_WR | PERM_RD;
        default:
            return 0;
    }
}

ssize_t null_fs_read(UNUSED seL4_CPtr ep, ssize_t id, UNUSED void* ptr, UNUSED off_t offset, UNUSED size_t len)
{
    if(id & PERM_RD) 
        return 0;
    else 
        return EBADF * -1;
}

ssize_t null_fs_write(UNUSED seL4_CPtr ep, ssize_t id, UNUSED void* ptr, UNUSED off_t offset, UNUSED size_t len)
{
    if(id & PERM_WR) 
        return 0;
    else 
        return EBADF * -1;
}

ssize_t null_fs_stat(UNUSED seL4_CPtr ep, UNUSED char* path, sos_stat_t* out)
{
    memset(out, 0, sizeof(sos_stat_t));
    out->st_fmode = FM_READ | FM_WRITE;
    out->st_type = ST_SPECIAL;
    return 0;
}

ssize_t null_fs_opendir(UNUSED seL4_CPtr ep, UNUSED char* path)
{
    return -ENOTDIR;
}

const char* null_fs_dirent(UNUSED seL4_CPtr ep, UNUSED ssize_t id, UNUSED size_t idx)
{
    return NULL;
}

void null_fs_closedir(UNUSED seL4_CPtr ep, UNUSED ssize_t id) {}

void null_fs_close(UNUSED seL4_CPtr ep, UNUSED ssize_t id) {/* do nothing */}
