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

int null_fs_open(UNUSED const char* fn, int mode)
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

ssize_t null_fs_read(int id, UNUSED void* ptr, UNUSED size_t len)
{
    if(id & PERM_RD) 
        return 0;
    else 
        return EBADF * -1;
}

ssize_t null_fs_write(int id, void* ptr, size_t len)
{
    return null_fs_read(id, ptr, len);
}

void null_fs_close(UNUSED int id) {/* do nothing */}
