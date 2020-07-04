#include "fake.h"

ssize_t fake_fs_stat(seL4_CPtr ep, char* path, sos_stat_t* out)
{
    memset(out, 0, sizeof(sos_stat_t));
    out->st_type = ST_FILE;
    out->st_fmode = 7;
    out->st_size = 123;
}

ssize_t fake_fs_opendir(seL4_CPtr ep, char* path)
{
    return 123;
}

const char* fake_fs_dirent(seL4_CPtr ep, ssize_t id, size_t pos)
{
    switch(pos) {
        case 0:
            return "filename1";
        case 1:
            return "world";
        default:
            return NULL;
    }
}
