#include "fake.h"
#include <stdbool.h>
#include <utils/util.h>
#include <errno.h>
#include "../utils.h"
#include "../vmem_layout.h"
#include "../mapping.h"

#define FAKE_FS_ID 123
#define FAKE_FS_CAPACITY (pagecount * PAGE_SIZE_4K)

// fields. the fake FS is basically an ADO
bool active = false;
size_t pagecount = 0;
size_t used = 0;

// make the file atomic!
seL4_CPtr mtx = 0;
ut_t* mtx_ut = NULL;

ssize_t fake_fs_rw(seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len, bool write);

void fake_fs_init(size_t capacity)
{
    pagecount = DIV_ROUND_UP(capacity, PAGE_SIZE_4K);
    printf("Initializing in-memory fake file with maximum capacity of %llu pages (%llu bytes) ...\n", pagecount, pagecount * PAGE_SIZE_4K);

    // mutex for locking
    mtx_ut = alloc_retype(&mtx, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!mtx_ut, "Unable to allocate notification for fake FS");
    seL4_Signal(mtx);

    // preallocate and premap the frames
    for(size_t i = 0; i < pagecount; ++i) {
        seL4_CPtr frame;
        ZF_LOGF_IF(!alloc_retype(&frame, seL4_ARM_SmallPageObject, seL4_PageBits),
            "Failed to allocate frame");
        seL4_Error err = map_frame(&cspace, frame, seL4_CapInitThreadVSpace, SOS_FAKE_FS + PAGE_SIZE_4K * i,
            seL4_AllRights, seL4_ARM_Default_VMAttributes);
        if(err != seL4_NoError) {
            ZF_LOGF("Error mapping frame for fake file system: %d", err);
        }
    }

    // memset test
    memset((void*)SOS_FAKE_FS, 0, PAGE_SIZE_4K * pagecount);

    puts("Successfully initialized fake file system!");
    return;
}

ssize_t fake_fs_stat(seL4_Word pid, char* path, sos_stat_t* out)
{
    memset(out, 0, sizeof(sos_stat_t));
    out->st_type = ST_SPECIAL;
    out->st_fmode = FM_READ | FM_WRITE;
    out->st_size = used;
    return 0;
}

ssize_t fake_fs_opendir(seL4_Word pid, char* path)
{
    return FAKE_FS_ID;
}

ssize_t fake_fs_open(seL4_Word pid, const char* fn, int mode)
{
    return FAKE_FS_ID;
}

const char* fake_fs_dirent(seL4_Word pid, ssize_t id, size_t pos)
{
    if(id != FAKE_FS_ID) 
        return NULL;
    
    // just returning a dummy directory entries here
    switch(pos) {
        case 0:
            return "dummy";
        case 1:
            return "directory";
        default:
            return NULL;
    }
}

ssize_t fake_fs_rw(seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len, bool write)
{
    if(id != FAKE_FS_ID)
        return -EBADF;
    if(offset >= FAKE_FS_CAPACITY)
        return 0;

    seL4_Wait(mtx, NULL);
    
    // ensure that total len < our capacity
    len = MIN(FAKE_FS_CAPACITY - offset, len);
    // enlarge our "used" size if needed
    if(used < (offset + len))
        used = offset + len;

    if(!write)
        // read: copy from "file" to user's supplied ptr
        memcpy(ptr, (void*)(SOS_FAKE_FS + offset), len);
    else
        // write: copy from user's supplied ptr to "file"
        memcpy((void*)(SOS_FAKE_FS + offset), ptr, len);

    seL4_Signal(mtx);
    return len;
}

ssize_t fake_fs_read(seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len)
{
    return fake_fs_rw(pid, id, ptr, offset, len, false);
}

ssize_t fake_fs_write(seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len)
{
    return fake_fs_rw(pid, id, ptr, offset, len, true);
}
