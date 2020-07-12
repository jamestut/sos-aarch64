#include "fake.h"
#include <stdbool.h>
#include <utils/util.h>
#include <errno.h>
#include "../utils.h"
#include "../frame_table.h"
#include "../vm/mapping2.h"
#include "../vmem_layout.h"

#define FAKE_FS_ID 123
#define FAKE_FS_CAPACITY (pagecount * PAGE_SIZE_4K)

// fields. the fake FS is basically an ADO
bool active = false;
size_t pagecount = 0;
size_t used = 0;

// make the file atomic!
seL4_CPtr mtx = 0;
ut_t* mtx_ut = NULL;


// since our frame_ref_t is capped to 19 bits, we can use 32 bit
// integer here instead of the default frame_ref_t.
uint32_t* frames;

ssize_t fake_fs_rw(seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len, bool write);

void fake_fs_init(size_t capacity)
{
    pagecount = DIV_ROUND_UP(capacity, PAGE_SIZE_4K);
    printf("Initializing in-memory fake file with maximum capacity of %llu pages (%llu bytes) ...\n", pagecount * PAGE_SIZE_4K, pagecount);

    // mutex for locking
    mtx_ut = alloc_retype(&mtx, seL4_NotificationObject, seL4_NotificationBits);
    if(!mtx_ut) {
        goto error_01;
    }
    seL4_Signal(mtx);
    
    // allocate table
    frames = malloc(pagecount * sizeof(uint32_t));
    if(!frames) {
        ZF_LOGE("Failed to malloc frame table for fake file system");
        goto error_02;
    }

    // preallocate frames
    for(size_t i = 0; i < pagecount; ++i) {
        frames[i] = alloc_frame();
        if(!frames[i]) {
            // error. dealloc
            ZF_LOGE("Failed to allocate frame for fake file system");
            for(size_t j = 0; j < i; ++j)
                free_frame(frames[i]);
            goto error_03;
        }
        frame_set_pin(frames[i], true);
    }

    // premap the frames
    for(size_t i = 0; i < pagecount; ++i) {
        seL4_Error err = grp01_map_frame(0, frames[i], false, SOS_FAKE_FS + PAGE_SIZE_4K * i, 
            seL4_AllRights, seL4_ARM_Default_VMAttributes);
        if(err != seL4_NoError) {
            ZF_LOGE("Error mapping frame for fake file system: %d", err);
            grp01_unmap_frame(0, SOS_FAKE_FS, SOS_FAKE_FS + PAGE_SIZE_4K * i, false);
            goto error_04;
        }
    }

    // memset test
    memset((void*)SOS_FAKE_FS, 0, PAGE_SIZE_4K * pagecount);

    puts("Successfully initialized fake file system!");
    return;

error_04:
    for(size_t i = 0; i < pagecount; ++i) 
        free_frame(frames[i]);
error_03:
    free(frames);
error_02:
    cspace_delete(&cspace, mtx);
    cspace_free_slot(&cspace, mtx);
    ut_free(mtx_ut);
error_01:
    pagecount = 0;
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
