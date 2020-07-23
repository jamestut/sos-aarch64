#include "cpiofs.h"
#include <errno.h>
#include <cpio/cpio.h>
#include <stdbool.h>
#include <utils/arith.h>
#include "../utils.h"

#define MAX_FILES 16
#define MAX_DIRENT 16
#define MAX_FILE_NAME 20

extern char _cpio_archive[];
extern char _cpio_archive_end[];

static char direntstor[MAX_DIRENT][MAX_FILE_NAME];
static char* dirent[MAX_DIRENT];
static bool dirread = false;
static size_t cpio_len;

typedef struct {
    bool used;
    uintptr_t base;
    size_t len;
} filetable_t;

filetable_t filetable[MAX_FILES];

seL4_CPtr filetablemtx;

void cpio_fs_init() {
    cpio_len = _cpio_archive_end - _cpio_archive;
    ZF_LOGF_IF(!alloc_retype(&filetablemtx, seL4_NotificationObject, seL4_NotificationBits),
        "Cannot create notification object for CPIO FS mutex");
    seL4_Signal(filetablemtx);

    for(int i=0; i<MAX_DIRENT; ++i)
        dirent[i] = direntstor[i];
}

ssize_t cpio_fs_open(seL4_Word pid, const char* fn, int mode) {
    // check if it is possible to read the file from CPIO
    unsigned long filelen;
    uintptr_t filebase = (uintptr_t)cpio_get_file(_cpio_archive, cpio_len, fn, &filelen);
    if(!filebase) 
        return -ENOENT;

    seL4_Wait(filetablemtx, NULL);
    // find a free slot
    int slot = -1;
    for(int i = 0; i < MAX_FILES; ++i) {
        if(!filetable[i].used) {
            slot = i;
            filetable[i].used = true;
            break;
        }
    }
    seL4_Signal(filetablemtx);
    if(slot < 0)
        return -ENFILE;
    
    // populate the slot
    filetable[slot].base = filebase;
    filetable[slot].len = filelen;
    return slot;
}

ssize_t cpio_fs_read(seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len) {
    filetable_t* fh = filetable + id;
    if(offset >= fh->len)
        return 0;

    size_t to_copy = MIN(len, fh->len - offset);
    memcpy(ptr, (void*)(fh->base + offset), to_copy);
    return to_copy;
}

ssize_t cpio_fs_write(seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len) {
    return 0;
}

ssize_t cpio_fs_stat(seL4_Word pid, char* path, sos_stat_t* out) {
    unsigned long sz;
    if(!cpio_get_file(_cpio_archive, cpio_len, path, &sz)) {
        return -ENOENT;
    }

    out->st_size = sz;
    out->st_fmode = FM_READ | FM_WRITE | FM_EXEC;
    out->st_type = ST_FILE;
    return 0;
}

ssize_t cpio_fs_opendir(seL4_Word pid, char* path) {
    if((strcmp(path, "") == 0) || (strcmp(path, "/") == 0)) {
        if(!dirread) {
            cpio_ls(_cpio_archive, cpio_len, dirent, sizeof(dirent));
            dirread = true;
            // clean the delimiter
            for(int i=0; i<MAX_DIRENT; ++i) {
                if(dirent[i][0] == 0) {
                    dirent[i] = 0;
                    break;
                }
            }
        }
        return MAX_FILES;
    }
    return -ENOENT;
}

const char* cpio_fs_dirent(seL4_Word pid, ssize_t id, size_t pos) {
    if(pos >= MAX_DIRENT)
        return NULL;
    return dirent[pos];
}

void cpio_fs_closedir(seL4_Word pid, ssize_t id) {}

void cpio_fs_close(seL4_Word pid, ssize_t id) {
    if(id >= 0 && id < MAX_FILES) {
        seL4_Wait(filetablemtx, NULL);
        filetable[id].used = false;
        seL4_Signal(filetablemtx);
    }
}