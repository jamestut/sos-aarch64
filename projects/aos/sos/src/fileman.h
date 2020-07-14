#pragma once

#include <sel4/sel4.h>
#include <cspace/cspace.h>
#include <stdint.h>
#include <stdbool.h>
#include <grp01/dynaarray.h>
#include <sos.h>

#include "grp01.h"
#include "sel4/sel4_arch/types.h"
#include "ut.h"

// note: for functions that return negative number when they're failing, please
//       multiply the result by -1 to get the errno.

// @param fn filename to open
//        ep endpoint to communicate with main thread
// @return negative if fail, internal file id (0 or larger) if success.
typedef ssize_t (*file_open_fn)(seL4_Word pid, const char* fn, int mode);

// @param id   whatever returned by file_open_fn
//        ptr  target pointer to store/read
//        len  max length to read/write
// @return negative if fail, number of bytes read/written if success. 
typedef ssize_t (*file_rw_fn)(seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len);

// @param path file to be stat-ed for
//        out  buffer to hold the stat-ed value, if successful
// @return negative if fail, 0 if success.
typedef ssize_t (*file_stat_fn)(seL4_Word pid, char* path, sos_stat_t* out);

// @param path   directory to be opened
// @return negative if fail, ID of directory if success.
typedef ssize_t (*file_opendir_fn)(seL4_Word pid, char* path);

// @param path   directory to be opened
// @return NULL if fail or end of directory, or pointer to C string of content name if success.
//         The returned C string is expected to be valid until closedir is called on the id.
typedef const char* (*file_dirent_fn)(seL4_Word pid, ssize_t id, size_t idx);

typedef void (*file_closedir_fn)(seL4_Word pid, ssize_t id);

// @param id whatever returned by file_open_fn
typedef void (*file_close_fn)(seL4_Word pid, ssize_t id);

struct filehandler
{
    file_open_fn open;
    file_rw_fn read;
    file_rw_fn write;
    file_stat_fn stat;
    file_opendir_fn opendir;
    file_dirent_fn gdent;
    file_closedir_fn closedir;
    file_close_fn close;
};

// initialize file table manager.
// call once when SOS is starting up.
// @param p_cspace pointer to cspace shared with eventloop handler.
// @return false if init failed, true if success
bool fileman_init();

// construct a new file table for a given pid.
// @return 0 if success, errno if fail.
int fileman_create(seL4_Word pid);

// free the file table of given pid.
void fileman_destroy(seL4_Word pid);

// get the handler functions appropriate for the file name
struct filehandler* find_handler(const char* fn);

// open a file handle.
// @return negative errno if failed, 0 if pending.
//         Result will be replied directly to the client once finishes,
//         using negative errno semantic.
int fileman_open(seL4_Word pid, seL4_CPtr reply, userptr_t filename, size_t filename_len, bool dir, int mode);

// @param fh valid file handle for the given pid returned by fileman_open
// @return 1 for immediate return, or 0 for pending operation.
int fileman_close(seL4_Word pid, seL4_CPtr reply, int fh);

// write buffer to the underlying file system
// @return negative errno if failed, 0 if pending.
//         Result will be replied directly to the client once finishes,
//         using negative errno semantic.
int fileman_write(seL4_Word pid, int fh, seL4_CPtr reply, userptr_t buff, uint32_t len);

// read to buffer from the underlying file system
// @return negative errno if failed, 0 if pending.
//         Result will be replied directly to the client once finishes,
//         using negative errno semantic.
int fileman_read(seL4_Word pid, int fh, seL4_CPtr reply, userptr_t buff, uint32_t len);

// get some information about the given file name.
// @return negative errno if failed, 0 if pending.
//         Result will be replied directly to the client once finishes,
//         using negative errno semantic.
int fileman_stat(seL4_Word pid, seL4_CPtr reply, userptr_t filename, size_t filename_len);

// get the directory entry from an open directory at a given position.
// @return negative errno if failed, 0 if pending.
//         Result will be replied directly to the client once finishes,
//         using negative errno semantic.
int fileman_readdir(seL4_Word pid, int fh, seL4_CPtr reply, size_t pos, userptr_t buff, size_t bufflen);

// close a directory handle.
// @return negative errno if failed, 0 if pending.
//         Result will be replied directly to the client once finishes,
//         using negative errno semantic.
int fileman_close(seL4_Word pid, seL4_CPtr reply, int fh);
