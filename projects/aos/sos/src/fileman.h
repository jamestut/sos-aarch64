#pragma once

#include <sel4/sel4.h>
#include <cspace/cspace.h>
#include <stdint.h>
#include <stdbool.h>
#include <grp01/dynaarray.h>

#include "grp01.h"
#include "ut.h"

// note: for functions that return negative number when they're failing, please
//       multiply the result by -1 to get the errno.

// @param fn filename to open
//        ep endpoint to communicate with main thread
// @return negative if fail, internal file id (0 or larger) if success.
typedef ssize_t (*file_open_fn)(seL4_CPtr ep, const char* fn, int mode);

// @param id   whatever returned by file_open_fn
//        ptr  target pointer to store/read
//        len  max length to read/write
// @return negative if fail, number of bytes read/written if success. 
typedef ssize_t (*file_rw_fn)(seL4_CPtr ep, ssize_t id, void* ptr, off_t offset, size_t len);

// @param id whatever returned by file_open_fn
typedef void (*file_close_fn)(seL4_CPtr ep, ssize_t id);

// TODO: for later use, implementing a generic interface for dir only
typedef ssize_t (*file_getdirent_fn)(seL4_CPtr ep, int pos, const char* path, size_t nbyte);

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

// open a file handle.
// @return errno if failed, 0 if pending.
//         Result will be replied directly to the client once finishes,
//         using negative errno semantic.
int fileman_open(seL4_Word pid, seL4_CPtr vspace, seL4_CPtr reply, ut_t* reply_ut, userptr_t filename, size_t filename_len, int mode);

// @param fh valid file handle for the given pid returned by fileman_open
// @return 1 for immediate return, or 0 for pending operation.
int fileman_close(seL4_Word pid, seL4_CPtr reply, ut_t* reply_ut, int fh);

// write buffer to the underlying file system
// @return errno if failed, 0 if pending.
//         Result will be replied directly to the client once finishes,
//         using negative errno semantic.
int fileman_write(seL4_Word pid, seL4_CPtr vspace, int fh, seL4_CPtr reply, ut_t* reply_ut, userptr_t buff, uint32_t len, dynarray_t* userasarr);

// read to buffer from the underlying file system
// @return errno if failed, 0 if pending.
//         Result will be replied directly to the client once finishes,
//         using negative errno semantic.
int fileman_read(seL4_Word pid, seL4_CPtr vspace, int fh, seL4_CPtr reply, ut_t* reply_ut, userptr_t buff, uint32_t len, dynarray_t* userasarr);

// get the direntry from underlying FS
// @return errno if failed, 0 if pending
//         Result will be directly passedto client once finishes,
//         using negative errno semantic.  
int fileman_getdirent (seL4_Word pid, seL4_CPtr vspace, seL4_CPtr reply, ut_t* reply_ut, int fh, userptr_t path, size_t path_len);