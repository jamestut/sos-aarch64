#pragma once

#include <sel4/sel4.h>
#include <cspace/cspace.h>
#include <stdint.h>
#include <stdbool.h>

#include "ut.h"

// note: for functions that return negative number when they're failing, please
//       multiply the result by -1 to get the errno.

// @param fn filename to open
// @return negative if fail, internal file id (0 or larger) if success.
typedef int (*file_open_fn)(const char* fn, int mode);

// @param id   whatever returned by file_open_fn
//        ptr  target pointer to store/read
//        len  max length to read/write
// @return negative if fail, number of bytes read/written if success. 
typedef int32_t (*file_rw_fn)(int id, void* ptr, uint32_t len);

// @param id whatever returned by file_open_fn
typedef void (*file_close_fn)(int id);

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
//         Result will be replied directly to the client once finishes.
int fileman_open(seL4_Word pid, seL4_CPtr reply, ut_t* reply_ut, const char* filename, int mode);

// @param fh valid file handle for the given pid returned by fileman_open
void fileman_close(seL4_Word pid, int fh);

// get errno number for functions that doesn't return error code directly
int fileman_get_error(seL4_Word pid);