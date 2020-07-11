// just for debugging

#include <utils/zf_log_if.h>
#include <sel4/sel4.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <utils/arith.h>

#include "console.h"

#ifndef CONFIG_PLAT_ODROIDC2

#define FAKE_READ_LIMIT UINT64_MAX

void console_fs_init(void)
{
    ZF_LOGI("fake console initialized.");
}

ssize_t console_fs_read(UNUSED seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len)
{
    static int charidx = 0;

    size_t toread = MIN(len, FAKE_READ_LIMIT);
    char* charptr = ptr;

    for(size_t i=0; i<toread; ++i) {
        charptr[i] = 'A' + charidx;
        charidx = (charidx + 1) % 26;
    }

    return toread;
}

ssize_t console_fs_write(UNUSED seL4_Word pid, ssize_t id, void* ptr, off_t offset, size_t len)
{
    // print to tty :)
    char* cptr = ptr;
    fputs("fake console: ", stdout);
    for(size_t i=0; i<len; ++i)
        putchar(cptr[i]);
    putchar('\n');
    return len;
}

#endif