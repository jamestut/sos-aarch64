// just for debugging

#include <utils/zf_log_if.h>
#include <sel4/sel4.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <utils/arith.h>

#ifndef CONFIG_PLAT_ODROIDC2

void console_fs_init(void)
{
    ZF_LOGI("fake console initialized.");
}

int32_t console_fs_read(int id, void* ptr, uint32_t len)
{
    const char* dummy = "hello";
    char* target = ptr;
    // do nothing
    ZF_LOGD("fake console read.");
    int to_copy = MIN(len,5);
    for(int i=0; i<to_copy; ++i) {
        target[i] = dummy[i];
    }

    return to_copy;
}

int32_t console_fs_write(int id, void* ptr, uint32_t len)
{
    // print to tty :)
    char* cptr = ptr;
    fputs("fake console: ", stdout);
    for(int i=0; i<len; ++i)
        putchar(cptr[i]);
    return len;
}

#endif