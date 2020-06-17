#include <sel4/sel4.h>
#include <stdint.h>
#include <stdbool.h>
#include "util.h"

void* get_large_ipc_buffer(void)
{
    return (void*)((uintptr_t)seL4_GetIPCBuffer() + PAGE_SIZE_4K);
}
