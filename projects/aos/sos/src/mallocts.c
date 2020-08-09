// thread safe operations to musl's allocator.
// requires a modified version of musl (the one that ships with this repo),
// where malloc is declared as a weak symbol.

#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>
#include <utils/util.h>
#include <stdarg.h>
#include <cspace/cspace.h>
#include "utils.h"
#include "threads.h"
#include "threadassert.h"
#include "mallocts.h"

typedef enum {
    MALLOC_OPS_NONE = 0,
    MALLOC_OPS_MALLOC,
    MALLOC_OPS_MALLOC0,
    MALLOC_OPS_REALLOC,
    MALLOC_OPS_FREE
} MallocOps;

static seL4_CPtr malloc_ep = 0;
static seL4_CPtr malloc_reply = 0;
static sos_thread_t* malloc_thread = NULL;

// for initialisation
static seL4_CPtr malloc_ntfn;
static ut_t* malloc_ntfn_ut;

static void malloc_thread_entry(UNUSED void* param);

static inline bool use_delegate() 
{
    // must has an endpoint and not in malloc thread
    return malloc_ep && (current_thread != malloc_thread);
}

static uintptr_t do_delegate(seL4_Word cmd, size_t msgcount, ...) 
{
    va_list args;
    va_start(args, msgcount);
    
    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, msgcount + 1);
    seL4_SetMR(0, cmd);
    for(size_t i = 0; i < msgcount; ++i) {
        seL4_SetMR(i + 1, va_arg(args, seL4_Word));
    }
    seL4_Call(malloc_ep, msginfo);
    return seL4_GetMR(0);
}

void malloc_ts_init(void)
{
    malloc_ntfn_ut = alloc_retype(&malloc_ntfn, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!malloc_ntfn_ut, "Error creating malloc thread initializer notification");

    seL4_Poll(malloc_ntfn, NULL);

    // spawn needs malloc internally!
    malloc_thread = spawn(malloc_thread_entry, NULL, "malloc_thread", 0);
    ZF_LOGF_IF(!malloc_thread, "Unable to spawn malloc thread");

    ZF_LOGF_IF(!alloc_retype(&malloc_ep, seL4_EndpointObject, seL4_EndpointBits),
        "Error allocating endpoint for malloc");
    ZF_LOGF_IF(!alloc_retype(&malloc_reply, seL4_ReplyObject, seL4_ReplyBits),
        "Error allocating reply objec for malloc delegate");

    // done. signal thread to proceed.
    seL4_Signal(malloc_ntfn);
}

void *malloc(size_t n) 
{
    if(use_delegate())
        return do_delegate(MALLOC_OPS_MALLOC, 1, n);
    return __malloc_full(n);
}

void *__malloc0(size_t n) 
{
    if(use_delegate())
        return do_delegate(MALLOC_OPS_MALLOC0, 1, n);
    return __malloc0_full(n);
}

void *realloc(void *p, size_t n)
{
    if(use_delegate())
        return do_delegate(MALLOC_OPS_REALLOC, 2, p, n);
    return __realloc_full(p, n);
}

void free(void* p)
{
    if(use_delegate())
        do_delegate(MALLOC_OPS_FREE, 1, p);
    else
        __free_full(p);
}

static inline void malloc_delegate(seL4_CPtr reply) 
{
    seL4_Word ret = 0;
    int hasret;
    switch(seL4_GetMR(0)) {
        case MALLOC_OPS_MALLOC:
            hasret = 1;
            ret = __malloc_full(seL4_GetMR(1));
            break;
        case MALLOC_OPS_MALLOC0:
            hasret = 1;
            ret = __malloc0_full(seL4_GetMR(1));
            break;
        case MALLOC_OPS_REALLOC:
            hasret = 1;
            ret = __realloc_full(seL4_GetMR(1), seL4_GetMR(2));
            break;
        case MALLOC_OPS_FREE:
            hasret = 0;
            __free_full(seL4_GetMR(1));
            break;
        default:
            ZF_LOGF("Unknown malloc command");
    }

    seL4_MessageInfo_t msginfo = seL4_MessageInfo_new(0, 0, 0, hasret);
    seL4_SetMR(0, ret);
    seL4_Send(reply, msginfo);
}

static void malloc_thread_entry(void* param)
{
    // wait until our endpoints are ready!
    seL4_Wait(malloc_ntfn, NULL);

    for(;;) {
        seL4_Word badge;
        seL4_MessageInfo_t message = seL4_Recv(malloc_ep, &badge, malloc_reply);
        malloc_delegate(malloc_reply);
    }
}