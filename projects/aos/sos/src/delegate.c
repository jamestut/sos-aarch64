#include "delegate.h"
#include "utils.h"
#include "network.h"

#include <utils/arith.h>

typedef enum {
    // generic
    INT_THRDREQ_NONE = 0,
    INT_THRDREQ_USERPTR_READ,
    INT_THRDREQ_USERPTR_WRITE_START,
    INT_THRDREQ_USERPTR_WRITE_NEXT,
    INT_THRDREQ_USERPTR_UNMAP,
    INT_THRDREQ_CAP_DELETE_FREE,
    INT_THRDREQ_UT_FREE,
} IntThreadReq;

/* ---- variables ---- */
seL4_CPtr delegate_ep;
seL4_CPtr reply_reuse_ep;

/* ---- common declarations ---- */
// we'll panic if we got a different parameter, because that's mean we have a bug!
#define PARAM_COUNT_CHECK(count, expected) {ZF_LOGF_IF((expected) != (count), "Wrong param count");}

/* ---- declaration for reply functions ---- */
void hdl_do_nothing(seL4_CPtr reply);

void hdl_userptr_read(seL4_CPtr reply);

void hdl_userptr_write_start(seL4_CPtr reply);

void hdl_userptr_write_next(seL4_CPtr reply);

void hdl_userptr_unmap(seL4_CPtr reply);

void hdl_free_cap(seL4_CPtr reply);

void hdl_free_ut(seL4_CPtr reply);

/* ---- definitions start here ---- */

void delegate_do_nothing()
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, INT_THRDREQ_NONE);
    seL4_Call(delegate_ep, msg);
}

void* delegate_userptr_read(userptr_t src, size_t len, seL4_Word badge)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 4);
    seL4_SetMR(0, INT_THRDREQ_USERPTR_READ);
    seL4_SetMR(1, src);
    seL4_SetMR(2, len);
    seL4_SetMR(3, badge);
    seL4_Call(delegate_ep, msg);
    return seL4_GetMR(0);
}

userptr_write_state_t delegate_userptr_write_start(userptr_t src, size_t len, seL4_Word badge)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 4);
    seL4_SetMR(0, INT_THRDREQ_USERPTR_WRITE_START);
    seL4_SetMR(1, src);
    seL4_SetMR(2, len);
    seL4_SetMR(3, badge);
    seL4_Call(delegate_ep, msg);
    
    userptr_write_state_t ret;
    memcpy(&ret, seL4_GetIPCBuffer()->msg, sizeof(ret));
    return ret;
}

bool delegate_userptr_write_next(userptr_write_state_t* it)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, INT_THRDREQ_USERPTR_WRITE_NEXT);
    seL4_SetMR(1, it);
    seL4_Call(delegate_ep, msg);
    return seL4_GetMR(0);
}

void delegate_userptr_unmap(void* sosaddr)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, INT_THRDREQ_USERPTR_UNMAP);
    seL4_SetMR(1, sosaddr);
    seL4_Call(delegate_ep, msg);
}

void delegate_free_cap(seL4_CPtr cap, bool del_cap, bool free_slot)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 4);
    seL4_SetMR(0, INT_THRDREQ_CAP_DELETE_FREE);
    seL4_SetMR(1, cap);
    seL4_SetMR(2, del_cap);
    seL4_SetMR(3, free_slot);
    seL4_Call(delegate_ep, msg);
}

void delegate_free_ut(ut_t* ut)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, INT_THRDREQ_UT_FREE);
    seL4_SetMR(1, ut);
    seL4_Call(delegate_ep, msg);
}

void delegate_reuse_reply(seL4_CPtr reply)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, reply);
    seL4_Call(reply_reuse_ep, msg);
}

/* ---- definitions for handler @ main thread ---- */

void delegate_init(cspace_t* srccspace, seL4_CPtr ipc_ep)
{
    delegate_ep = cspace_alloc_slot(&cspace);
    reply_reuse_ep = cspace_alloc_slot(&cspace);
    ZF_LOGF_IF(!(delegate_ep && reply_reuse_ep), "Failed to allocate endpoint slot for delegate");
    ZF_LOGF_IF(cspace_mint(&cspace, delegate_ep, srccspace, ipc_ep, seL4_AllRights, BADGE_DELEGATE) != seL4_NoError,
        "Error minting endpoint for delegate");
    ZF_LOGF_IF(cspace_mint(&cspace, reply_reuse_ep, srccspace, ipc_ep, seL4_AllRights, BADGE_REPLY_RET) != seL4_NoError,
        "Error minting endpoint for delegate");
}

void handle_delegate_req(seL4_Word badge, seL4_Word msglen, seL4_CPtr reply)
{
    ZF_LOGD("Got internal request from thread %d\n", badge);
    IntThreadReq cmd = seL4_GetMR(0);
    switch(cmd) {
        case INT_THRDREQ_NONE:
            PARAM_COUNT_CHECK(msglen, 1);
            hdl_do_nothing(reply);
            break;

        case INT_THRDREQ_USERPTR_READ:
            PARAM_COUNT_CHECK(msglen, 4);
            hdl_userptr_read(reply);
            break;

        case INT_THRDREQ_USERPTR_WRITE_START:
            PARAM_COUNT_CHECK(msglen, 4);
            hdl_userptr_write_start(reply);
            break;

        case INT_THRDREQ_USERPTR_WRITE_NEXT:
            PARAM_COUNT_CHECK(msglen, 2);
            hdl_userptr_write_next(reply);
            break;

        case INT_THRDREQ_USERPTR_UNMAP:
            PARAM_COUNT_CHECK(msglen, 2);
            hdl_userptr_unmap(reply);
            break;

        case INT_THRDREQ_CAP_DELETE_FREE:
            PARAM_COUNT_CHECK(msglen, 4);
            hdl_free_cap(reply);
            break;

        case INT_THRDREQ_UT_FREE:
            PARAM_COUNT_CHECK(msglen, 2);
            hdl_free_ut(reply);
            break;
        
        default:
            ZF_LOGF("Unknown request code!");
    }
}

void hdl_do_nothing(seL4_CPtr reply) 
{
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 0);
    seL4_Send(reply, reply_msg);
}

void hdl_userptr_read(seL4_CPtr reply)
{
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    uintptr_t ret = (uintptr_t)userptr_read(seL4_GetMR(1), seL4_GetMR(2), seL4_GetMR(3));
    seL4_SetMR(0, ret);
    seL4_Send(reply, reply_msg);
}

void hdl_userptr_write_start(seL4_CPtr reply)
{
    userptr_write_state_t ret = userptr_write_start(seL4_GetMR(1), seL4_GetMR(2), seL4_GetMR(3));
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, DIV_ROUND_UP(sizeof(ret), sizeof(seL4_Word)));
    memcpy(seL4_GetIPCBuffer()->msg, &ret, sizeof(ret));
    seL4_Send(reply, reply_msg);
}

void hdl_userptr_write_next(seL4_CPtr reply)
{
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    bool ret = userptr_write_next((userptr_write_state_t*)seL4_GetMR(1));
    seL4_SetMR(0, ret);
    seL4_Send(reply, reply_msg);
}

void hdl_userptr_unmap(seL4_CPtr reply)
{
    userptr_unmap((void*)seL4_GetMR(1));
    hdl_do_nothing(reply);
}

void hdl_free_cap(seL4_CPtr reply)
{
    if(seL4_GetMR(2))
        cspace_delete(&cspace, seL4_GetMR(1));
    if(seL4_GetMR(3))
        cspace_free_slot(&cspace, seL4_GetMR(1));
    hdl_do_nothing(reply);
}

void hdl_free_ut(seL4_CPtr reply)
{
    ut_free((ut_t*)seL4_GetMR(1));
    hdl_do_nothing(reply);
}
