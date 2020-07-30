#include "delegate.h"
#include "utils.h"
#include "network.h"
#include "vmem_layout.h"
#include "procman.h"

#include <utils/arith.h>

extern dynarray_t scratchas;

_Static_assert(sizeof(seL4_Word) == sizeof(uint64_t), "requires 64 bit platform");

typedef enum {
    // generic
    INT_THRDREQ_NONE = 0,
    INT_THRDREQ_USERPTR_READ,
    INT_THRDREQ_USERPTR_WRITE_START,
    INT_THRDREQ_USERPTR_WRITE_NEXT,
    INT_THRDREQ_USERPTR_UNMAP,
    INT_THRDREQ_CAP_DELETE_FREE,
    INT_THRDREQ_UT_FREE,
    INT_THRDREQ_FT_ALLOC_FRAME,
    INT_THRDREQ_FT_FRAME_SET_PIN,
    INT_THRDREQ_FT_FRAME_DATA,
    INT_THRDREQ_FT_FREE_FRAME,
    INT_THRDREQ_VM_MAP_FRAME,
    INT_THRDREQ_VM_GET_FRAME,
    INT_THRDREQ_SOS_FILE_MAP,
    INT_THRDREQ_SOS_ALLOC_SCRATCH,
    INT_THRDREQ_SOS_FREE_SCRATCH,
    INT_THRDREQ_PROCMAN_DESTROY_PROC,
    
    // sentinel value
    INT_THRDREQ_COUNT
} IntThreadReq;

/* ---- variables ---- */
seL4_CPtr delegate_ep;
seL4_CPtr reply_reuse_ep;

/* ---- declaration for reply functions ---- */
void hdl_do_nothing(seL4_CPtr reply);

void hdl_userptr_read(seL4_CPtr reply);

void hdl_userptr_write_start(seL4_CPtr reply);

void hdl_userptr_write_next(seL4_CPtr reply);

void hdl_userptr_unmap(seL4_CPtr reply);

void hdl_free_cap(seL4_CPtr reply);

void hdl_free_ut(seL4_CPtr reply);

void hdl_ft_alloc_frame(seL4_CPtr reply);

void hdl_ft_frame_set_pin(seL4_CPtr reply);

void hdl_ft_frame_data(seL4_CPtr reply);

void hdl_ft_free_frame(seL4_CPtr reply);

void hdl_vm_map_frame(seL4_CPtr reply);

void hdl_vm_get_frame(seL4_CPtr reply);

void hdl_sos_file_map(seL4_CPtr reply);

void hdl_sos_alloc_scratch(seL4_CPtr reply);

void hdl_sos_free_scratch(seL4_CPtr reply);

void hdl_procman_destroy_proc(seL4_CPtr reply);

// WARNING: order of declaration must follow that of IntThreadReq
struct {
    void (*handler)(seL4_CPtr);
    unsigned short code;
    unsigned short expected_param;
} handlers[] = {
    {hdl_do_nothing, INT_THRDREQ_NONE, 0},
    {hdl_userptr_read, INT_THRDREQ_USERPTR_READ, 4},
    {hdl_userptr_write_start, INT_THRDREQ_USERPTR_WRITE_START, 4},
    {hdl_userptr_write_next, INT_THRDREQ_USERPTR_WRITE_NEXT, 2},
    {hdl_userptr_unmap, INT_THRDREQ_USERPTR_UNMAP, 2},
    {hdl_free_cap, INT_THRDREQ_CAP_DELETE_FREE, 4},
    {hdl_free_ut, INT_THRDREQ_UT_FREE, 2},
    {hdl_ft_alloc_frame, INT_THRDREQ_FT_ALLOC_FRAME, 1},
    {hdl_ft_frame_set_pin, INT_THRDREQ_FT_FRAME_SET_PIN, 3},
    {hdl_ft_frame_data, INT_THRDREQ_FT_FRAME_DATA, 2},
    {hdl_ft_free_frame, INT_THRDREQ_FT_FREE_FRAME, 2},
    {hdl_vm_map_frame, INT_THRDREQ_VM_MAP_FRAME, 8},
    {hdl_vm_get_frame, INT_THRDREQ_VM_GET_FRAME, 3},
    {hdl_sos_file_map, INT_THRDREQ_SOS_FILE_MAP, 4},
    {hdl_sos_alloc_scratch, INT_THRDREQ_SOS_ALLOC_SCRATCH, 2},
    {hdl_sos_free_scratch, INT_THRDREQ_SOS_FREE_SCRATCH, 2},
    {hdl_procman_destroy_proc, INT_THRDREQ_PROCMAN_DESTROY_PROC, 2},
};

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

frame_ref_t delegate_alloc_frame()
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, INT_THRDREQ_FT_ALLOC_FRAME);
    seL4_Call(delegate_ep, msg);
    return seL4_GetMR(0);
}

void delegate_free_frame(frame_ref_t frame_ref)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, INT_THRDREQ_FT_FREE_FRAME);
    seL4_SetMR(1, frame_ref);
    seL4_Call(delegate_ep, msg);
}

bool delegate_frame_set_pin(frame_ref_t frame_ref, bool pin)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 3);
    seL4_SetMR(0, INT_THRDREQ_FT_FRAME_SET_PIN);
    seL4_SetMR(1, frame_ref);
    seL4_SetMR(2, pin);
    seL4_Call(delegate_ep, msg);
    return seL4_GetMR(0);
}

void* delegate_frame_data(frame_ref_t frame_ref)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, INT_THRDREQ_FT_FRAME_DATA);
    seL4_SetMR(1, frame_ref);
    seL4_Call(delegate_ep, msg);
    return seL4_GetMR(0);
}

seL4_Error delegate_map_frame(seL4_Word badge, frame_ref_t frameref, bool free_frame_on_delete, bool unpin_on_unmap,
                     seL4_Word vaddr, seL4_CapRights_t rights, seL4_ARM_VMAttributes attr)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 8);
    seL4_SetMR(0, INT_THRDREQ_VM_MAP_FRAME);
    seL4_SetMR(1, badge);
    seL4_SetMR(2, frameref);
    seL4_SetMR(3, free_frame_on_delete);
    seL4_SetMR(4, unpin_on_unmap);
    seL4_SetMR(5, vaddr);
    seL4_SetMR(6, rights.words[0]);
    seL4_SetMR(7, attr);
    seL4_Call(delegate_ep, msg);
    return seL4_GetMR(0);
}

frame_ref_t delegate_get_frame(seL4_Word badge, seL4_Word vaddr)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 3);
    seL4_SetMR(0, INT_THRDREQ_VM_GET_FRAME);
    seL4_SetMR(1, badge);
    seL4_SetMR(2, vaddr);
    seL4_Call(delegate_ep, msg);
    return seL4_GetMR(0);
}

uintptr_t delegate_allocate_sos_scratch(size_t size)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, INT_THRDREQ_SOS_ALLOC_SCRATCH);
    seL4_SetMR(1, size);
    seL4_Call(delegate_ep, msg);
    return seL4_GetMR(0);
}

bool delegate_file_backed_sos_map(sos_filehandle_t* fh, uintptr_t base, size_t size_bytes)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 4);
    seL4_SetMR(0, INT_THRDREQ_SOS_FILE_MAP);
    seL4_SetMR(1, fh);
    seL4_SetMR(2, base);
    seL4_SetMR(3, size_bytes);
    seL4_Call(delegate_ep, msg);
    return seL4_GetMR(0);
}

void delegate_free_sos_scratch(uintptr_t base)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, INT_THRDREQ_SOS_FREE_SCRATCH);
    seL4_SetMR(1, base);
    seL4_Call(delegate_ep, msg);
}

void delegate_destroy_process(sos_pid_t pid)
{
    seL4_MessageInfo_t msg = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, INT_THRDREQ_PROCMAN_DESTROY_PROC);
    seL4_SetMR(1, pid);
    seL4_Call(delegate_ep, msg);
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
    
    // ensure constant time lookup
    ZF_LOGF_IF(cmd >= INT_THRDREQ_COUNT, "Unknown command received");
    assert(handlers[cmd].code == cmd);

    assert(handlers[cmd].expected_param == msglen);
    handlers[cmd].handler(reply);
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

void hdl_ft_alloc_frame(seL4_CPtr reply)
{
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);   
    seL4_SetMR(0, alloc_frame());
    seL4_Send(reply, reply_msg);
}

void hdl_ft_frame_set_pin(seL4_CPtr reply)
{
    bool rs = frame_set_pin(seL4_GetMR(1), seL4_GetMR(2));
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);   
    seL4_SetMR(0, rs);
    seL4_Send(reply, reply_msg);
}

void hdl_ft_frame_data(seL4_CPtr reply)
{
    void* rs = frame_data(seL4_GetMR(1));
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);   
    seL4_SetMR(0, (seL4_Word)rs);
    seL4_Send(reply, reply_msg);
}

void hdl_ft_free_frame(seL4_CPtr reply)
{
    free_frame(seL4_GetMR(1));
    hdl_do_nothing(reply);
}

void hdl_vm_map_frame(seL4_CPtr reply)
{
    seL4_CapRights_t rights;
    rights.words[0] = seL4_GetMR(6);
    seL4_Error err = grp01_map_frame(seL4_GetMR(1), seL4_GetMR(2), seL4_GetMR(3), seL4_GetMR(4),
        seL4_GetMR(5), rights, seL4_GetMR(7));
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);   
    seL4_SetMR(0, err);
    seL4_Send(reply, reply_msg);
}

void hdl_vm_get_frame(seL4_CPtr reply)
{
    frame_ref_t rs = grp01_get_frame(seL4_GetMR(1), seL4_GetMR(2));
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);   
    seL4_SetMR(0, rs);
    seL4_Send(reply, reply_msg);
}

void hdl_sos_file_map(seL4_CPtr reply)
{
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    sos_filehandle_t* fh = seL4_GetMR(1);
    uintptr_t base = seL4_GetMR(2);
    size_t pagecount = DIV_ROUND_UP(seL4_GetMR(3), PAGE_SIZE_4K);
    bool ret = false;

    for(size_t i = 0; i < pagecount; ++i) {
        frame_ref_t fr = alloc_frame();
        if(!fr) {
            ZF_LOGE("Failed to allocate frame");
            goto fail;
        }
        frame_set_file_backing(fr, fh, i);
        seL4_Error err = grp01_map_frame(0, fr, true, false, base + PAGE_SIZE_4K * i, 
            seL4_AllRights, seL4_ARM_Default_VMAttributes);
        if(err != seL4_NoError) {
            ZF_LOGE("Failed to file map for SOS");
            goto fail;
        }
    }
    
    ret = true;
    goto finish;

fail:
    ret = false;
    grp01_unmap_frame(0, base, base + pagecount * PAGE_SIZE_4K, false);

finish:
    seL4_SetMR(0, ret);
    seL4_Send(reply, reply_msg);
}

void hdl_sos_alloc_scratch(seL4_CPtr reply)
{
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    uintptr_t ret = 0;
    size_t sz = seL4_GetMR(1);
    if(!sz)
        goto finish;
    size_t pagecount = DIV_ROUND_UP(sz, PAGE_SIZE_4K);

    // check if we have enough scratch vmem to handle this
    ret = addrspace_find_free_reg(&scratchas, sz, SOS_SCRATCH, VMEM_TOP);
    if(!ret) {
        ZF_LOGE("Cannot find enough scratch region to hold requested data");
        goto finish;
    }

    addrspace_t curras;
    curras.attr.type = AS_NORMAL;
    curras.perm = seL4_CapRights_new(false, false, true, true);
    curras.begin = ret;
    curras.end = ret + pagecount * PAGE_SIZE_4K;
    if(addrspace_add(&scratchas, curras, false, NULL) != AS_ADD_NOERR) {
        ZF_LOGE("Cannot create scratch address space");
        ret = 0;
        goto finish;
    }

finish:
    seL4_SetMR(0, ret);
    seL4_Send(reply, reply_msg);
}

void hdl_sos_free_scratch(seL4_CPtr reply)
{
    int asidx = addrspace_find(&scratchas, reply);
    if(asidx >= 0) {
        addrspace_t* as = (addrspace_t*)scratchas.data + asidx;
        grp01_unmap_frame(0, as->begin, as->end, false);
        addrspace_remove(&scratchas, asidx);
    }
    hdl_do_nothing(reply);
}

void hdl_procman_destroy_proc(seL4_CPtr reply)
{
    destroy_process(seL4_GetMR(1));
    hdl_do_nothing(reply);
}
