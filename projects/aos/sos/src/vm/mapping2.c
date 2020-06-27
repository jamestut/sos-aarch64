// This mapping keeps the bookkeeping of page directories and page tables
// for each vspaces. Need initialisation for every vspaces to be managed.
// Can be used safely with the original SOS mapping.
// however, PDs and PTs allocated by SOS mapping won't be tracked.

// these code will only work on AArch64 and nothing else!

#include "mapping2.h"
#include "../frame_table.h"
#include "../utils.h"
#include "../vmem_layout.h"
#include <sync/mutex.h>
#include <sys/types.h>
#include <utils/zf_log_if.h>
#include <sel4/sel4_arch/mapping.h>

#define BK_BUCKETS 4
#define FRAME_TABLE_BITS 19
#define FR_FLAG_AREA     0xFF00000000000000ULL
#define FR_FLAG_REF_AREA (~FR_FLAG_AREA)

typedef enum {
    PT_PGD = 3,
    PT_PUD = 2,
    PT_PD  = 1,
    PT_PT  = 0,
    PT_UNDEFINED = -1
} PDType;

typedef enum {
    FR_FLAG_NOERASE = 0x8000000000000000ULL
} FrameRefFlag;

// ---- macro section ----

// index to page table. use PDType above for type param.
// AArch64 has 48 bits of vaddr, not 64 bit
#define PD_INDEX(vaddr, type) \
    ({ uintptr_t _vaddr = (vaddr); \
       size_t _type = (type); \
       (_vaddr >> (12 + _type * 9)) & 0x1FF; })

#define PD_INDEX_VADDR(ind) \
    ((((uintptr_t)(ind).str.pt) << 12) | (((uintptr_t)(ind).str.pd) << 21) | (((uintptr_t)(ind).str.pud) << 30) | (((uintptr_t)(ind).str.pgd) << 39))

// ---- local functions section ----
// for debugging
size_t PD_INDEX_MACROEXP(uintptr_t vaddr, size_t type) {return PD_INDEX(vaddr, type);}

size_t PD_INDEX_VADDR_MACROEXP(pd_indices_t ind) {return PD_INDEX_VADDR(ind);}

inline bool userptr_single_map(uintptr_t local, pd_indices_t useridx, 
    seL4_CapRights_t userright, seL4_Word pid);

#define PD_ENTRY(pd, idx) \
    (((struct pagedir*)frame_data((pd).dir))[(idx)])

PACKED struct pagedir {
    // this frame contains array of child page directories (this structure)
    frame_ref_t dir : FRAME_TABLE_BITS;
    
    // this frame contains array of actual page directories caps
    frame_ref_t cap : FRAME_TABLE_BITS;
    
    // this frame contains array of ut_t that backs the capabilities of the directory
    frame_ref_t ut : FRAME_TABLE_BITS;

    size_t unused : 64 - FRAME_TABLE_BITS*3;
};

static_assert(sizeof(struct pagedir) == sizeof(size_t));

struct bookkeeping {
    // the vspace will be always generated from SOS' cspace.
    // therefore, we can just use a vspace CPtr to identify a bookeeping item.
    seL4_CPtr vspace;

    // shadow PGD that store PUDs (untyped, actual/hardware, and shadow)
    struct pagedir sh_pgd;
};

// buckets used to bookeep page table objects.
// we won't need lock for this structure because we are event based
struct bookkeeping bk[MAX_PID];

extern dynarray_t scratchas;
extern sync_mutex_t scratch_lock;

void grp01_map_bookkeep_init()
{
    memset(bk, 0, sizeof(bk));
}

bool grp01_map_init(seL4_Word badge, seL4_CPtr vspace)
{
    // check if badge is valid :)
    // badge == 0 means we're managing SOS' (not used for now)
    if(badge >= MAX_PID)
        return false;
    
    // check if this vspace is not managed by us yet. also find the slot.
    struct bookkeeping* lbk = bk + badge;
    ZF_LOGF_IF(lbk->vspace, "Attempt to manage page directory for process %ld twice!", badge);

    // we expect that this structure is pristine and empty when vspace == 0!
    lbk->vspace = vspace;

    return true;
}

seL4_Error grp01_map_frame(seL4_Word badge, frame_ref_t frameref, bool free_frame_on_delete, seL4_CPtr vspace, seL4_Word vaddr, seL4_CapRights_t rights,
                     seL4_ARM_VMAttributes attr)
{
    // simply refuse to map NULL
    if(!vaddr)
        return seL4_IllegalOperation;

    if(badge >= MAX_PID || !vspace)
        return seL4_RangeError;

    // find the bucket
    struct bookkeeping* lbk = bk + badge;
    if(lbk->vspace != vspace)
        return seL4_InvalidArgument;

    // allocate shadow tables if not allocated yet for the given vaddr
    struct pagedir* ppd = &lbk->sh_pgd;
    for(PDType pdtype=PT_PGD; pdtype>PT_PT; --pdtype) {
        if(!ppd->dir) {
            if(!(ppd->dir = alloc_empty_frame())) {
                ZF_LOGE("Cannot allocate frame for shadow page directory");
                return seL4_NotEnoughMemory;
            }
        }
        ppd = ((struct pagedir*)frame_data(ppd->dir)) + PD_INDEX(vaddr, pdtype);
    }
    // shadow PT
    // allocate frame for PT, for storing frame ref and cptr to mapped frame
    if(!ppd->dir) {
        ppd->dir = alloc_empty_frame();
        if(!ppd->dir) {
            ZF_LOGE("Cannot allocate frame for page table");
            return seL4_NotEnoughMemory;
        }
    }
    if(!ppd->cap) {
        ppd->cap = alloc_empty_frame();
        if(!ppd->cap) {
            ZF_LOGE("Cannot allocate frame for page table");
            return seL4_NotEnoughMemory;
        }
    }

    seL4_Error err;

    // check if frame is already mapped to our data structure
    if(((frame_ref_t*)frame_data(ppd->dir))[PD_INDEX(vaddr, PT_PT)]) 
        return seL4_DeleteFirst;

    // copy the frame cap so that we can map it to target vspace
    // because frame table is already mapping the frame
    seL4_CPtr mapped_frame = cspace_alloc_slot(&cspace);
    if(mapped_frame == NULL_FRAME) {
        ZF_LOGE("Cannot allocate cspace slot to map frame");
        return seL4_NotEnoughMemory;
    }
    err = cspace_copy(&cspace, mapped_frame, &cspace, frame_page(frameref), seL4_AllRights);
    if(err != seL4_NoError) {
        ZF_LOGE("Cannot copy frame capability for mapping: %d\n", err);
        return err;
    }

    // try allocating for PUD/PD/PT
    err = seL4_ARM_Page_Map(mapped_frame, vspace, vaddr, rights, attr);
    
    for (size_t i = 0; i < MAPPING_SLOTS && err == seL4_FailedLookup; i++) {
        /* save this so nothing else trashes the message register value */
        seL4_Word failed = seL4_MappingFailedLookupLevel();

        // select the container (directory) of the requested object
        struct pagedir * contpd;
        PDType conttype;
        seL4_Word targetpdtype;
        switch (failed) {
        case SEL4_MAPPING_LOOKUP_NO_PT:
            contpd = &PD_ENTRY(
                PD_ENTRY(
                    PD_ENTRY(
                        lbk->sh_pgd, PD_INDEX(vaddr, PT_PGD)
                    ), PD_INDEX(vaddr, PT_PUD)
                ), PD_INDEX(vaddr, PT_PD));
            conttype = PT_PD;
            targetpdtype = seL4_ARM_PageTableObject;
            break;

        case SEL4_MAPPING_LOOKUP_NO_PD:
            contpd = &PD_ENTRY(
                    PD_ENTRY(
                        lbk->sh_pgd, PD_INDEX(vaddr, PT_PGD)
                    ), PD_INDEX(vaddr, PT_PUD));
            conttype = PT_PUD;
            targetpdtype = seL4_ARM_PageDirectoryObject;
            break;

        case SEL4_MAPPING_LOOKUP_NO_PUD:
            contpd = &PD_ENTRY(lbk->sh_pgd, PD_INDEX(vaddr, PT_PGD));
            conttype = PT_PGD;
            targetpdtype = seL4_ARM_PageUpperDirectoryObject;
            break;

        default:
            // either we forgot to map the vspace, or something really bad happened.
            ZF_LOGE("seL4 give unknown mapping error: %ld", failed);
            return err;
        }

        // allocate a new page directory frame
        if(!contpd->ut) {
            contpd->ut = alloc_empty_frame();
            if(!contpd->ut) {
                ZF_LOGE("Cannot allocate frame for untyped table.");
                return seL4_NotEnoughMemory;
            }
        }

        ut_t* ut_pd = ((ut_t**)frame_data(contpd->ut))[PD_INDEX(vaddr, conttype)] = ut_alloc_4k_untyped(NULL);
        if(!ut_pd) {
            ZF_LOGE("Failed to allocate frame for hardware page directory");
            return seL4_NotEnoughMemory;
        }

        // create cspace slot for this new page table
        if(!contpd->cap) {
            contpd->cap = alloc_empty_frame();
            if(!contpd->ut) {
                ZF_LOGE("Cannot allocate frame for capabilities table.");
                return seL4_NotEnoughMemory;
            }
        }
            
        seL4_CPtr* pd_cap = (seL4_CPtr*)frame_data(contpd->cap) + PD_INDEX(vaddr, conttype);
        if((*pd_cap = cspace_alloc_slot(&cspace)) == seL4_CapNull) {
            ZF_LOGE("Failed to allocate cspace slot for page directory");
            ut_free(ut_pd);
            return seL4_NotEnoughMemory;
        }

        // retype UT to the appropriate PD type
        err = cspace_untyped_retype(&cspace, ut_pd->cap, *pd_cap, targetpdtype, seL4_PageBits);
        if(err) {
            ZF_LOGE("Failed to retype page directory: %d", err);
            cspace_free_slot(&cspace, *pd_cap);
            ut_free(ut_pd);
            return err;
        }

        // map the PD to seL4
        switch(targetpdtype) {
            case seL4_ARM_PageUpperDirectoryObject:
                err = seL4_ARM_PageUpperDirectory_Map(*pd_cap, vspace, vaddr, seL4_ARM_Default_VMAttributes);
                break;
            case seL4_ARM_PageDirectoryObject:
                err = seL4_ARM_PageDirectory_Map(*pd_cap, vspace, vaddr, seL4_ARM_Default_VMAttributes);
                break;
            case seL4_ARM_PageTableObject:
                err = seL4_ARM_PageTable_Map(*pd_cap, vspace, vaddr, seL4_ARM_Default_VMAttributes);
                break;
            default:
                ZF_LOGF("Got unforeseen type.");
        }

        if(err) {
            ZF_LOGE("Cannot map page directory.");
            return err;
        }

        // try mapping again
        err = seL4_ARM_Page_Map(mapped_frame, vspace, vaddr, rights, attr);
    }

    // if err here is noerr, it means that we've mapped the frame successfully
    if(err == seL4_NoError) {
        // take note the frame to PT
        ((frame_ref_t*)frame_data(ppd->dir))[PD_INDEX(vaddr, PT_PT)] = frameref 
            | (free_frame_on_delete ? 0 : FR_FLAG_NOERASE);
        ((seL4_CPtr*)frame_data(ppd->cap))[PD_INDEX(vaddr, PT_PT)] = mapped_frame;
    } else {
        // free up the frames that we've allocated
        cspace_delete(&cspace, mapped_frame);
        cspace_free_slot(&cspace, mapped_frame);
        if(free_frame_on_delete)
            free_frame(frameref);
    }

    return err;
}

seL4_Error grp01_unmap_frame(seL4_Word badge, seL4_CPtr vspace, seL4_Word vaddrbegin, seL4_Word vaddrend)
{
    // must pass a page aligned address here!
    ZF_LOGF_IF((vaddrbegin % PAGE_SIZE_4K) || (vaddrend % PAGE_SIZE_4K), "vaddr not page aligned");
    if(vaddrend < vaddrbegin)
        return seL4_RangeError;

    if(badge >= MAX_PID || !vspace)
        return seL4_RangeError;

    // find the bucket
    struct bookkeeping* lbk = bk + badge;
    if(lbk->vspace != vspace)
        return seL4_InvalidArgument;

    ssize_t numpages = (vaddrend - vaddrbegin) >> seL4_PageBits;

    uint16_t indices[4];
    for(int i = PT_PT; i <= PT_PGD; ++i)
        indices[i] = PD_INDEX(vaddrbegin, i);
    
    struct pagedir pud, pd, pt;
    frame_ref_t* fr;
    seL4_CPtr* frcap;

    while(numpages) { // PGD
        ZF_LOGF_IF(indices[PT_PGD] >= 512, "vaddr out of bound");
        pud = PD_ENTRY(lbk->sh_pgd, indices[PT_PGD]);
        if(pud.dir) {
            while(numpages) { // PUD
                pd = PD_ENTRY(pud, indices[PT_PUD]);
                if(pd.dir) {
                    while(numpages) { // PD
                        pt = PD_ENTRY(pd, indices[PT_PD]);
                        if(pt.dir) {
                            ZF_LOGF_IF(!pt.cap, "Page table has frame table but no capability table");
                            while(numpages) { // PT
                                fr = ((frame_ref_t*)frame_data(pt.dir)) + indices[PT_PT];
                                if(*fr) {
                                    // the actual unmapping
                                    frcap = ((frame_ref_t*)frame_data(pt.cap)) + indices[PT_PT];
                                    ZF_LOGE_IF(seL4_ARM_Page_Unmap(*frcap) != seL4_NoError,
                                        "Error unmapping frame");
                                    // free the duplicated capability
                                    ZF_LOGE_IF(cspace_delete(&cspace, *frcap) != seL4_NoError,
                                        "Error deleting capability for frame");
                                    cspace_free_slot(&cspace, *frcap);
                                    // return frame back to frame table
                                    if(!(*fr & FR_FLAG_NOERASE))
                                        free_frame(*fr & FR_FLAG_REF_AREA);
                                    // zero out the PT
                                    *fr = *frcap = 0;
                                }
                                --numpages;
                                if(++indices[PT_PT] >= 512) {
                                    indices[PT_PT] = 0;
                                    break;
                                }
                            }
                        } else {
                            numpages = MAX(0, numpages - (512 - indices[PT_PT]));
                            indices[PT_PT] = 0;
                        }
                        if(++indices[PT_PD] >= 512) {
                            indices[PT_PD] = 0;
                            break;
                        }
                    }
                } else {
                    numpages = MAX(0, numpages - (512 - indices[PT_PT]));
                    numpages = MAX(0, numpages - (512 - (indices[PT_PD] + 1)) * 512);
                    indices[PT_PT] = indices[PT_PD] = 0;
                }
                if(++indices[PT_PUD] >= 512) {
                    indices[PT_PUD] = 0;
                    break;
                }
            }
        } else {
            numpages = MAX(0, numpages - (512 - indices[PT_PT]));
            numpages = MAX(0, numpages - (512 - (indices[PT_PD] + 1)) * 512);
            numpages = MAX(0, numpages - (512 - (indices[PT_PUD] + 1)) * 512*512);
            indices[PT_PT] = indices[PT_PD] = indices[PT_PUD] = 0;
        }
        ++indices[PT_PGD];
    }
    return seL4_NoError;
}

frame_ref_t grp01_get_frame(seL4_Word badge, seL4_CPtr vspace, seL4_Word vaddr)
{
    // the usual checking
    if(badge >= MAX_PID || !vspace)
        return 0;
    struct bookkeeping* lbk = bk + badge;
    if(lbk->vspace != vspace)
        return 0;

    struct pagedir* ppd = &lbk->sh_pgd;
    for(PDType pdtype=PT_PGD; pdtype>PT_PT; --pdtype) {
        if(!ppd->dir)
            return 0;
        ppd = ((struct pagedir*)frame_data(ppd->dir)) + PD_INDEX(vaddr, pdtype);
    }

    return ((frame_ref_t*)frame_data(ppd->dir))[PD_INDEX(vaddr, PT_PT)] & FR_FLAG_REF_AREA;
}

void* userptr_read(userptr_t src, size_t len, seL4_Word badge, seL4_CPtr vspace)
{
    // the usual checking
    if(badge >= MAX_PID || !vspace)
        return 0;
    struct bookkeeping* userbk = bk + badge;
    if(userbk->vspace != vspace)
        return 0;

    uintptr_t ret = 0;

    // net length!
    size_t lennet = len + (src % PAGE_SIZE_4K);
    size_t pagecount = ROUND_UP(lennet - 1, PAGE_SIZE_4K) / PAGE_SIZE_4K;
    
    // check if we have enough scratch vmem to handle this
    sync_mutex_lock(&scratch_lock);
    if(scratchas.used == 0) {
        // check if our entire addrspace can be used to fit this request!
        if(lennet < (VMEM_TOP - SOS_SCRATCH))
            ret = SOS_SCRATCH;
    } else {
        // find an empty region, starting from rearmost!
        for(int i = scratchas.used - 1; i >= 0; --i) {
            uintptr_t scregend = ((addrspace_t*)scratchas.data)[i].end;
            if(lennet < (VMEM_TOP - scregend)) {
                ret = scregend;
                break;
            }
        }
    }
    // our code is designed not to invoke malloc again on scratch space, so ...
    ZF_LOGF_IF(scratchas.used + 1 >= scratchas.capacity, 
        "Request is going to exceed scratch AS slot.");

    // create the AS
    addrspace_t curras;
    if(ret) {
        curras.attr.type = AS_NORMAL;
        // we set write to true, as sometimes we also need to ensure the NULL terminator.
        curras.perm = seL4_CapRights_new(false, false, true, true);
        curras.begin = ret;
        curras.end = ret + pagecount * PAGE_SIZE_4K;
        // this ensures that other thread can't touch our scratch region
        if(addrspace_add(&scratchas, curras, false, NULL) != AS_ADD_NOERR) {
            ZF_LOGE("Cannot map scratch address space.");
            ret = 0;
        }
    }
    sync_mutex_unlock(&scratch_lock);

    if(!ret)
        return NULL;

    // map all user pages to the scratch addr space
    uint16_t indices[4];
    for(int i = PT_PT; i <= PT_PGD; ++i)
        indices[i] = PD_INDEX(src, i);
    struct pagedir pud, pd, pt;
    frame_ref_t fr;
    uintptr_t scratchvaddr = ret;

    bool allpagesmapped = true;
    while(pagecount) { // PGD
        ZF_LOGF_IF(indices[PT_PGD] >= 512, "vaddr out of bound");
        pud = PD_ENTRY(userbk->sh_pgd, indices[PT_PGD]);
        if(pud.dir) {
            while(pagecount) { // PUD
                pd = PD_ENTRY(pud, indices[PT_PUD]);
                if(pd.dir) {
                    while(pagecount) { // PD
                        pt = PD_ENTRY(pd, indices[PT_PD]);
                        if(pt.dir) {
                            ZF_LOGF_IF(!pt.cap, "Page table has frame table but no capability table");
                            while(pagecount) { // PT
                                fr = ((frame_ref_t*)frame_data(pt.dir))[indices[PT_PT]] & FR_FLAG_REF_AREA;
                                if(!fr) {
                                    allpagesmapped = false;
                                    break;
                                }
                                if(grp01_map_frame(0, fr, false, bk->vspace, scratchvaddr, 
                                    curras.perm, seL4_ARM_Default_VMAttributes) != seL4_NoError)
                                        allpagesmapped = false;
                                scratchvaddr += PAGE_SIZE_4K;
                                // next
                                --pagecount;
                                if(++indices[PT_PT] >= 512) {
                                    indices[PT_PT] = 0;
                                    break;
                                }
                            }
                        } else
                            allpagesmapped = false;
                        if(!allpagesmapped)
                            break;
                        // next
                        if(++indices[PT_PD] >= 512) {
                            indices[PT_PD] = 0;
                            break;
                        }
                    }
                } else
                    allpagesmapped = false;
                if(!allpagesmapped)
                    break;
                // next
                if(++indices[PT_PUD] >= 512) {
                    indices[PT_PUD] = 0;
                    break;
                }
            }
        } else
            allpagesmapped = false;
        if(!allpagesmapped)
            break;
        ++indices[PT_PGD];
    }
    // there is no point in continuing the reading if not all pages are mapped.
    // we expect that pages are already mapped and init-ed when user wishes us to read it
    if(!allpagesmapped) {
        ZF_LOGI("User app requested read on unmapped frames.");
        // unmap from our AS
        ZF_LOGF_IF(grp01_unmap_frame(0, bk->vspace, curras.begin, curras.end) != seL4_NoError, 
            "Error unmapping scratch frame");
        // and remove the AS
        sync_mutex_lock(&scratch_lock);
        // find the index again, as our scratch AS might be moved around while we didn't lock the AS
        int currasidx = addrspace_find(&scratchas, src);
        ZF_LOGF_IF(currasidx < 0, "Got invalid scratch AS.");
        addrspace_remove(&scratchas, currasidx);
        sync_mutex_unlock(&scratch_lock);
        return 0;
    }

    // offset the ret
    ret += src % PAGE_SIZE_4K;
    return (void*)ret;
}

userptr_write_state_t userptr_write_start(userptr_t src, size_t len, dynarray_t* userasarr, seL4_Word badge, seL4_CPtr vspace)
{
    userptr_write_state_t ret = {0};
    addrspace_t scratch = {0};
    scratch.attr.type = AS_NORMAL;
    scratch.perm = seL4_CapRights_new(false, false, true, true);

    // the usual checking
    if(badge >= MAX_PID || !vspace)
        return ret;
    struct bookkeeping* userbk = bk + badge;
    if(userbk->vspace != vspace)
        return ret;

    // check if the given address range is valid in user's
    int asidx = addrspace_find(userasarr, src);
    if(asidx < 0)
        return ret;
    addrspace_t* useras = (addrspace_t*)userasarr->data + asidx;

    // out of bound of user's AS?
    // also take into account that a region can be adjacent to another
    while((src + len) >= useras->end) {
        if((uint32_t)asidx < userasarr->used) {
            if((useras+1)->begin == useras->end) {
                ++useras;
                ++asidx;
            } else
                return ret;
        } else
            return ret;
    }

    // at this point, the given address range should be valid.
    // now create a scratch mapping
    sync_mutex_lock(&scratch_lock);
    // check if we have enough scratch vmem to handle this
    if(scratchas.used == 0) {
        // check if our entire addrspace can be used to fit this request!
        if(PAGE_SIZE_4K < (VMEM_TOP - SOS_SCRATCH))
            ret.curr = scratch.begin = SOS_SCRATCH;
    } else {
        // find an empty region, starting from rearmost!
        for(int i = scratchas.used - 1; i >= 0; --i) {
            uintptr_t scregend = ((addrspace_t*)scratchas.data)[i].end;
            if(PAGE_SIZE_4K < (VMEM_TOP - scregend)) {
                ret.curr = scratch.begin = scregend;
                break;
            }
        }
    }
    // our code is designed not to invoke malloc again on scratch space, so ...
    ZF_LOGF_IF(scratchas.used + 1 >= scratchas.capacity, 
        "Request is going to exceed scratch AS slot.");
    
    // create the AS
    if(ret.curr) {
        scratch.end = scratch.begin + PAGE_SIZE_4K;
        if(addrspace_add(&scratchas, scratch, false, NULL) != AS_ADD_NOERR) {
            ZF_LOGE("Cannot map scratch address space.");
            ret.curr = 0;
        }
    }
    sync_mutex_unlock(&scratch_lock);

    // setup offset and remaining bytes
    ret.curr += src % PAGE_SIZE_4K;
    ret.remcurr = MIN(PAGE_SIZE_4K - (src % PAGE_SIZE_4K), len);
    ret.remall = len;
    ret.pid = badge;
    ret.userasperm = useras->perm;

    // setup indices for mapping user's vspace
    for(PDType pdtype=PT_PGD; pdtype >= PT_PT; --pdtype)
        ret.useridx.arr[pdtype] = PD_INDEX(src, pdtype);

    if(!userptr_single_map(scratch.begin, ret.useridx, useras->perm, badge)) {
        // failed. remove the AS.
        // we assume that the frame is not mapped to SOS at it returns an error!
        // however, it might be mapped to user's tho
        sync_mutex_lock(&scratch_lock);
        int asidx = addrspace_find(&scratchas, scratch.begin);
        ZF_LOGF_IF(asidx < 0, "Scratch map not found.");
        addrspace_remove(&scratchas, asidx);
        sync_mutex_unlock(&scratch_lock);

        ret.curr = 0;
    }

    return ret;
}

bool userptr_write_next(userptr_write_state_t* it)
{
    if(it->curr) {
        // unmap SOS scratch frame
        it->curr = ROUND_DOWN(it->curr, PAGE_SIZE_4K);
        if(grp01_unmap_frame(0, bk->vspace, it->curr, it->curr + PAGE_SIZE_4K) != seL4_NoError) {
            ZF_LOGE("Error unmapping scratch frame.");
            return false;
        }

        it->remall -= it->remcurr;
        it->remcurr = MIN(it->remall, PAGE_SIZE_4K);

        if(it->remall) {
            // increment user page index
            for(PDType i = PT_PT; i <= PT_PGD; ++i) {
                if(++it->useridx.arr[i] >= 512)
                    it->useridx.arr[i] = 0;
                else
                    break;
            }

            // remap the SOS scratch with the new user address
            if(!userptr_single_map(it->curr, it->useridx, it->userasperm, it->pid)) {
                // we expect caller to call the userptr_unmap
                it->curr = 0;
                return false;
            }
        } else 
            it->curr = 0;
    } 
    return true;
}

void userptr_unmap(void* sosaddr)
{
    sync_mutex_lock(&scratch_lock);
    int idx = addrspace_find(&scratchas, (uintptr_t)sosaddr);
    if(idx >= 0) {
        addrspace_t* as = (addrspace_t*)scratchas.data + idx;
        ZF_LOGF_IF(grp01_unmap_frame(0, bk->vspace, as->begin, as->end),
            "Error unmapping scratch frame");
        addrspace_remove(&scratchas, idx);
    }
    sync_mutex_unlock(&scratch_lock);
}

bool userptr_single_map(uintptr_t local, pd_indices_t useridx, 
    seL4_CapRights_t userright, seL4_Word pid)
{
    // check if we have a frame already on user's
    struct pagedir pd = bk[pid].sh_pgd;
    frame_ref_t fr = 0;
    for(PDType pdtype=PT_PGD; pdtype > PT_PT; --pdtype) {
        pd = PD_ENTRY(pd, useridx.arr[pdtype]);
        if(!pd.dir) 
            break;
    }
    
    // if pddir == 0, then one or more of intermediary PD doesn't have a directory mapped
    if(pd.dir) 
        // check if PT has entry
        fr = ((frame_ref_t*)frame_data(pd.dir))[useridx.str.pt] & FR_FLAG_REF_AREA;

    if(!fr) {
        // have to map frame
        fr = alloc_frame();
        if(!fr) {
            ZF_LOGE("Cannot allocate frame for user.");
            return false;
        }
        if(grp01_map_frame(pid, fr, true, bk[pid].vspace, PD_INDEX_VADDR(useridx), 
            userright, seL4_ARM_Default_VMAttributes) != seL4_NoError)
        {
            ZF_LOGE("Cannot map user's frame.");
            return false;
        }
    } 
    
    // map the frame to the designated scratch address
    if(grp01_map_frame(0, fr, false, bk->vspace, local, seL4_AllRights, 
        seL4_ARM_Default_VMAttributes) != seL4_NoError)
    {
        ZF_LOGE("Cannot map frame to SOS scratch");
        return false;
    }

    // OK!
    return true;
}