// This mapping keeps the bookkeeping of page directories and page tables
// for each vspaces. Need initialisation for every vspaces to be managed.
// Can be used safely with the original SOS mapping.
// however, PDs and PTs allocated by SOS mapping won't be tracked.

// these code will only work on AArch64 and nothing else!

#include "mapping2.h"
#include "../frame_table.h"
#include "../utils.h"
#include "../vmem_layout.h"
#include "../proctable.h"
#include "../threadassert.h"
#include <sos/gen_config.h>
#include <sync/mutex.h>
#include <sys/types.h>
#include <utils/zf_log_if.h>
#include <sel4/sel4_arch/mapping.h>

#define BK_BUCKETS 4
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
    FR_FLAG_NOERASE = 0x100000000000000ULL,
    FR_FLAG_UNPIN_UNMAP = 0x200000000000000ULL
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
struct bookkeeping bk[CONFIG_SOS_MAX_PID];

extern dynarray_t scratchas;

void grp01_map_bookkeep_init()
{
    memset(bk, 0, sizeof(bk));
}

void grp01_map_init(seL4_Word badge, seL4_CPtr vspace)
{
    // check if badge is valid :)
    // badge == 0 means we're managing SOS' (not used for now)
    assert(badge < CONFIG_SOS_MAX_PID);
    
    // check if this vspace is not managed by us yet. also find the slot.
    struct bookkeeping* lbk = bk + badge;
    ZF_LOGF_IF(lbk->vspace, "Attempt to manage page directory for process %ld twice!", badge);

    // we expect that this structure is pristine and empty when vspace == 0!
    lbk->vspace = vspace;

    return true;
}

void grp01_map_destroy(seL4_Word badge)
{
    // never destroy SOS' structure
    assert(badge && (badge < CONFIG_SOS_MAX_PID));

    struct bookkeeping* lbk = bk + badge;
    assert(lbk->vspace);

    // unmap everything, including shadow tables
    grp01_unmap_frame(badge, 0, VMEM_TOP, true);

    // caller should destroy the vspace object
    lbk->vspace = 0;
}

seL4_Error grp01_map_frame(seL4_Word badge, frame_ref_t frameref, bool free_frame_on_delete, bool unpin_on_unmap, seL4_Word vaddr, seL4_CapRights_t rights,
                     seL4_ARM_VMAttributes attr)
{
    seL4_Error err;

    // used to convert and checkf frame_data, whether we get a frame or not.
    union {
        frame_ref_t* fr;
        ut_t** ut;
        seL4_CPtr* cap;
    } tmp;

    // we always assume that the badge passed here is valid!
    seL4_CPtr vspace = proctable[badge].vspace;

    // simply refuse to map NULL
    if(!vaddr)
        return seL4_IllegalOperation;

    if(badge >= CONFIG_SOS_MAX_PID || !vspace)
        return seL4_RangeError;

    // find the bucket
    struct bookkeeping* lbk = bk + badge;
    if(lbk->vspace != vspace)
        return seL4_InvalidArgument;

    // allocate shadow tables if not allocated yet for the given vaddr
    struct pagedir* ppd = &lbk->sh_pgd;
    frame_ref_t ppd_fr;
    for(PDType pdtype=PT_PGD; pdtype>PT_PT; --pdtype) {
        if(!ppd->dir) {
            if(!(ppd->dir = alloc_empty_frame())) {
                ZF_LOGE("Cannot allocate frame for shadow page directory");
                err = seL4_NotEnoughMemory;
                goto finish3;
            }
        }
        ppd_fr = ppd->dir;
        struct pagedir* ppd_fr_data = frame_data(ppd_fr);
        if(!ppd_fr_data)
            return seL4_NotEnoughMemory;
        ppd = ppd_fr_data + PD_INDEX(vaddr, pdtype);
    }
    // pin the ppd so that we don't get evicted.
    frame_set_pin(ppd_fr, true);

    // shadow PT
    // allocate frame for PT, for storing frame ref and cptr to mapped frame
    if(!ppd->dir) {
        ppd->dir = alloc_empty_frame();
        if(!ppd->dir) {
            ZF_LOGE("Cannot allocate frame for page table");
            err = seL4_NotEnoughMemory;
            goto finish2;
        }
    }
    if(!ppd->cap) {
        ppd->cap = alloc_empty_frame();
        if(!ppd->cap) {
            ZF_LOGE("Cannot allocate frame for page table");
            err = seL4_NotEnoughMemory;
            goto finish2;
        }
    }

    // check if frame is already mapped to our data structure
    tmp.fr = ((frame_ref_t*)frame_data(ppd->dir));
    if(!tmp.fr) {
        err = seL4_NotEnoughMemory;
        goto finish2;
    }
    frame_ref_t existing_frameref = tmp.fr[PD_INDEX(vaddr, PT_PT)];
    if(existing_frameref){
        if(frameref) {
            // means that caller tries to map a frame but there is another one already mapped
            // if frameref is 0, it means that caller wishes to remap
            err = seL4_DeleteFirst;
            goto finish2;
        } else {
            frameref = existing_frameref & FR_FLAG_REF_AREA;
            free_frame_on_delete = !(existing_frameref & FR_FLAG_NOERASE);
        }
    } else if(!frameref) {
        // we need a properly allocated frame in that case!
        err = seL4_FailedLookup;
        goto finish2;
    }

    seL4_CPtr mapped_frame;
    if(!existing_frameref) {
        // copy the frame cap so that we can map it to target vspace
        // because frame table is already mapping the frame
        mapped_frame = cspace_alloc_slot(&cspace);
        if(mapped_frame == NULL_FRAME) {
            ZF_LOGE("Cannot allocate cspace slot to map frame");
            err = seL4_NotEnoughMemory;
            goto finish2;
        }
    } else {
        // get the existing slot. this current slot must already have the cap invalidated
        tmp.cap = ((seL4_CPtr*)frame_data(ppd->cap));
        if(!tmp.cap) {
            err = seL4_NotEnoughMemory;
            goto finish2;
        }
        mapped_frame = tmp.cap[PD_INDEX(vaddr, PT_PT)];
    }

    // this pinning is to avoid the page that we're mapping to get evicted.
    // because if that happens, seL4 will obviously fail to map an empty capability
    // and we'll left puzzled otherwise!
    bool frameref_pin_status = frame_set_pin(frameref, true);

    seL4_CPtr orig_fr_cap = frame_page(frameref);
    if(!orig_fr_cap) {
        cspace_free_slot(&cspace, mapped_frame);
        ZF_LOGE("Not enough memory when allocating frame");
        err = seL4_NotEnoughMemory;
        goto finish4;
    }
    err = cspace_copy(&cspace, mapped_frame, &cspace, orig_fr_cap, seL4_AllRights);
    if(err != seL4_NoError) {
        cspace_free_slot(&cspace, mapped_frame);
        ZF_LOGE("Cannot copy frame capability for mapping: %d\n", err);
        goto finish4;
    }

    // try allocating for PUD/PD/PT
    err = seL4_ARM_Page_Map(mapped_frame, vspace, vaddr, rights, attr);
    
    for (size_t i = 0; i < MAPPING_SLOTS && err == seL4_FailedLookup; i++) {
        seL4_Error sperr = seL4_NoError;

        /* save this so nothing else trashes the message register value */
        seL4_Word failed = seL4_MappingFailedLookupLevel();

        // select the container (directory) of the requested object
        // reference to frame used by contpd. used for pinning/unpinning.
        frame_ref_t contpd_frame;
        struct pagedir * contpd;
        PDType conttype;
        seL4_Word targetpdtype;
        switch (failed) {
        case SEL4_MAPPING_LOOKUP_NO_PT:
            contpd = frame_data(lbk->sh_pgd.dir);
            if(!contpd) {
                sperr = seL4_NotEnoughMemory;
                goto maploopfinish;
            }
            contpd = frame_data(contpd[PD_INDEX(vaddr, PT_PGD)].dir);
            if(!contpd) {
                sperr = seL4_NotEnoughMemory;
                goto maploopfinish;
            }
            contpd_frame = contpd[PD_INDEX(vaddr, PT_PUD)].dir;
            conttype = PT_PD;
            targetpdtype = seL4_ARM_PageTableObject;
            break;

        case SEL4_MAPPING_LOOKUP_NO_PD:
            contpd = frame_data(lbk->sh_pgd.dir);
            if(!contpd) {
                sperr = seL4_NotEnoughMemory;
                goto maploopfinish;
            }
            contpd_frame = contpd[PD_INDEX(vaddr, PT_PGD)].dir;
            conttype = PT_PUD;
            targetpdtype = seL4_ARM_PageDirectoryObject;
            break;

        case SEL4_MAPPING_LOOKUP_NO_PUD:
            contpd_frame = lbk->sh_pgd.dir;
            conttype = PT_PGD;
            targetpdtype = seL4_ARM_PageUpperDirectoryObject;
            break;

        default:
            // either we forgot to map the vspace, or something really bad happened.
            ZF_LOGE("seL4 give unknown mapping error: %ld", failed);
            sperr = seL4_FailedLookup;
            goto maploopfinish;
        }

        bool contpd_frame_pin_status = frame_set_pin(contpd_frame, true);
        contpd = frame_data(contpd_frame);
        if(!contpd) {
            sperr = seL4_NotEnoughMemory;
            goto maploopfinish;
        }
        contpd = contpd + PD_INDEX(vaddr, conttype);

        // allocate a new page directory frame
        if(!contpd->ut) {
            // we don't check UT directly when unmapping, as it is always created together with the cap.
            // Therefore, we can let this data unitialized.
            contpd->ut = alloc_frame();
            if(!contpd->ut) {
                ZF_LOGE("Cannot allocate frame for untyped table.");
                sperr = seL4_NotEnoughMemory;
                goto maploopfinish;
            }
        }

        ut_t** ut_pd_ptr = ((ut_t**)frame_data(contpd->ut));
        if(!ut_pd_ptr) {
            sperr = seL4_NotEnoughMemory;
            goto maploopfinish;
        }
        ut_t* ut_pd = ut_pd_ptr[PD_INDEX(vaddr, conttype)] = ut_alloc_4k_untyped(NULL);
        if(!ut_pd) {
            ZF_LOGE("Failed to allocate frame for hardware page directory");
            sperr = seL4_NotEnoughMemory;
            goto maploopfinish;
        }

        // create cspace slot for this new page table
        if(!contpd->cap) {
            contpd->cap = alloc_empty_frame();
            if(!contpd->ut) {
                ZF_LOGE("Cannot allocate frame for capabilities table.");
                sperr = seL4_NotEnoughMemory;
                goto maploopfinish;
            }
        }
        
        seL4_CPtr* pd_cap_ptr = ((seL4_CPtr*)frame_data(contpd->cap));
        if(!pd_cap_ptr) {
            sperr = seL4_NotEnoughMemory;
            goto maploopfinish;
        }
        seL4_CPtr pd_cap = pd_cap_ptr[PD_INDEX(vaddr, conttype)] = cspace_alloc_slot(&cspace);
        if(pd_cap == seL4_CapNull) {
            ZF_LOGE("Failed to allocate cspace slot for page directory");
            ut_free(ut_pd);
            sperr = seL4_NotEnoughMemory;
            goto maploopfinish;
        }

        // retype UT to the appropriate PD type
        err = cspace_untyped_retype(&cspace, ut_pd->cap, pd_cap, targetpdtype, seL4_PageBits);
        if(err) {
            ZF_LOGE("Failed to retype page directory: %d", err);
            cspace_free_slot(&cspace, pd_cap);
            ut_free(ut_pd);
            sperr = err;
            goto maploopfinish;
        }

        // map the PD to seL4
        switch(targetpdtype) {
            case seL4_ARM_PageUpperDirectoryObject:
                err = seL4_ARM_PageUpperDirectory_Map(pd_cap, vspace, vaddr, seL4_ARM_Default_VMAttributes);
                break;
            case seL4_ARM_PageDirectoryObject:
                err = seL4_ARM_PageDirectory_Map(pd_cap, vspace, vaddr, seL4_ARM_Default_VMAttributes);
                break;
            case seL4_ARM_PageTableObject:
                err = seL4_ARM_PageTable_Map(pd_cap, vspace, vaddr, seL4_ARM_Default_VMAttributes);
                break;
            default:
                ZF_LOGF("Got unforeseen type.");
        }

        if(err) {
            ZF_LOGE("Cannot map page directory.");
            sperr = err;
            goto maploopfinish;
        }

        // try mapping again
        err = seL4_ARM_Page_Map(mapped_frame, vspace, vaddr, rights, attr);

    maploopfinish:
        frame_set_pin(contpd_frame, contpd_frame_pin_status);
        if(sperr) {
            err = sperr;
            goto finish;
        }
    }

    // if err here is noerr, it means that we've mapped the frame successfully
    if(err == seL4_NoError) {
        // take note the frame to PT
        tmp.fr = ((frame_ref_t*)frame_data(ppd->dir));
        if(!tmp.fr) {
            err = seL4_NotEnoughMemory;
            goto finish;
        }
        tmp.fr[PD_INDEX(vaddr, PT_PT)] = frameref 
            | (free_frame_on_delete ? 0 : FR_FLAG_NOERASE)
            | (unpin_on_unmap ? FR_FLAG_UNPIN_UNMAP : 0);
        tmp.cap = ((seL4_CPtr*)frame_data(ppd->cap));
        if(!tmp.cap) {
            err = seL4_NotEnoughMemory;
            goto finish;
        }
        tmp.cap[PD_INDEX(vaddr, PT_PT)] = mapped_frame;
    }

finish:
    if(err != seL4_NoError) {
        // free up the frames that we've allocated
        cspace_delete(&cspace, mapped_frame);
        cspace_free_slot(&cspace, mapped_frame);
        if(free_frame_on_delete)
            free_frame(frameref);
    }
finish4:
    frame_set_pin(frameref, frameref_pin_status);
finish2:
    frame_set_pin(ppd_fr, false);
finish3:
    if(unpin_on_unmap && err)
        frame_set_pin(frameref, false);
    return err;
}

seL4_Error grp01_unmap_frame(seL4_Word badge, seL4_Word vaddrbegin, seL4_Word vaddrend, bool full)
{
    // we always assume that the badge passed here is valid!
    seL4_CPtr vspace = proctable[badge].vspace;    

    // if full is turned on, we will completely obliviate all the intermediary pages from bottom to top!
    if(full) {
        vaddrbegin = 0;
        vaddrend = VMEM_TOP;
    }

    // must pass a page aligned address here!
    ZF_LOGF_IF((vaddrbegin % PAGE_SIZE_4K) || (vaddrend % PAGE_SIZE_4K), "vaddr not page aligned");
    if(vaddrend < vaddrbegin)
        return seL4_RangeError;

    if(badge >= CONFIG_SOS_MAX_PID || !vspace)
        return seL4_RangeError;

    // find the bucket
    struct bookkeeping* lbk = bk + badge;
    if(lbk->vspace != vspace)
        return seL4_InvalidArgument;

    ssize_t numpages = (vaddrend - vaddrbegin) >> seL4_PageBits;

    pd_indices_t indices;
    for(int i = PT_PT; i <= PT_PGD; ++i)
        indices.arr[i] = PD_INDEX(vaddrbegin, i);
    
    frame_ref_t pud_fr, pd_fr, pt_fr;
    struct pagedir pud, pd, pt;
    frame_ref_t* fr;
    seL4_CPtr* frcap;
    
    // to check that frame_data successfully get a frame
    struct pagedir * tmp;
    seL4_Error err = seL4_NoError;

    frame_set_pin(lbk->sh_pgd.dir, true);
    while(numpages) { // PGD
        ZF_LOGF_IF(indices.str.pgd >= 512, "vaddr out of bound");
        tmp = frame_data(lbk->sh_pgd.dir);
        if(!tmp) {
            err = seL4_NotEnoughMemory;
            break;
        }
        pud = tmp[indices.str.pgd];
        if(pud.dir) {
            frame_set_pin(pud.dir, true);
            while(numpages) { // PUD
                tmp = frame_data(pud.dir);
                if(!tmp) {
                    err = seL4_NotEnoughMemory;
                    break;
                }
                pd = tmp[indices.str.pud];
                if(pd.dir) {
                    frame_set_pin(pd.dir, true);
                    while(numpages) { // PD
                        tmp = frame_data(pd.dir);
                        if(!tmp) {
                            err = seL4_NotEnoughMemory;
                            break;
                        }
                        pt = tmp[indices.str.pd];
                        if(pt.dir) {
                            ZF_LOGF_IF(!pt.cap, "Page table has frame table but no capability table");
                            frame_set_pin(pt.dir, true);
                            frame_set_pin(pt.cap, true);
                            while(numpages) { // PT
                                fr = ((frame_ref_t*)frame_data(pt.dir));
                                if(!fr) {
                                    err = seL4_NotEnoughMemory;
                                    break;
                                }
                                fr += indices.str.pt;
                                if(*fr) {
                                    // the actual unmapping
                                    frcap = ((seL4_CPtr*)frame_data(pt.cap));
                                    if(frcap) {
                                        frcap += indices.str.pt;
                                        // any errors would be caused by parent page revoking this
                                        // capability (e.g. due to page out)
                                        seL4_ARM_Page_Unmap(*frcap);
                                        // free the duplicated capability
                                        ZF_LOGE_IF(cspace_delete(&cspace, *frcap) != seL4_NoError,
                                            "Error deleting capability for frame");
                                        cspace_free_slot(&cspace, *frcap);
                                        // unpin if required
                                        if(*fr & FR_FLAG_UNPIN_UNMAP)
                                            frame_set_pin(*fr & FR_FLAG_REF_AREA, false);
                                        // return frame back to frame table if required
                                        if(!(*fr & FR_FLAG_NOERASE))
                                            free_frame(*fr & FR_FLAG_REF_AREA);
                                        // zero out the PT
                                        *fr = *frcap = 0;
                                    } else {
                                        err = seL4_NotEnoughMemory;
                                        break;
                                    }
                                }
                                --numpages;
                                if(++indices.str.pt >= 512) {
                                    indices.str.pt = 0;
                                    break;
                                }
                            }
                            frame_set_pin(pt.dir, false);
                            frame_set_pin(pt.cap, false);
                            if(err)
                                break;
                            if(full) {
                                // free this PT's frame data
                                free_frame(pt.dir);
                                pt.dir = 0;
                                free_frame(pt.cap);
                                pt.cap = 0;
                                // unmap this PT and free the UT
                                if(pd.cap) {
                                    ZF_LOGF_IF(!pd.ut, "shadow PD has cap frame but no ut frame.");
                                    seL4_CPtr* ptcap = &((seL4_CPtr*)frame_data(pd.cap))[indices.str.pd];
                                    if(*ptcap) {
                                        seL4_Error unmap_error = seL4_ARM_PageTable_Unmap(*ptcap);
                                        cspace_delete(&cspace, *ptcap);
                                        cspace_free_slot(&cspace, *ptcap);
                                        *ptcap = 0;
                                        ut_free(((ut_t**)frame_data(pd.ut))[indices.str.pd]);
                                    }
                                }
                            }
                        } else {
                            numpages = MAX(0, numpages - (512 - indices.str.pt));
                            indices.str.pt = 0;
                        }
                        if(++indices.str.pd >= 512) {
                            indices.str.pd = 0;
                            break;
                        }
                    }
                    frame_set_pin(pd.dir, false);
                    if(err)
                        break;
                    if(full) {
                        // free this PD's frame data
                        free_frame(pd.dir);
                        pd.dir = 0;
                        if(pd.cap) {
                            free_frame(pd.cap);
                            pd.cap = 0;
                        }
                        if(pd.ut) {
                            free_frame(pd.ut);
                            pd.ut = 0;
                        }
                        // unmap this PD and free the UT
                        if(pud.cap) {
                            ZF_LOGF_IF(!pud.ut, "shadow PUD has cap frame but no ut frame.");
                            seL4_CPtr* pdcap = &((seL4_CPtr*)frame_data(pud.cap))[indices.str.pud];
                            if(*pdcap) {
                                seL4_Error unmap_error = seL4_ARM_PageDirectory_Unmap(*pdcap);
                                cspace_delete(&cspace, *pdcap);
                                cspace_free_slot(&cspace, *pdcap);
                                *pdcap = 0;
                                ut_free(((ut_t**)frame_data(pud.ut))[indices.str.pud]);
                            }
                        }
                    }
                } else {
                    numpages = MAX(0, numpages - (512 - indices.str.pt));
                    numpages = MAX(0, numpages - (512 - (indices.str.pd + 1)) * 512);
                    indices.str.pt = indices.str.pd = 0;
                }
                if(++indices.str.pud >= 512) {
                    indices.str.pud = 0;
                    break;
                }
            }
            frame_set_pin(pud.dir, false);
            if(err)
                break;
            if(full) {
                // free this PUD's frame data
                free_frame(pud.dir);
                pud.dir = 0;
                if(pud.cap) {
                    free_frame(pud.cap);
                    pud.cap = 0;
                }
                if(pud.ut) {
                    free_frame(pud.ut);
                    pud.ut = 0;
                }
                // unmap this PD and free the UT
                if(lbk->sh_pgd.cap) {
                    ZF_LOGF_IF(!lbk->sh_pgd.ut, "shadow PGD has cap frame but no ut frame.");
                    seL4_CPtr* pudcap = ((seL4_CPtr*)frame_data(lbk->sh_pgd.cap))[indices.str.pgd];
                    if(*pudcap) {
                        ZF_LOGF_IF(seL4_ARM_PageUpperDirectory_Unmap(*pudcap) != seL4_NoError, 
                            "Error unmapping PUD");
                        cspace_delete(&cspace, *pudcap);
                        cspace_free_slot(&cspace, *pudcap);
                        *pudcap = 0;
                        ut_free(((ut_t**)frame_data(lbk->sh_pgd.ut))[indices.str.pgd]);
                    }
                }
            }
        } else {
            numpages = MAX(0, numpages - (512 - indices.str.pt));
            numpages = MAX(0, numpages - (512 - (indices.str.pd + 1)) * 512);
            numpages = MAX(0, numpages - (512 - (indices.str.pud + 1)) * 512*512);
            indices.str.pt = indices.str.pd = indices.str.pud = 0;
        }
        ++indices.str.pgd;
    }
    frame_set_pin(lbk->sh_pgd.dir, false);

    // free the PGD and unmap it
    // (however, let the caller unmap the PGD and free its cspace instead)
    if(full) {
        if(lbk->sh_pgd.dir) {
            free_frame(lbk->sh_pgd.dir);
            lbk->sh_pgd.dir = 0;
        }
        if(lbk->sh_pgd.cap) {
            free_frame(lbk->sh_pgd.cap);
            lbk->sh_pgd.cap = 0;
        }
        if(lbk->sh_pgd.ut) {
            free_frame(lbk->sh_pgd.ut);
            lbk->sh_pgd.ut = 0;
        }
    }

    // at the moment we have nowhere to go but panic if unmap failed
    ZF_LOGF_IF(err != seL4_NoError, "Unmap error: %d", err);
    return err;
}

frame_ref_t grp01_get_frame(seL4_Word badge, seL4_Word vaddr)
{
    // we always assume that the badge passed here is valid!
    seL4_CPtr vspace = proctable[badge].vspace;
    
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

void* userptr_read(userptr_t src, size_t len, seL4_Word badge)
{
    assert_main_thread();

    // we always assume that the badge passed here is valid!
    seL4_CPtr vspace = proctable[badge].vspace;

    // the usual checking
    if(!len)
        return 0;
    struct bookkeeping* userbk = bk + badge;
    if(userbk->vspace != vspace)
        return 0;

    uintptr_t ret = 0;

    // net length!
    size_t lennet = len + (src % PAGE_SIZE_4K);
    size_t pagecount = ROUND_UP(lennet - 1, PAGE_SIZE_4K) / PAGE_SIZE_4K;
    
    // check if we have enough scratch vmem to handle this
    ret = addrspace_find_free_reg(&scratchas, lennet, SOS_SCRATCH, VMEM_TOP);

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
    } else
        return NULL;

    // map all user pages to the scratch addr space
    uint16_t indices[4];
    for(int i = PT_PT; i <= PT_PGD; ++i)
        indices[i] = PD_INDEX(src, i);
    struct pagedir pud, pd, pt;
    frame_ref_t fr;
    uintptr_t scratchvaddr = ret;

    // get the reference. check if we can map the pages.
    struct pagedir* tmp;

    bool allpagesmapped = true;
    frame_set_pin(userbk->sh_pgd.dir, true);
    while(pagecount) { // PGD
        ZF_LOGF_IF(indices[PT_PGD] >= 512, "vaddr out of bound");
        tmp = frame_data(userbk->sh_pgd.dir);
        if(!tmp) {
            allpagesmapped = false;
            break;
        }
        pud = tmp[indices[PT_PGD]];
        if(pud.dir) {
            frame_set_pin(pud.dir, true);
            while(pagecount) { // PUD
                tmp = frame_data(pud.dir);
                if(!tmp) {
                    allpagesmapped = false;
                    break;
                }
                pd = tmp[indices[PT_PUD]];
                if(pd.dir) {
                    frame_set_pin(pd.dir, true);
                    while(pagecount) { // PD
                        tmp = frame_data(pd.dir);
                        if(!tmp) {
                            allpagesmapped = false;
                            break;
                        }
                        pt = tmp[indices[PT_PD]];
                        if(pt.dir) {
                            ZF_LOGF_IF(!pt.cap, "Page table has frame table but no capability table");
                            frame_set_pin(pt.dir, true);
                            while(pagecount) { // PT
                                frame_ref_t* pt_ptr = frame_data(pt.dir);
                                if(!pt_ptr) {
                                    allpagesmapped = false;
                                    break;
                                }
                                fr = pt_ptr[indices[PT_PT]] & FR_FLAG_REF_AREA;
                                if(!fr) {
                                    allpagesmapped = false;
                                    break;
                                }
                                // pin the frame. if it was previously unpinned, indicate so to mapper.
                                bool fr_pinned = frame_set_pin(fr, true);
                                if(grp01_map_frame(0, fr, false, !fr_pinned, scratchvaddr, 
                                    curras.perm, seL4_ARM_Default_VMAttributes) != seL4_NoError) {
                                        allpagesmapped = false;
                                        break;
                                }
                                scratchvaddr += PAGE_SIZE_4K;
                                // next
                                --pagecount;
                                if(++indices[PT_PT] >= 512) {
                                    indices[PT_PT] = 0;
                                    break;
                                }
                            }
                            frame_set_pin(pt.dir, false);
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
                    frame_set_pin(pd.dir, false);
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
            frame_set_pin(pud.dir, false);
        } else
            allpagesmapped = false;
        if(!allpagesmapped)
            break;
        ++indices[PT_PGD];
    }
    frame_set_pin(userbk->sh_pgd.dir, false);
    // there is no point in continuing the reading if not all pages are mapped.
    // we expect that pages are already mapped and init-ed when user wishes us to read it
    if(!allpagesmapped) {
        ZF_LOGI("User app requested read on unmapped frames.");
        // unmap from our AS
        ZF_LOGF_IF(grp01_unmap_frame(0, curras.begin, curras.end, false) != seL4_NoError, 
            "Error unmapping scratch frame");
        // and remove the AS
        // find the index again, as our scratch AS might be moved around while we didn't lock the AS
        int currasidx = addrspace_find(&scratchas, curras.begin);
        ZF_LOGF_IF(currasidx < 0, "Got invalid scratch AS.");
        addrspace_remove(&scratchas, currasidx);
        return 0;
    }

    // offset the ret
    ret += src % PAGE_SIZE_4K;
    return (void*)ret;
}

userptr_write_state_t userptr_write_start(userptr_t src, size_t len, seL4_Word badge)
{
    assert_main_thread();

    userptr_write_state_t ret = {0};
    addrspace_t scratch = {0};
    scratch.attr.type = AS_NORMAL;
    scratch.perm = seL4_CapRights_new(false, false, true, true);

    if(!len)
        return ret;

    // we always assume that the badge passed here is valid!
    seL4_CPtr vspace = proctable[badge].vspace;
    dynarray_t* userasarr = &proctable[badge].as;

    // the usual checking
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
    // check if we have enough scratch vmem to handle this
    ret.curr = scratch.begin = addrspace_find_free_reg(&scratchas, PAGE_SIZE_4K, SOS_SCRATCH, VMEM_TOP);
    
    // create the AS
    if(ret.curr) {
        scratch.end = scratch.begin + PAGE_SIZE_4K;
        if(addrspace_add(&scratchas, scratch, false, NULL) != AS_ADD_NOERR) {
            ZF_LOGE("Cannot map scratch address space.");
            ret.curr = 0;
        }
    } else 
        // no space
        return ret;

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
        int asidx = addrspace_find(&scratchas, scratch.begin);
        ZF_LOGF_IF(asidx < 0, "Scratch map not found.");
        addrspace_remove(&scratchas, asidx);

        ret.curr = 0;
    }

    return ret;
}

bool userptr_write_next(userptr_write_state_t* it)
{
    assert_main_thread();

    if(it->curr) {
        // unmap SOS scratch frame
        it->curr = ROUND_DOWN(it->curr, PAGE_SIZE_4K);
        if(grp01_unmap_frame(0, it->curr, it->curr + PAGE_SIZE_4K, false) != seL4_NoError) {
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

char* map_user_string(userptr_t ptr, size_t len, seL4_Word badge, char* originalchar)
{
    if(len >= CONFIG_SOS_MAX_FILENAME) {
        // flat out refuse if filename is too long!
        ZF_LOGI("Refused to service very long file name.");
        return NULL;
    }
    // WARNING! this function is meant to be called from main thread
    char* ret = userptr_read(ptr, len + 1, badge);
    if(!ret)
        return ret;
    // set last char to NULL to ensure safety
    *originalchar = ret[len];
    ret[len] = 0;
    return ret;
}

void userptr_unmap(void* sosaddr)
{
    assert_main_thread();

    int idx = addrspace_find(&scratchas, (uintptr_t)sosaddr);
    if(idx >= 0) {
        addrspace_t* as = (addrspace_t*)scratchas.data + idx;
        ZF_LOGF_IF(grp01_unmap_frame(0, as->begin, as->end, false),
            "Error unmapping scratch frame");
        addrspace_remove(&scratchas, idx);
    }
}

bool userptr_single_map(uintptr_t local, pd_indices_t useridx, 
    seL4_CapRights_t userright, seL4_Word pid)
{
    // check if we have a frame already on user's
    struct pagedir pd = bk[pid].sh_pgd;
    frame_ref_t fr = 0;
    for(PDType pdtype=PT_PGD; pdtype > PT_PT; --pdtype) {
        struct pagedir* tmp = frame_data(pd.dir);
        if(!tmp) {
            ZF_LOGE("Not enough memory when mapping page directory.");
            return 0;
        }
        pd = tmp[useridx.arr[pdtype]];
        if(!pd.dir) 
            break;
    }
    
    // if pddir == 0, then one or more of intermediary PD doesn't have a directory mapped
    if(pd.dir) {
        // check if PT has entry
        frame_ref_t* tmp = frame_data(pd.dir);
        if(!tmp) {
            ZF_LOGE("Not enough memory when mapping page table.");
            return 0;
        }
        fr = tmp[useridx.str.pt] & FR_FLAG_REF_AREA;
    }

    if(!fr) {
        // have to map frame
        fr = alloc_frame();
        if(!fr) {
            ZF_LOGE("Cannot allocate frame for user.");
            return false;
        }
        // map to user's address space so that they can read the data!
        if(grp01_map_frame(pid, fr, true, false, PD_INDEX_VADDR(useridx), 
            userright, seL4_ARM_Default_VMAttributes) != seL4_NoError)
        {
            ZF_LOGE("Cannot map user's frame.");
            return false;
        }
    } 
    
    // map the frame to the designated scratch address
    bool fr_pinned = frame_set_pin(fr, true);
    if(grp01_map_frame(0, fr, false, !fr_pinned, local, seL4_AllRights, 
        seL4_ARM_Default_VMAttributes) != seL4_NoError)
    {
        ZF_LOGE("Cannot map frame to SOS scratch");
        return false;
    }

    // OK!
    return true;
}