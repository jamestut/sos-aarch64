// This mapping keeps the bookkeeping of page directories and page tables
// for each vspaces. Need initialisation for every vspaces to be managed.
// Can be used safely with the original SOS mapping.
// however, PDs and PTs allocated by SOS mapping won't be tracked.

// these code will only work on AArch64 and nothing else!

#include "mapping2.h"
#include "../frame_table.h"
#include "../utils.h"
#include <grp01/hash.h>
#include <sync/mutex.h>
#include <utils/zf_log_if.h>
#include <sel4/sel4_arch/mapping.h>

#define BK_BUCKETS 4
#define FRAME_TABLE_BITS 19

typedef enum {
    PT_PGD = 3,
    PT_PUD = 2,
    PT_PD  = 1,
    PT_PT  = 0,
    PT_UNDEFINED = -1
} PDType;

// ---- macro section ----

// index to page table. use PDType above for type param.
// AArch64 has 48 bits of vaddr, not 64 bit
#define PD_INDEX_1(vaddr, type) \
    ({ uintptr_t _vaddr = (vaddr); \
       size_t _type = (type); \
       (_vaddr >> (12 + _type * 9)) & 0x1FF; })

// ---- local functions section ----
// DEBUG
size_t PD_INDEX(uintptr_t vaddr, size_t type) {return PD_INDEX_1(vaddr, type);}

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
    
    // linked list in case of hash collision.
    struct bookkeeping* next;
};

// buckets used to bookeep page table objects.
struct bookkeeping* bk[BK_BUCKETS] = {0};

// lock the bucket when init/destroy
struct {
    seL4_CPtr ntfn;
    sync_mutex_t lock;
} bksync;

void grp01_map_bookkeep_init()
{
    ut_t* ut = alloc_retype(&bksync.ntfn, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!ut, "Failed to allocate notification object.");
    // mutex creation is always successful if the above object is a valid notification cap
    sync_mutex_init(&bksync.lock, bksync.ntfn);
}

bool grp01_map_init(seL4_CPtr vspace)
{
    // select which bucket to fall into
    unsigned int bkidx = hash(&vspace, sizeof(vspace)) % BK_BUCKETS;

    bool ret = false;

    sync_mutex_lock(&bksync.lock);
    
    // check if this vspace is not managed by us yet. also find the slot.
    struct bookkeeping** lbkslot = bk + bkidx;
    while(*lbkslot) {
        if((*lbkslot)->vspace == vspace) {
            // we're already managing this vspace
            ZF_LOGI("Attempt to create a new mapping bookkeeping on an already managed cspace.");
            ret = true;
            goto finish;
        }
        lbkslot = &(*lbkslot)->next;
    }

    // time to create a new bookkeeping object!
    *lbkslot = calloc(1, sizeof(struct bookkeeping));
    if(!*lbkslot) {
        ZF_LOGE("Error allocating bookkeeping object");
        goto finish;
    }
    (*lbkslot)->vspace = vspace;
    ret = true;
finish:
    sync_mutex_unlock(&bksync.lock);
    return ret;
}

seL4_Error grp01_map_frame(seL4_CPtr frame_cap, seL4_CPtr vspace, seL4_Word vaddr, seL4_CapRights_t rights,
                     seL4_ARM_VMAttributes attr)
{
    // find the bucket
    unsigned int bkidx = hash(&vspace, sizeof(vspace)) % BK_BUCKETS;
    struct bookkeeping* lbk;
    sync_mutex_lock(&bksync.lock);
    lbk = bk[bkidx];
    while(lbk && (lbk->vspace != vspace))
        lbk = lbk->next;
    sync_mutex_unlock(&bksync.lock);
    ZF_LOGF_IF(!lbk, "Bookkeeping object was not allocated for this vspace.");

    // allocate shadow tables if not allocated yet for the given vaddr
    struct pagedir* ppd = &lbk->sh_pgd;
    for(PDType pdtype=PT_PGD; pdtype>=PT_PT; --pdtype) {
        if(!ppd->dir) {
            if(!(ppd->dir = alloc_empty_frame())) {
                ZF_LOGE("Cannot allocate frame for shadow page directory");
                return seL4_NotEnoughMemory;
            }
        }
        ppd = ((struct pagedir*)frame_data(ppd->dir)) + PD_INDEX(vaddr, pdtype);
    }

    // try allocating for PUD/PD/PT
    seL4_Error err = seL4_ARM_Page_Map(frame_cap, vspace, vaddr, rights, attr);
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
        err = seL4_ARM_Page_Map(frame_cap, vspace, vaddr, rights, attr);
    }

    return err;
}