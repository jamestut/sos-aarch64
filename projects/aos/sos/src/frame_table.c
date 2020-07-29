/*
 * Copyright 2019, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(DATA61_GPL)
 */
#include "frame_table.h"
#include "mapping.h"
#include "vmem_layout.h"
#include "fileman.h"
#include "threadassert.h"
#include "vm/addrspace.h"

#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <utils/util.h>
#include <sos/gen_config.h>
#include <grp01/bitfield.h>
#include <fcntl.h>

/* Debugging macro to get the human-readable name of a particular list. */
#define LIST_NAME(list) LIST_ID_NAME(list->list_id)

/* Names of each of the lists. */
#define LIST_NAME_ENTRY(list) [list] = #list
char *frame_table_list_names[] = {
    LIST_NAME_ENTRY(NO_LIST),
    LIST_NAME_ENTRY(FREE_LIST),
    LIST_NAME_ENTRY(ALLOCATED_LIST),
};

/*
 * An entire page of data.
 */
typedef unsigned char frame_data_t[BIT(seL4_PageBits)];
compile_time_assert("Frame data size correct", sizeof(frame_data_t) == BIT(seL4_PageBits));

/* Memory-efficient doubly linked list of frames
 *
 * As all frame objects will live in effectively an array, we only need
 * to be able to index into that array.
 */
typedef struct {
    list_id_t list_id;
    /* Index of first element in list */
    frame_ref_t first;
    /* Index in last element of list */
    frame_ref_t last;
    /* Size of list (useful for debugging) */
    size_t length;
} frame_list_t;

PACKED struct page_cap {
    // instead of going full on 64 bit, we know that the maximum
    // CPtr is of INITIAL_TASK_CSPACE_BITS!
    uint32_t cap : INITIAL_TASK_CSPACE_BITS;
};
typedef struct page_cap page_cap_t;
// just to be sure that the structure is 32 bit aligned
compile_time_assert(page_cap_t size, sizeof(page_cap_t) == sizeof(uint32_t));

// Used to store free frames information alongside with a bitmap for faster lookup
#define PAGE_CAP_CONT_CAPACITY 992
typedef struct {
    uint64_t bmpfree[16];
    page_cap_t data[PAGE_CAP_CONT_CAPACITY];
} page_cap_cont_t;
compile_time_assert(page_cap_cont_t size is one page, sizeof(page_cap_cont_t) == PAGE_SIZE_4K);

/* This global variable tracks the frame table */
static struct {
    /* The array of all frames in memory. */
    frame_t *frames;
    /* The data region of the frame table. */
    frame_data_t *frame_data;
    /* The current capacity of the frame table. */
    size_t capacity;
    /* The current number of frames resident in the table. */
    size_t used;
    /* The current size of the frame table in bytes. */
    size_t byte_length;
    /* The free frames. */
    frame_list_t free;
    /* The allocated frames. */
    frame_list_t allocated;
    /* cspace used to make allocations of capabilities. */
    cspace_t *cspace;
    /* vspace used to map pages into SOS. */
    seL4_ARM_PageGlobalDirectory vspace;
    // total page_cap_cont_t objects
    size_t cap_frame_count;
    // The array of all page capability containers.
    page_cap_cont_t* cap_frames;
    // bitmap of free spaces in page file
    uint64_t* pf_bmp;
    // number of words in page file bitmap
    size_t pf_bmp_count;
    // second chance clockhand
    frame_ref_t clockhand;
} frame_table = {
    .frames = (void *)SOS_FRAME_TABLE,
    .frame_data = (void *)SOS_FRAME_DATA,
    .free = { .list_id = FREE_LIST },
    .allocated = { .list_id = ALLOCATED_LIST },
    .cap_frames = (void *)SOS_FRAME_CAP_TABLE,
    .pf_bmp = (uint64_t*)SOS_FRAME_PF_BITMAP,
    .cap_frame_count = 0,
    .pf_bmp_count = 0,
    .clockhand = NULL_FRAME
};

sos_filehandle_t page_file = {0};

/* Convenience functions/macros to access data */
#define FRAME_PAGE_CAP(idx) (frame_table.cap_frames[(idx)/PAGE_CAP_CONT_CAPACITY].\
    data[(idx)%PAGE_CAP_CONT_CAPACITY])

#define GET_FRAME_CAP_STATUS(idx) (GET_BMP(frame_table.cap_frames[(idx)/PAGE_CAP_CONT_CAPACITY].\
    bmpfree, (idx)%PAGE_CAP_CONT_CAPACITY))
#define TOGGLE_FRAME_CAP_FREE(idx) (TOGGLE_BMP(frame_table.cap_frames[(idx)/PAGE_CAP_CONT_CAPACITY].\
    bmpfree, (idx)%PAGE_CAP_CONT_CAPACITY))

/* utility functions */
static size_t frame_mem_page_idx(frame_ref_t frame_ref);

// returns the index to frame cap if successful
static size_t evict_frame();

static size_t get_new_phy_frame(void);

/* Management of frame nodes */
static frame_ref_t ref_from_frame(frame_t *frame);

/* Management of frame list */
static void push_front(frame_list_t *list, frame_t *frame);
static void push_back(frame_list_t *list, frame_t *frame);
static frame_t *pop_front(frame_list_t *list);
static void remove_frame(frame_list_t *list, frame_t *frame);

/*
 * Allocate a frame at a particular address in SOS.
 *
 * @param(in)  vaddr  Address in SOS at which to map the frame.
 * @return            Page used to map frame into SOS.
 */
static seL4_ARM_Page alloc_frame_at(uintptr_t vaddr);

/* Allocate a new frame. */
static frame_t *alloc_fresh_frame(void);

/* Increase the capacity of the frame table.
 *
 * @return  0 on succuss, -ve on failure. */
static int bump_capacity(void);

void frame_table_init(cspace_t *cspace, seL4_CPtr vspace)
{
    frame_table.cspace = cspace;
    frame_table.vspace = vspace;

    #ifdef CONFIG_SOS_FRAME_LIMIT
    if(CONFIG_SOS_FRAME_LIMIT)
        printf("Configured frame limit: %llu frames\n", CONFIG_SOS_FRAME_LIMIT);
    #endif
}

void frame_table_init_page_file()
{
    #if CONFIG_SOS_FAKE_PF > 0ul
    page_file.fh = *find_handler("fake");
    page_file.id = page_file.fh->open(0, "fake", O_RDWR);
    #else
    page_file.fh = find_handler("pf");
    page_file.id = page_file.fh->open(0, "pf", O_RDWR);
    #endif
}

cspace_t *frame_table_cspace(void)
{
    return frame_table.cspace;
}

frame_ref_t alloc_frame(void)
{
    assert_main_thread();

    frame_t *frame = pop_front(&frame_table.free);

    if (frame == NULL) {
        frame = alloc_fresh_frame();
    }

    if (frame != NULL) {
        push_back(&frame_table.allocated, frame);
    }
    // the frame is not used until it faults!
    frame->usage = 0;

    return ref_from_frame(frame);
}

frame_ref_t alloc_empty_frame(void)
{
    frame_ref_t ret = alloc_frame();
    frame_from_ref(ret)->reqempty = true;
    return ret;
}

void free_frame(frame_ref_t frame_ref)
{
    assert_main_thread();

    if (frame_ref != NULL_FRAME) {
        frame_t *frame = frame_from_ref(frame_ref);
        if(frame->backed) {
            if(frame->paged) {
                // free the page space
                frame->paged = false;
                // mark the backing page file as free
                assert(GET_BMP(frame_table.pf_bmp, frame->back_idx));
                TOGGLE_BMP(frame_table.pf_bmp, frame->back_idx);
            } else {
                page_cap_t pagecap = FRAME_PAGE_CAP(frame->back_idx);
                // revoke all derived frame page to ensure that no one is mapping it
                cspace_revoke(frame_table.cspace, pagecap.cap);
                // mark the backing frame as free
                assert(GET_FRAME_CAP_STATUS(frame->back_idx));
                TOGGLE_FRAME_CAP_FREE(frame->back_idx);
            }
            // either way, we removed the backing space!
            frame->backed = false;
        }
        // unpin the frame if needed
        frame->pinned = false;

        // also unmark this frame as file backed if it was file backed
        // it is caller's responsibility to close the file handle
        frame->file_backed = false;
        frame->file_pos = frame->file_backer = 0;

        remove_frame(&frame_table.allocated, frame);
        push_front(&frame_table.free, frame);

        // reset the clockhand if this frame was used last
        if(frame_table.clockhand == frame_ref)
            frame_table.clockhand = NULL_FRAME;
    }
}

static size_t frame_mem_page_idx(frame_ref_t frame_ref)
{
    assert_main_thread();

    frame_t *frame = frame_from_ref(frame_ref);
    size_t pageidx;
    if(frame->backed && !frame->paged) {
        pageidx = frame->back_idx;
    } else {
        pageidx = get_new_phy_frame();
        if(!pageidx) {
            ZF_LOGE("Failed to obtain a frame. Memory full!");
            return 0;
        } else {
            if(frame->reqempty) {
                // the frame object must be fresh!
                assert(!frame->backed);
                memset((void*)(SOS_FRAME_DATA + pageidx * PAGE_SIZE_4K), 0, PAGE_SIZE_4K);
                frame->reqempty = false;
            } else if (frame->backed && frame->paged) {
                if(frame->file_backed) {
                    // restore from the backed file
                    sos_filehandle_t* fh = (void*)frame->file_backer;
                    ssize_t rd = fh->fh->read(0, fh->id,frame_table.frame_data[pageidx], frame->file_pos * PAGE_SIZE_4K, PAGE_SIZE_4K);
                    ZF_LOGE_IF(rd <= 0, "Read file backed by file returned: %lld", rd);
                } else {
                    // restore from PF
                    ssize_t rdres = page_file.fh->read(0, page_file.id, frame_table.frame_data[pageidx],
                        frame->back_idx * PAGE_SIZE_4K, PAGE_SIZE_4K);
                    // should the read is failed for any reason, we'll bail out!
                    // we also consider unfulfilled reads as a failure as well ...
                    if(rdres != PAGE_SIZE_4K) {
                        ZF_LOGE("Error reading from page file: got %lld instead of %lld",
                            rdres, PAGE_SIZE_4K);
                        return 0;
                    }
                    // mark the backing page file as free
                    assert(GET_BMP(frame_table.pf_bmp, frame->back_idx));
                    TOGGLE_BMP(frame_table.pf_bmp, frame->back_idx);
                }
            }
            frame->back_idx = pageidx;
            frame->backed = true;
            frame->paged = false;
            if(frame->usage < MAX_FRAME_USAGE)
                ++frame->usage;
            // mark the physical frame capability as used
            assert(!GET_FRAME_CAP_STATUS(pageidx));
            TOGGLE_FRAME_CAP_FREE(pageidx);
        }
    }
    return pageidx;
}

static size_t evict_frame()
{
    size_t ret = NULL_FRAME;
    if(!frame_table.clockhand)
        frame_table.clockhand = frame_table.allocated.first;
    
    frame_t* fr;
    size_t trial_count = 0;
    while(frame_table.clockhand) {
        fr = frame_from_ref(frame_table.clockhand);
        // check if this frame is resident in memory
        if(fr->backed && !fr->paged && !fr->pinned) {
            // if usage count is 0, go ahead!
            if(!fr->usage) {
                ret = fr->back_idx;
                if(!page_out_frame(frame_table.clockhand)) {
                    ZF_LOGE("Error paging out frame.");
                    return 0;
                }
            } else {
                --fr->usage;
            }
        }
        // advance the clock hand
        frame_table.clockhand = fr->next;
        if(!frame_table.clockhand) {
            frame_table.clockhand = frame_table.allocated.first;
            if(trial_count++ > MAX_FRAME_USAGE)
                break;
        }

        if(ret)
            break;
    }
    return ret;
}

static size_t get_new_phy_frame()
{
    // find a page_cap_cont_t that contains a free frame
    ssize_t free_slot = -1;
    for(int retry = 0;; ++retry) {
        for(size_t i = 0; i < frame_table.cap_frame_count; ++i) {
            free_slot = bitfield_first_free(sizeof(frame_table.cap_frames->bmpfree)/sizeof(uint64_t),
                frame_table.cap_frames[i].bmpfree);
            // we'll always have an extra space in the bitmap due to the structure
            assert(free_slot >= 0);
            if(free_slot >= PAGE_CAP_CONT_CAPACITY)
                // full. check next container.
                free_slot = -1;
            else {
                free_slot += PAGE_CAP_CONT_CAPACITY * i;
                break;
            }
        }
        if(free_slot < 0) {
            if(retry) {
                ZF_LOGE("Ran out of frame cap store!");
                // we've tried allocating before. no dice. so bail out!
                break;
            }
            // try allocating new frame cap container
            uintptr_t vaddr = frame_table.cap_frames + frame_table.cap_frame_count;
            seL4_ARM_Page cptr = alloc_frame_at(vaddr);
            if(cptr == seL4_CapNull) {
                ZF_LOGE("Failed to allocate frame to store frame capabilities");
                break;
            }
            memset((void*)vaddr, 0, PAGE_SIZE_4K);
            // if this is the first allocation, set the sentinel 0th entry to non 0
            if(!frame_table.cap_frame_count) {
                TOGGLE_FRAME_CAP_FREE(0);
                assert(GET_BMP(frame_table.cap_frames->bmpfree, 0));
                // just fill with anything that is non zero :)
                frame_table.cap_frames->data[0].cap = LONG_MAX; 
            }
            ++frame_table.cap_frame_count;
        } else
            break;
    }
    // never return a sentinel frame
    assert(free_slot != 0);
    
    // check that our allocated slot does not exceed the defined frame limit
    #ifdef CONFIG_SOS_FRAME_LIMIT
    if (CONFIG_SOS_FRAME_LIMIT != 0ul) {
        if(free_slot >= CONFIG_SOS_FRAME_LIMIT) {
            ZF_LOGI("Configured frame limit exceeded.");
            free_slot = -1;
        }
    }
    #endif

    if(free_slot > 0) {
        page_cap_t* pagecap = &FRAME_PAGE_CAP(free_slot);
        
        // check if there is actually a page on the given index. if not, allocate!
        if(!pagecap->cap) {
            pagecap->cap = alloc_frame_at((uintptr_t)frame_table.frame_data[free_slot]);
            if(!pagecap->cap) {
                ZF_LOGE("Failed to allocate new page to store capability.");
                return 0;
            }
        }
    } else {
        // find a page to page out from allocated frames
        // if this returns 0 then we have no choice but to report it to caller
        free_slot = evict_frame();
    }

    return free_slot;
}

seL4_ARM_Page frame_page(frame_ref_t frame_ref)
{
    size_t pageidx = frame_mem_page_idx(frame_ref);
    if(pageidx)
        return FRAME_PAGE_CAP(pageidx).cap;
    return seL4_CapNull;
}

unsigned char *frame_data(frame_ref_t frame_ref)
{
    size_t pageidx = frame_mem_page_idx(frame_ref);
    if(pageidx) 
        return frame_table.frame_data[pageidx];
    return NULL;
}

void flush_frame(frame_ref_t frame_ref)
{
    frame_t *frame = frame_from_ref(frame_ref);
    if(!frame->paged && frame->backed) {
        seL4_ARM_Page pagecap = FRAME_PAGE_CAP(frame->back_idx).cap;
        seL4_ARM_Page_Clean_Data(pagecap, 0, BIT(seL4_PageBits));
        seL4_ARM_Page_Unify_Instruction(pagecap, 0, BIT(seL4_PageBits));
    }
}

void invalidate_frame(frame_ref_t frame_ref)
{
    frame_t *frame = frame_from_ref(frame_ref);
    if(!frame->paged && frame->backed) {
        seL4_ARM_Page pagecap = FRAME_PAGE_CAP(frame->back_idx).cap;
        seL4_ARM_Page_Invalidate_Data(pagecap, 0, BIT(seL4_PageBits));
    }
}

frame_t *frame_from_ref(frame_ref_t frame_ref)
{
    assert(frame_ref != NULL_FRAME);
    assert(frame_ref < frame_table.capacity);
    return &frame_table.frames[frame_ref];
}

static frame_ref_t ref_from_frame(frame_t *frame)
{
    if(!frame)
        return 0;
    assert(frame >= frame_table.frames);
    assert(frame < frame_table.frames + frame_table.used);
    return frame - frame_table.frames;
}

static void push_front(frame_list_t *list, frame_t *frame)
{
    assert(frame != NULL);
    assert(frame->list_id == NO_LIST);
    assert(frame->next == NULL_FRAME);
    assert(frame->prev == NULL_FRAME);

    frame_ref_t frame_ref = ref_from_frame(frame);

    if (list->last == NULL_FRAME) {
        list->last = frame_ref;
    }

    frame->next = list->first;
    if (frame->next != NULL_FRAME) {
        frame_t *next = frame_from_ref(frame->next);
        next->prev = frame_ref;
    }

    list->first = frame_ref;
    list->length += 1;
    frame->list_id = list->list_id;

    ZF_LOGD("%s.length = %lu", LIST_NAME(list), list->length);
}

static void push_back(frame_list_t *list, frame_t *frame)
{
    assert(frame != NULL);
    assert(frame->list_id == NO_LIST);
    assert(frame->next == NULL_FRAME);
    assert(frame->prev == NULL_FRAME);

    frame_ref_t frame_ref = ref_from_frame(frame);

    if (list->last != NULL_FRAME) {
        frame_t *last = frame_from_ref(list->last);
        last->next = frame_ref;

        frame->prev = list->last;
        list->last = frame_ref;

        frame->list_id = list->list_id;
        list->length += 1;
        ZF_LOGD("%s.length = %lu", LIST_NAME(list), list->length);
    } else {
        /* Empty list */
        push_front(list, frame);
    }
}

static frame_t *pop_front(frame_list_t *list)
{
    if (list->first != NULL_FRAME) {
        frame_t *head = frame_from_ref(list->first);
        if (list->last == list->first) {
            /* Was last in list */
            list->last = NULL_FRAME;
            assert(head->next == NULL_FRAME);
        } else {
            frame_t *next = frame_from_ref(head->next);
            next->prev = NULL_FRAME;
        }

        list->first = head->next;

        assert(head->prev == NULL_FRAME);
        head->next = NULL_FRAME;
        head->list_id = NO_LIST;
        head->prev = NULL_FRAME;
        head->next = NULL_FRAME;
        list->length -= 1;
        ZF_LOGD("%s.length = %lu", LIST_NAME(list), list->length);
        return head;
    } else {
        return NULL;
    }
}

static void remove_frame(frame_list_t *list, frame_t *frame)
{
    assert(frame != NULL);
    assert(frame->list_id == list->list_id);

    if (frame->prev != NULL_FRAME) {
        frame_t *prev = frame_from_ref(frame->prev);
        prev->next = frame->next;
    } else {
        list->first = frame->next;
    }

    if (frame->next != NULL_FRAME) {
        frame_t *next = frame_from_ref(frame->next);
        next->prev = frame->prev;
    } else {
        list->last = frame->prev;
    }

    list->length -= 1;
    frame->list_id = NO_LIST;
    frame->prev = NULL_FRAME;
    frame->next = NULL_FRAME;
    ZF_LOGD("%s.length = %lu", LIST_NAME(list), list->length);
}

static frame_t *alloc_fresh_frame(void)
{
    assert(frame_table.used <= frame_table.capacity);

    if (frame_table.used == frame_table.capacity) {
        if (bump_capacity() != 0) {
            /* Could not increase capacity. */
            return NULL;
        }
    }

    assert(frame_table.used < frame_table.capacity);

    if (frame_table.used == 0) {
        /* The first frame is a sentinel NULL frame. */
        frame_table.used = 1;
    }

    frame_t *frame = &frame_table.frames[frame_table.used];
    frame_table.used += 1;

    *frame = (frame_t) {
        .list_id = NO_LIST,
    };

    ZF_LOGD("Frame table contains %lu/%lu frames", frame_table.used, frame_table.capacity);
    return frame;
}

static int bump_capacity(void)
{
    // NOTE: the artificial frame limiter here is removed, as a frame can now refer
    // to both a physical frame and a page file.

    uintptr_t vaddr = (uintptr_t)frame_table.frames + frame_table.byte_length;

    seL4_ARM_Page cptr = alloc_frame_at(vaddr);
    if (cptr == seL4_CapNull) {
        return -1;
    }
    memset((void*)vaddr, 0, PAGE_SIZE_4K);

    frame_table.byte_length += BIT(seL4_PageBits);
    frame_table.capacity = frame_table.byte_length / sizeof(frame_t);

    ZF_LOGD("Frame table contains %lu/%lu frames", frame_table.used, frame_table.capacity);
    return 0;
}

static seL4_ARM_Page alloc_frame_at(uintptr_t vaddr)
{
    /* Allocate an untyped for the frame. */
    ut_t *ut = ut_alloc_4k_untyped(NULL);
    if (ut == NULL) {
        return seL4_CapNull;
    }

    /* Allocate a slot for the page capability. */
    seL4_ARM_Page cptr = cspace_alloc_slot(frame_table.cspace);
    if (cptr == seL4_CapNull) {
        ut_free(ut);
        return seL4_CapNull;
    }

    /* Retype the untyped into a page. */
    int err = cspace_untyped_retype(frame_table.cspace, ut->cap, cptr, seL4_ARM_SmallPageObject, seL4_PageBits);
    if (err != 0) {
        cspace_free_slot(frame_table.cspace, cptr);
        ut_free(ut);
        return seL4_CapNull;
    }

    /* Map the frame into SOS. */
    seL4_ARM_VMAttributes attrs = seL4_ARM_Default_VMAttributes | seL4_ARM_ExecuteNever;
    err = map_frame(frame_table.cspace, cptr, frame_table.vspace, vaddr, seL4_ReadWrite, attrs);
    if (err != 0) {
        cspace_delete(frame_table.cspace, cptr);
        cspace_free_slot(frame_table.cspace, cptr);
        ut_free(ut);
        return seL4_CapNull;
    }

    return cptr;
}

bool frame_set_pin(frame_ref_t frame_ref, bool pin)
{
    // avoid race condition with frame evictor
    assert_main_thread();
    
    frame_t* fr = frame_from_ref(frame_ref);
    bool ret = fr->pinned;
    fr->pinned = pin;
    return ret;
}

bool page_out_frame(frame_ref_t frame_ref)
{
    if(!page_file.id) {
        ZF_LOGE("Request page out, but page file is not ready.");
        return false;
    }

    frame_t* fr = frame_from_ref(frame_ref);
    if(fr->pinned)
        return false;
    if(fr->backed && !fr->paged) {
        // since we're only supporting read only file maps, we won't write anything to the
        // backing file upon page out.
        if(!fr->file_backed) {
            // find the first free page file slot
            ssize_t free_slot;
            for(int retry = 0;; ++retry) {
                free_slot = bitfield_first_free(frame_table.pf_bmp_count, frame_table.pf_bmp);
                if(free_slot < 0) {
                    if(retry) {
                        ZF_LOGE("Ran out of page file bitmap space!");
                        // we've tried allocating before. no dice. so bail out!
                        return false;
                    }
                    // try reallocating frame for PF
                    assert((frame_table.pf_bmp_count * sizeof(uint64_t)) % PAGE_SIZE_4K == 0);
                    uintptr_t vaddr = frame_table.pf_bmp + frame_table.pf_bmp_count;
                    seL4_ARM_Page cptr = alloc_frame_at(vaddr);
                    if(cptr == seL4_CapNull) {
                        ZF_LOGE("Failed to allocate frame to store page file bitmap space");
                        return false;
                    }
                    memset((void*)vaddr, 0, PAGE_SIZE_4K);
                    // if this is the first allocation, set the sentinel 0th entry to 0
                    if(!frame_table.pf_bmp_count) {
                        TOGGLE_BMP(frame_table.pf_bmp, 0);
                        assert(GET_BMP(frame_table.pf_bmp, 0));
                    }
                    frame_table.pf_bmp_count += PAGE_SIZE_4K / sizeof(uint64_t);
                } else
                    break;
            }
            // page out frame to file
            ssize_t wrres = page_file.fh->write(0, page_file.id, frame_table.frame_data[fr->back_idx], 
                free_slot * PAGE_SIZE_4K, PAGE_SIZE_4K);
            if(wrres != PAGE_SIZE_4K) {
                ZF_LOGE("Page file write error. Got %lld instead of %lld.", wrres, PAGE_SIZE_4K);
                return false;
            }
            // write OK. now mark the memory frame as free
            assert(GET_FRAME_CAP_STATUS(fr->back_idx));
            TOGGLE_FRAME_CAP_FREE(fr->back_idx);
            // and mark the page file area as used
            assert(!GET_BMP(frame_table.pf_bmp, free_slot));
            TOGGLE_BMP(frame_table.pf_bmp, free_slot);

            // change the index to page file's instead
            fr->back_idx = free_slot;
        }

        // invalidate the frame so that all derived caps are removed, and maps are unmapped
        cspace_revoke(frame_table.cspace, FRAME_PAGE_CAP(fr->back_idx).cap);

        // and mark the frame object as such
        fr->paged = true;
    }
    return true;
}

void frame_set_file_backing(frame_ref_t frame_ref, sos_filehandle_t* backer, size_t page_offset)
{
    assert((uintptr_t)backer < BIT(FILE_BACKER_PTR_BITS));
    assert(page_offset < BIT(FILE_OFFSET_BITS));

    frame_t* fr = frame_from_ref(frame_ref);
    // we don't support setting a frame backing twice
    assert(!fr->file_backed);
    assert(!fr->pinned);

    fr->file_backer = backer;
    fr->file_pos = page_offset;
    fr->file_backed = true;

    if(!fr->backed)
        // mark this so that next time a fault happens, IO operation will occur instead
        fr->paged = fr->backed = true;
    else {
        // if this frame is resident, discard whatever in it
        // remember that we only support read only here
        if(!fr->paged) 
            page_out_frame(frame_ref);
    }
}
