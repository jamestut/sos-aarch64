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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <clock/clock.h>

/* The functions in src/device.h should help you interact with the timer
 * to set registers and configure timeouts. */
#include "device.h"
#include "soslinkage.h"

// maximum numbers of clients registered
#define MAXCLIENTS 16

// structure to contain the registered client info.
struct clientinfo {
    uint64_t remaining; // milliseconds
    timer_callback_t callback;
    void* data;
};

// structure to maintain queue
struct llnode {
    struct clientinfo* cli;
    struct llnode* next;
};

static struct {
    volatile meson_timer_reg_t *regs;
    /* Add fields as you see necessary */
    seL4_IRQHandler handlerA;
    bool started;

    // the "clockhand" for figuring out which slot to use in clients
    uint16_t clockhand;
    uint16_t clientscount;
    // ID given out to clients maps directly with index in this array
    struct clientinfo clients[MAXCLIENTS];
    // must be maintained from earliest to latest
    struct llnode* queue;
} clock = {.started = false, .clockhand = 1, .handlerA = 0};

int start_timer(unsigned char *timer_vaddr)
{
    if(!clock.started) {
        clock.regs = (meson_timer_reg_t *)(timer_vaddr + TIMER_REG_START);

        #ifdef CONFIG_PLAT_ODROIDC2
        // disable timer A
        configure_timeout(clock.regs, MESON_TIMER_A, false, true, TIMEOUT_TIMEBASE_1_MS, 1);

        int err;
        // register IRQ
        err = sos_register_irq_handler(meson_timeout_irq(MESON_TIMER_A), true, timer_irq, NULL, &clock.handlerA);
        if(err) {
            ZF_LOGE("Error registering IRQ handler with SOS (code %d).", err);
            return CLOCK_R_FAIL;
        }
        err = seL4_IRQHandler_Ack(clock.handlerA);
        if(err) {
            ZF_LOGE("Error acknowledging IRQ handler with seL4 (code %d).", err);
            return CLOCK_R_FAIL;
        }

        // configure timer E
        configure_timestamp(clock.regs, TIMESTAMP_TIMEBASE_1_US);
        
        #else
        ZF_LOGW("Compiled for non meson target. Actual timer interrupt won't be working.");
        #endif

        // we assume that inside "clients" are all invalid
        memset(clock.clients, 0, sizeof(struct clientinfo) * MAXCLIENTS);
        clock.queue = NULL;

        clock.started = true;
        return CLOCK_R_OK;
    } else {
        return stop_timer();
    }
}

timestamp_t get_time(void)
{
    ZF_LOGI_IF(!clock.started, "Requested timestamp while clock is not running.");
    #ifdef CONFIG_PLAT_ODROIDC2
    return clock.started ? read_timestamp(clock.regs) : 0;
    #else
    ZF_LOGW("Not compiled for meson. Timestamp is unavailable.");
    return 0;
    #endif
}

uint32_t register_timer(uint64_t delay, timer_callback_t callback, void *data)
{
    // the usual error checks
    if(!clock.started) {
        ZF_LOGW("Attempt to register a timer handler when clock is not started.");
        return 0;
    }
    // remember, we reserve slot 0
    if(clock.clientscount >= (MAXCLIENTS-1)) {
        ZF_LOGW("Clock handler slot is full.");
        return 0;
    }
    if(!callback) {
        ZF_LOGW("Callback is NULL.");
        return 0;
    }

    // convert delay to millisecond, and make it at least 1 ms
    delay /= 1000;
    if(!delay)
        ++delay;

    // find a slot
    uint32_t ret = 0;
    for(int i=0; i<MAXCLIENTS; ++i) {
        if(!clock.clients[clock.clockhand].callback)
            ret = clock.clockhand;
        
        // increment clockhand. remember that 0 is reserved.
        clock.clockhand = (clock.clockhand + 1) % MAXCLIENTS;
        if(!clock.clockhand)
            ++clock.clockhand;

        if(ret)
            break;
    }

    if(ret) {
        struct clientinfo* target = clock.clients + ret;
        target->callback = callback;
        target->data = data;
        ++clock.clientscount;

        // find a slot to put this handler on in the queue
        struct llnode** prevptr = &clock.queue; // ptr to curr
        struct llnode* curr = clock.queue;
        while(curr) {
            if(curr->cli->remaining > delay)
                break;
            
            delay -= curr->cli->remaining;
            prevptr = &curr->next;
            curr = curr->next;
        }

        *prevptr = malloc(sizeof(struct llnode));
        (*prevptr)->cli = target;
        (*prevptr)->next = curr;
        
        target->remaining = delay;

        // if we have a next node, ensure that the next node remaining is substracted
        if(curr) 
            curr->cli->remaining -= delay;
    }

    // if ret is 0, then we have bug when checking above (or race condition??).
    ZF_LOGF_IF(!ret, "Retry count exceeded.");

    // TODO: update timer timeout

    return ret;
}

int remove_timer(uint32_t id)
{
    // the usual checks
    if(id >= MAXCLIENTS) {
        ZF_LOGW("Timer ID to remove is larger than what is possible.");
        return CLOCK_R_FAIL;
    }
    // check if the target slot is available
    if(!clock.clients[id].callback) {
        ZF_LOGW("Invalid ID to remove.");
        return CLOCK_R_FAIL;
    }

    struct clientinfo* target = clock.clients + id;
    
    // remove from queue
    struct llnode** prevptr = &clock.queue;
    struct llnode* curr = clock.queue;    
    while(curr) {
        if(curr->cli == target) {
            *prevptr = curr->next;
            // update the time remaining of the next node, if exists
            if(*prevptr)
                (*prevptr)->cli->remaining += target->remaining;
            
            // TODO: update timer if this is the first in queue
            if(curr == clock.queue) {

            }
            
            free(curr);
            break;
        }
        prevptr = &curr->next;
        curr = curr->next;
    }    
    
    // zero out target. the zero callback field means that the slot is regarded as empty
    memset(target, 0, sizeof(struct clientinfo));

    --clock.clientscount;
    return CLOCK_R_OK;
}

int timer_irq(
    void *data,
    seL4_Word irq,
    seL4_IRQHandler irq_handler
)
{
    // TODO:
    if(clock.started) {
    }

    /* Acknowledge that the IRQ has been handled */
    seL4_IRQHandler_Ack(clock.handlerA);
    return CLOCK_R_OK;
}

int stop_timer(void)
{
    ZF_LOGI_IF(!clock.started, "Stopping an already stopped libclock.");

    /* Stop the timer from producing further interrupts and remove all
     * existing timeouts */
    configure_timeout(clock.regs, MESON_TIMER_A, false, false, TIMEOUT_TIMEBASE_1_MS, 1);
    if(clock.started) {
        clock.started = false;
    }
    
    return CLOCK_R_OK;
}
