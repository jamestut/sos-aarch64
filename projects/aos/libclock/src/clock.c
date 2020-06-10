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
#include <math.h>

#include <clock/clock.h>

/* The functions in src/device.h should help you interact with the timer
 * to set registers and configure timeouts. */
#include "device.h"
#include "soslinkage.h"

// maximum numbers of clients registered
#define MAXCLIENTS 16

// structure to contain the registered client info.
struct clientinfo {
    uint64_t target_ts;
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

    // target timestamp
    uint64_t ts_target;
    // indicates if we set an interrupt timer
    bool timer_active;
} clock = {.started = false, .clockhand = 1, .handlerA = 0, .timer_active = false};

#ifndef CONFIG_PLAT_ODROIDC2
// fake state for platform w/o meson timer
// have to be periodically polled.
static struct {
    uint64_t currtime;
    int64_t timeout;
    int64_t timeout_set;
    bool enabled;
    bool periodic;
} fakestate = {.currtime = 0, .timeout = 0, .enabled = false};
#endif

/* procedures private to this compilation unit */
/**
 * Update the timer A IRQ to fire at the first element in queue (or the maximum 65.535 sec).
 */
void update_timer(void);

/**
 * Call configure_timeout from meson timer driver, but with compilation-time DTS check.
 */
inline void configure_timeout_hwchk(volatile meson_timer_reg_t *regs, timeout_id_t timer, bool enable,
                       bool periodic, timeout_timebase_t timebase, int64_t timeout);

int start_timer(unsigned char *timer_vaddr)
{
    if(!clock.started) {
        clock.regs = (meson_timer_reg_t *)(timer_vaddr + TIMER_REG_START);

        #ifdef CONFIG_PLAT_ODROIDC2
        // disable timer A
        configure_timeout(clock.regs, MESON_TIMER_A, false, true, TIMEOUT_TIMEBASE_1_MS, 1);

        int err;
        // register IRQ
        if(!clock.handlerA) {
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
    ZF_LOGW("Not compiled for meson. Timestamp is unavailable. Using fake state.");
    return fakestate.currtime;
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

    uint64_t curr_ts = get_time();

    // make it at least 1 us
    if(!delay)
        delay = 1;
    uint64_t target_ts = curr_ts + delay;

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
        target->target_ts = target_ts;
        ++clock.clientscount;

        // find a slot to put this handler on in the queue
        // remember, the queue have to be maintained ascending order by target_ts
        struct llnode** prevptr = &clock.queue; // ptr to curr
        struct llnode* curr = clock.queue;
        while(curr) {
            if(curr->cli->target_ts > target_ts)
                break;
            
            prevptr = &curr->next;
            curr = curr->next;
        }

        // put in the queue
        *prevptr = malloc(sizeof(struct llnode));
        (*prevptr)->cli = target;
        (*prevptr)->next = curr;

        // if we modify the queue head, also modify the current active timer.
        if(target == clock.queue->cli)
            update_timer();
    }

    // if ret is 0, then we have bug when checking above (or race condition??).
    ZF_LOGF_IF(!ret, "Retry count exceeded.");

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
            
            // update timer if this is the first in queue
            if(curr == clock.queue)
                update_timer();
            
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
    ZF_LOGD("Timer IRQ handler invoked.");

    // make sure that we're in valid state before doing something,
    // that is, we're active and has pending queue.
    if(clock.started && clock.queue) {
        int64_t currtime = get_time();
        
        // distance to the deadline in milliseconds
        int64_t dista_ms = ((int64_t)currtime - (int64_t)clock.ts_target) / 1000;
        ZF_LOGD("dista_ms = %d", dista_ms);

        if(dista_ms < -1) {
            // still faraway to the deadline. set the timer again and do nothing!
            dista_ms *= -1;
            configure_timeout_hwchk(clock.regs, MESON_TIMER_A, true, false, TIMEOUT_TIMEBASE_1_MS, dista_ms);
        } else {
            // we will fire the timer anyway if it is 1 ms before the deadline :)

            // indicates the pause to the next queue
            int64_t target_ms = 0;
            // keep executing if target is 0
            while(!target_ms) {
                // copy data to this stack as we're going to free the content
                // we do this so that if the callback does something w/ ourselves (e.g. add new timer)
                // we will be safe.
                struct clientinfo cli = *clock.queue->cli;
                uint32_t id = clock.queue->cli - clock.clients;

                // dequeue and free
                void* currqueue = clock.queue;
                memset(clock.queue->cli, 0, sizeof(struct clientinfo));
                clock.queue = clock.queue->next;
                free(currqueue);
                --clock.clientscount;

                // set the next timer if there still exists any queue 
                if(clock.queue) {
                    ZF_LOGD("Next queue exists.");
                    // update dista as we might spend some time doing previous processing
                    currtime = get_time();
                    dista_ms = ((int64_t)currtime - (int64_t)clock.ts_target) / 1000;
                    target_ms = ((int64_t)clock.queue->cli->target_ts - (int64_t)currtime) / 1000 - dista_ms;
                    ZF_LOGD("Next queue. dista_ms = %d, target_ms = %d", dista_ms, target_ms);
                    
                    // if we have some time processing the next item, then let the timer
                    // wake us up if it is the time :)
                    if(target_ms >= 1) {
                        ZF_LOGD("Setting timer for next queue.");
                        clock.ts_target = clock.queue->cli->target_ts;
                        configure_timeout_hwchk(clock.regs, MESON_TIMER_A, true, false, TIMEOUT_TIMEBASE_1_MS, target_ms);
                    } else {
                        // missed the deadline. execute next queue ASAP.
                        ZF_LOGD("Executing the next queue directly.");
                        target_ms = 0;
                    }
                } else {
                    // no more queue = disable timer
                    clock.timer_active = false;
                    target_ms = 42; // stop :)
                }
                // fire!
                cli.callback(id, cli.data);
            }
        }
    } else {
        ZF_LOGD("Received timer IRQ when timer is disabled.");
    }

    /* Acknowledge that the IRQ has been handled */
    if(irq_handler)
        seL4_IRQHandler_Ack(irq_handler);
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

void update_timer(void)
{
    if(!clock.queue)
    {
        // no active queue. disable time interrupt.
        clock.timer_active = false;
        configure_timeout(clock.regs, MESON_TIMER_A, false, false, TIMEOUT_TIMEBASE_1_MS, 1);
        return;
    }

    // use this timestamp as current time reference in this session, no matter what.
    uint64_t curr_ts = get_time();

    if(clock.timer_active) {
        // update the existing active timer
        
        // new target
        clock.ts_target = clock.queue->cli->target_ts;
        // remaining time in ms to target
        int64_t rem_ms = ((int64_t)clock.ts_target - (int64_t)curr_ts) / 1000;

        // the hwchk version will automatically truncate large values and <1 to 1.
        configure_timeout_hwchk(clock.regs, MESON_TIMER_A, true, false, TIMEOUT_TIMEBASE_1_MS, rem_ms);
    } else {
        // just set the timer variables here
        clock.ts_target = clock.queue->cli->target_ts;
        clock.timer_active = true;
        
        // actually configure the hardware
        configure_timeout_hwchk(clock.regs, MESON_TIMER_A, true, false, TIMEOUT_TIMEBASE_1_MS,
            (clock.ts_target - curr_ts) / 1000);
    }
}

void configure_timeout_hwchk(volatile meson_timer_reg_t *regs, timeout_id_t timer, bool enable,
                       bool periodic, timeout_timebase_t timebase, int64_t timeout)
{
    #ifdef CONFIG_PLAT_ODROIDC2
    if(timeout <= 0) {
        ZF_LOGD("Timeout was set to zero or negative. Reverting to 1.");
        timeout = 1;
    } else if (timeout > 0xFFFF) {
        ZF_LOGV("Timeout %lld too large. Truncated to %d.", timeout, 0xFFFF);
        timeout = 0xFFFF;
    }
    configure_timeout(regs, timer, enable, periodic, timebase, timeout);
    #else
    ZF_LOGW("Meson timer configuration not available on this platform. Using mock state.");
    switch(timebase) {
        case TIMEOUT_TIMEBASE_1_US:
            fakestate.timeout = timeout;
            break;
        case TIMEOUT_TIMEBASE_10_US:
            fakestate.timeout = timeout * 10;
            break;
        case TIMEOUT_TIMEBASE_100_US:
            fakestate.timeout = timeout * 100;
            break;
        case TIMEOUT_TIMEBASE_1_MS:
            fakestate.timeout = timeout * 1000;
            break;
    }
    fakestate.timeout_set = fakestate.timeout;
    fakestate.enabled = enable;
    fakestate.periodic = periodic;
    #endif
}

void timer_tick()
{
    #ifndef CONFIG_PLAT_ODROIDC2
    const uint64_t acc = 10000; // in us
    fakestate.currtime += acc;
    if(fakestate.enabled) {
        fakestate.timeout -= acc;
        if(fakestate.timeout <= 0) {
            if(fakestate.periodic)
                fakestate.timeout = fakestate.timeout_set;
            else
                fakestate.enabled = false;
            timer_irq(NULL, 0, 0);
        }
    }
    #endif
}