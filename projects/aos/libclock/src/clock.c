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

    // timestamp when the timer was set
    uint64_t ts_set;
    // target timestamp
    uint64_t ts_target;
    // indicates if we set an interrupt timer
    bool timer_active;
} clock = {.started = false, .clockhand = 1, .handlerA = 0, .timer_active = false,
    .ts_set = 0};

// GRP01: for local debug
#ifdef CONFIG_PLAT_QEMU_ARM_VIRT
static struct {
    uint64_t currtime;
} fakestate = {.currtime = 0};
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
            // update the time remaining of the next node, if exists
            if(*prevptr)
                (*prevptr)->cli->remaining += target->remaining;
            
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

    if(clock.started && clock.queue) {
        int64_t currtime = get_time();
        
        int64_t dista_ms = (currtime - (int64_t)clock.ts_target) / 1000;

        // GRP01: just for debugging
        // #ifdef CONFIG_PLAT_QEMU_ARM_VIRT
        // dista_ms = 0;
        // #endif

        if(dista_ms < -1) {
            // still faraway to the deadline. set the timer again and do nothing!
            dista_ms *= -1;
            configure_timeout_hwchk(clock.regs, MESON_TIMER_A, true, false, TIMEOUT_TIMEBASE_1_MS, dista_ms);
        } else {
            // we will fire the timer anyway if it is 1 ms before the deadline :)

            // copy data to this stack as we're going to free the content
            // we do this so that if the callback does something w/ ourselves (e.g. add new timer)
            // we will be safe.
            struct clientinfo cli = *clock.queue->cli;
            uint32_t id = clock.queue->cli - clock.clients;

            // TODO: handle if the next queue has 0 timeout
            // dequeue and free
            void* currqueue = clock.queue;
            memset(clock.queue->cli, 0, sizeof(struct clientinfo));
            clock.queue = clock.queue->next;
            free(currqueue);
            --clock.clientscount;
            // GRP01: debug
            ZF_LOGI("Number of active clients after dequeue: %d", clock.clientscount);

            // set the next timer if exists
            if(clock.queue) {
                // dista_ms is how much we've missed the deadline (or too early)
                // update clock data
                clock.ts_set = currtime;
                int64_t target_ms = clock.queue->cli->remaining - dista_ms;
                clock.ts_target = currtime + target_ms * 1000;
                configure_timeout_hwchk(clock.regs, MESON_TIMER_A, true, false, TIMEOUT_TIMEBASE_1_MS, target_ms);
            } else {
                clock.timer_active = false;
            }

            // fire!
            cli.callback(id, cli.data);
        }
    } else {
        ZF_LOGD("Received timer IRQ when timer is disabled.");
    }

    /* Acknowledge that the IRQ has been handled */
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
        // elapsed time between the last time we set the timer and now.
        ZF_LOGF_IF(curr_ts < clock.ts_set, "Timer was set in the future.");
        uint64_t elapsed_ms = (curr_ts - clock.ts_set) / 1000;
        
        // new target
        // when the timer has to fire
        int64_t target_ms = clock.queue->cli->remaining - elapsed_ms;
        // what is the actual target relative to when the time was started prior
        clock.ts_target = clock.ts_set + (clock.queue->cli->remaining) * 1000;
        
        if(target_ms <= 0)
            // we've missed the deadline. set timer to fire immediately!
            configure_timeout_hwchk(clock.regs, MESON_TIMER_A, true, false, TIMEOUT_TIMEBASE_1_MS, 1);
        else
            configure_timeout_hwchk(clock.regs, MESON_TIMER_A, true, false, TIMEOUT_TIMEBASE_1_MS, target_ms);
    } else {
        // just set the timer here
        clock.ts_set = curr_ts;
        clock.ts_target = curr_ts + (clock.queue->cli->remaining) * 1000;
        clock.timer_active = true;
        
        // actually configure the hardware
        configure_timeout_hwchk(clock.regs, MESON_TIMER_A, true, false, TIMEOUT_TIMEBASE_1_MS, clock.queue->cli->remaining);
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
    ZF_LOGW("Meson timer configuration not available on this platform. Using fake state instead.");
    fakestate.currtime += timeout * 1000;
    #endif
}