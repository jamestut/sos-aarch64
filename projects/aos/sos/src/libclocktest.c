#include "libclocktest.h"

#include <aos/sel4_zf_logif.h>
#include <stdint.h>
#include <clock/clock.h>
#include <stddef.h>

// callbacks

void callback1(uint32_t id, void *data)
{
    ZF_LOGI("Timer callback. ID = %d. Data = %llu. Timestamp = %llu ms.",
        id, (uintptr_t)data, get_time()/1000);
}

void callback_periodically(uint32_t id, void *data)
{
    ZF_LOGI("Timer callback periodically. ID = %d, Timestamp = %llu ms.",
        id, get_time()/1000);
    register_timer(3000 * 1000, callback_periodically, data);
}


void libclocktest_begin(void)
{
    uint32_t id;
    //id = register_timer(15000 * 1000, callback1, (void*)123);
    //id = register_timer(17000 * 1000, callback1, (void*)456);
    //id = register_timer(7000 * 1000, callback1, (void*)777);
    //id = register_timer(2000 * 1000, callback1, (void*)222);
    id = register_timer(1000 * 1000, callback_periodically, (void*)222);
    //id = register_timer(5000 * 1000, callback1, (void*)555);
    //id = register_timer(19000 * 1000, callback1, (void*)1997);
    //id = register_timer(100000 * 1000, callback1, (void*)1000000);
    //id = register_timer(200000 * 1000, callback1, (void*)2000000);
    //ZF_LOGI("Registered timer with ID = %d", id);
}

void libclocktest_manual_action(void)
{
    #ifdef CONFIG_PLAT_QEMU_ARM_VIRT
    ZF_LOGW("WARNING: manually call the IRQ handler.");
    while(1)
        timer_irq(NULL, 0, 0);
    #endif
}
