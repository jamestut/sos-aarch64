#include "libclocktest.h"

#include <aos/sel4_zf_logif.h>
#include <stdint.h>
#include <clock/clock.h>
#include <stddef.h>

// callbacks

void callback1(uint32_t id, void *data)
{
    printf("Timer callback. ID = %d. Data = %llu. Timestamp = %llu ms.\n",
        id, (uintptr_t)data, get_time()/1000);
}

void callback_periodically(uint32_t id, void *data)
{
    printf("CP1 %llu ms.\n", get_time()/1000);
    // ZF_LOGI("Timer callback periodically. ID = %d, Timestamp = %llu ms.",
    //     id, get_time()/1000);
    register_timer(123 * 1000, callback_periodically, data);

    // remove_timer(11);
    // remove_timer(12);
}

void callback_periodically_2(uint32_t id, void *data)
{
    printf("CP2 %llu ms.\n", get_time()/1000);
    // ZF_LOGI("Timer callback periodically. ID = %d, Timestamp = %llu ms.",
    //     id, get_time()/1000);
    register_timer(350 * 1000, callback_periodically_2, data);
}

void callback_periodically_3(uint32_t id, void *data)
{
    printf("CP3 %llu ms.\n", get_time()/1000);
    // ZF_LOGI("Timer callback periodically. ID = %d, Timestamp = %llu ms.",
    //     id, get_time()/1000);
    register_timer(660 * 1000, callback_periodically_3, data);
}

void libclocktest_begin(void)
{
    uint32_t id;
    id = register_timer(15000 * 1000, callback1, (void*)123);
    id = register_timer(17000 * 1000, callback1, (void*)456);
    id = register_timer(7000 * 1000, callback1, (void*)777);
    id = register_timer(2000 * 1000, callback1, (void*)222);
    id = register_timer(1000 * 1000, callback_periodically, (void*)222);
    id = register_timer(1000 * 1000, callback_periodically_2, (void*)222);
    id = register_timer(1000 * 1000, callback_periodically_3, (void*)222);
    id = register_timer(6000 * 1000, callback1, (void*)555);
    id = register_timer(6000 * 1000, callback1, (void*)556);
    id = register_timer(6000 * 1000, callback1, (void*)557);
    id = register_timer(8000 * 1000, callback1, (void*)558);
    id = register_timer(3000 * 1000, callback1, (void*)1997);
    id = register_timer(100000 * 1000, callback1, (void*)1000000);
    id = register_timer(200000 * 1000, callback1, (void*)2000000);
    //ZF_LOGI("Registered timer with ID = %d", id);
}

void libclocktest_manual_action(void)
{
    #ifndef CONFIG_PLAT_ODROIDC2
    ZF_LOGW("WARNING: manually call the IRQ handler.");
    while(1)
        timer_tick();
    #endif
}
