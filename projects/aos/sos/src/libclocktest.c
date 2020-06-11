#include "libclocktest.h"

#include <aos/sel4_zf_logif.h>
#include <stdint.h>
#include <stdio.h>
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
    // param data = hi 32 = number, lo 32 = delay in ms.
    uintptr_t cdata = data;

    printf("CP %d @ %llu ms.\n", (cdata >> 32ULL), get_time()/1000);
    register_timer((cdata & 0xFFFFFFFFULL) * 1000, callback_periodically, data);
}

void callback_delete(uint32_t id, void* data)
{
    int result = remove_timer((uint32_t)data);
    printf("Removing timer %d %s.\n", (uint32_t)data,
        result == CLOCK_R_OK ? "succeeded" : "failed");
}

void test1()
{
    register_timer(15000 * 1000, callback1, (void*)123);
    register_timer(17000 * 1000, callback1, (void*)456);
    register_timer(7000 * 1000, callback1, (void*)777);
    register_timer(2000 * 1000, callback1, (void*)222);
    register_timer(1000 * 1000, callback_periodically, (void*)((1ULL << 32ULL) | 123ULL));
    register_timer(1000 * 1000, callback_periodically, (void*)((2ULL << 32ULL) | 350ULL));
    register_timer(1000 * 1000, callback_periodically, (void*)((3ULL << 32ULL) | 660ULL));
    register_timer(6000 * 1000, callback1, (void*)555);
    register_timer(6000 * 1000, callback1, (void*)556);
    register_timer(6000 * 1000, callback1, (void*)557);
    register_timer(8000 * 1000, callback1, (void*)558);
    register_timer(3000 * 1000, callback1, (void*)1997);
    register_timer(100000 * 1000, callback1, (void*)1000000);
    register_timer(200000 * 1000, callback1, (void*)2000000);
}

void test2()
{
    // a lot of pending timers :)
    for(int i=1; i<=2048; ++i) {
        if(!register_timer(i * 100000, callback1, (void*)i)) {
            printf("Registered %d timers before failed.\n", i);
            break;
        }
    }
}

void test3()
{
    uintptr_t id;
    register_timer(15000 * 1000, callback1, (void*)123);
    register_timer(17000 * 1000, callback1, (void*)456);
    register_timer(11000 * 1000, callback_periodically, (void*)222);
    id = register_timer(7000 * 1000, callback1, (void*)777);
    register_timer(2000 * 1000, callback_delete, (void*)id);
    register_timer(6000 * 1000, callback1, (void*)555);
    register_timer(6000 * 1000, callback1, (void*)556);
    register_timer(6000 * 1000, callback1, (void*)557);
    id = register_timer(10000 * 1000, callback1, (void*)558000);
    register_timer(9500 * 1000, callback_delete, (void*)id);
    register_timer(3000 * 1000, callback1, (void*)1997);
    register_timer(100000 * 1000, callback1, (void*)1000000);
    register_timer(200000 * 1000, callback1, (void*)2000000);    
}

void libclocktest_begin(void)
{
    test2();
}

void libclocktest_manual_action(void)
{
    #ifndef CONFIG_PLAT_ODROIDC2
    ZF_LOGW("WARNING: manually call the IRQ handler.");
    while(1)
        timer_tick();
    #endif
}
