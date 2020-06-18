#include <sel4/sel4.h>
#include <clock/clock.h>

#include "timer.h"
#include "../threads.h"

#ifndef CONFIG_PLAT_ODROIDC2
bool started = false;

void timer_ticker(void* unused);

void start_fake_timer()
{
    if(!started) {
        thread_create(timer_ticker, NULL, 0, true);
        started = true;
        ZF_LOGI("Fake timer started!");
    }
}

void timer_ticker(void* unused)
{
    while(1) {
        for(int i=0; i<10; ++i)
            seL4_Yield();
        timer_tick();
    }
}

#else

void start_fake_timer() {/*do nothing!*/}

#endif
