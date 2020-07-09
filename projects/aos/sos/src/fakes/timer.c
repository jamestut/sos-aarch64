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
        spawn(timer_ticker, NULL, "fake_timer", 0, 0, 0);
        started = true;
        ZF_LOGI("Fake timer started!");
    }
}

void timer_ticker(void* unused)
{
    // TODO: GRP01 - messes with IPC. fix.
    while(1) {
        for(int i=0; i<10; ++i)
            seL4_Yield();
        timer_tick();
    }
}

#else

void start_fake_timer()
{
    /*we don't have to fake anything here as we have the REAL meson timer!*/
}

#endif
