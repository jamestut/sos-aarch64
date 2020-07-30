#include <stdio.h>
#include <unistd.h>
#include <sos.h>

#define INTERVAL_MS 1000

int main(void)
{
    sosapi_init_syscall_table();
    printf("Cuckoo PID %d started! Interval: %d ms\n", sos_my_id(), INTERVAL_MS);
    while(1) {
        sos_sys_usleep(INTERVAL_MS);
        printf("Cuckoo! Current millis: %llu\n", sos_sys_time_stamp() / 1000);
    }
}
