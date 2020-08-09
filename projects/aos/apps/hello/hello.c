#include <stdio.h>
#include <unistd.h>
#include <sos.h>
#include <fcntl.h>

int main(void)
{
    sosapi_init_syscall_table();
    puts("Hello World!");
    _exit(0);
}