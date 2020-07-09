#include "md5.h"
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>

#define FILENAME "Sunset.heic"
#define BUFFSZ 100000

void doit()
{
    puts("MD5 Calculator");
    printf("Open file: %s\n", FILENAME);

    mbedtls_md5_context md5ctx;
    mbedtls_md5_init(&md5ctx);

    if(mbedtls_md5_starts_ret(&md5ctx)) {
        puts("MD5 start error");
        return;
    }

    printf("Start time = %lld ms\n", sos_sys_time_stamp() / 1000);

    int fh = open(FILENAME, O_RDONLY);
    printf("Got FH = %d\n", fh);
    size_t acc = 0;
    if(fh >= 0) {
        void *buff = mmap(NULL, BUFFSZ, PROT_WRITE | PROT_READ, MAP_ANON, 0, 0);
        printf("Target buffer = %p\n", buff);
        ssize_t rd = 0;
        for(;;) {
            rd = read(fh, buff, BUFFSZ);
            if(rd < 0) {
                printf("Read error: %lld\n", rd);
                return;
            }
            acc += rd;
            if(mbedtls_md5_update_ret(&md5ctx, buff, rd)) {
                puts("MD5 update error");
                return;
            }
            if(rd < BUFFSZ)
                break;
            printf("Processed %d bytes\n", acc);
        }
    }
    printf("Total read: %llu\n", acc);
    unsigned char output[16];
    if(mbedtls_md5_finish_ret(&md5ctx, output)) {
        puts("MD5 finish error");
        return;
    }

    fputs("Hash: ", stdout);
    for(int i=0; i<sizeof(output); ++i)
        printf("%02x", output[i]);
    putchar('\n');

    printf("Finish time = %lld ms\n", sos_sys_time_stamp() / 1000);

    close(fh);
}

int main()
{
    sosapi_init_syscall_table();

    ttyout_init();

    doit();
}