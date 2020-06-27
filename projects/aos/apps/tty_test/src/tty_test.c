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
/****************************************************************************
 *
 *      $Id:  $
 *
 *      Description: Simple milestone 0 test.
 *
 *      Author:         Godfrey van der Linden
 *      Original Author:    Ben Leslie
 *
 ****************************************************************************/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sel4/sel4.h>
#include <syscalls.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>
#include <sys/mman.h>

#include <sos.h>

#include "ttyout.h"

#define PAGE_SIZE_4K 0x1000

#define MALLOC_SZ    20000
#define MALLOC_TEST  20000

char mymem[128];

extern int sos_errno;

void hello(size_t depth)
{
    printf("Hello %d!\n", depth);
    hello(depth + 1);
}

void printbuff(char* b, size_t len)
{
    for(size_t i = 0; i < len; ++i)
        putchar(b[i]);
    putchar('\n');
    putchar('\n');
}

void printfmt()
{
    
}

void read_test(int fh)
{
    int rs;
    printf("Read invalid pointer. \n");
    rs = read(fh, 1234, 100);
    printf("Got: %d\n", rs);

    printf("Read local stack. \n");
    char test[100];
    strcpy(test, "for debugging");
    rs = read(fh, test, 100);
    printf("Got: %d\n", rs);
    puts("Data:");
    printbuff(test, 100);

    char* test_mmap = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_ANON, 0, 0);
    char* test_mmap2 = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_ANON, 0, 0);
    printf("mmap 1 = %p\n", test_mmap);
    printf("mmap 2 = %p\n", test_mmap2);
    
    puts("Read out of bound");
    rs = read(fh, test_mmap2 + 16380, 10);
    printf("Got: %d\n", rs);

    puts("Read across page boundary");
    rs = read(fh, test_mmap + 0x2FF0, 100);
    printf("Got: %d\n", rs);
    puts("Data:");
    printbuff(test_mmap + 0x2FF0, 100);

    puts("Read across adjacent segment boundary");
    rs = read(fh, test_mmap + 0x3FF0, 100);
    printf("Got: %d\n", rs);
    puts("Data:");
    printbuff(test_mmap + 0x3FF0, 100);

    puts("Read large");
    rs = read(fh, test_mmap + 0x1100, 20000);
    printf("Got: %d\n", rs);
    puts("Will show result in 4 sec. Be ready!");
    //sleep(4);
    puts("Data:");
    printbuff(test_mmap + 0x1100, 20000);
}

void write_test(int fh)
{

}

int main(void)
{
    long ret;
    sosapi_init_syscall_table();

    /* initialise communication */
    ttyout_init();

    printf("Current stack is %d pages\n", sos_grow_stack(0));
    printf("New stack is now %d pages\n", sos_grow_stack(999999999));
    printf("Regrowing again. Stack is now %d pages\n", sos_grow_stack(999999999));
    //hello(0);

    char msgbuff[128];
    int msglen;

    int fh = open("console", O_RDWR);
    int rs = write(fh, "Hello World! Read test!\n", 24);
    read_test(fh);

    rs = write(fh, NULL, 10);

    char* testrw = mmap(NULL, 16384, PROT_WRITE | PROT_READ, MAP_ANON, 0, 0);
    rs = write(fh, testrw + 10, 15);
    assert(rs == -1);
    strcpy(testrw + 4090, "Across page boundary!");
    rs = write(fh, testrw + 4090, 21);


    msglen = sprintf(msgbuff, "Test malloc size = %d, actual = %d\n", MALLOC_SZ, MALLOC_TEST);
    rs = write(fh, msgbuff, msglen);

    char* ptr = mmap(NULL, 16384, PROT_WRITE | PROT_READ, MAP_ANON, 0, 0);
    printf("ptr1: %p\n", ptr);
    char* ptr2 = mmap(NULL, 32768, PROT_WRITE | PROT_READ, MAP_ANON, 0, 0);
    printf("ptr2: %p\n", ptr2);
    char* ptr3 = mmap(NULL, 65536, PROT_WRITE | PROT_READ, MAP_ANON, 0, 0);
    printf("ptr3: %p\n", ptr3);
    char* ptr4 = mmap(NULL, 131072, PROT_WRITE | PROT_READ, MAP_ANON, 0, 0);
    printf("ptr4: %p\n", ptr4);
    ptr[2] = 'a';
    ptr[14000] = 'b';
    ptr[10000] = 'c';
    ret = munmap(ptr + 4096, 8192);
    printf("Unmapped\n");
    munmap(ptr4 + 8192, 32768);
    ptr4[7700] = 'z';
    puts("OK");
    ptr4[100000] = 'z';
    puts("OK");
    //ptr4[10000] = 'z';

    printf("Big mmap\n");
    char* bigmmap = mmap(NULL, 0xFFFFFFFF000, PROT_WRITE | PROT_READ, MAP_ANON, 0, 0);
    printf("Big mmap addr = %p\n", bigmmap);
    printf("Big mmap touching ...\n");
    // touch some
    bigmmap[0x12345] = 'A';
    bigmmap[0x77777700] = 'B';
    bigmmap[0xABCDEF1234] = 'C';
    bigmmap[0x54321DEFAB] = 'D';
    munmap(bigmmap, 0xFFFFFFFF000);
    printf("Big mmap unmapped\n");
    
    strcpy(ptr4 + 100000, "console");
    int fh2 = open(ptr4 + 100000, O_RDWR);

    char* malloctgt = malloc(MALLOC_SZ);
    msglen = sprintf(msgbuff, "malloc ptr is = %p\n", malloctgt);
    write(fh, msgbuff, msglen);
    msglen = sprintf(msgbuff, "test write\n");
    write(fh, msgbuff, msglen);

    for(int i=0; i<MALLOC_TEST; ++i) {
        malloctgt[i] = 'A' + (i % 26);
    }

    msglen = sprintf(msgbuff, "test read\n");
    write(fh, msgbuff, msglen);

    bool haserr = false;
    for(int i=0; i<MALLOC_TEST; ++i) {
        if(malloctgt[i] != ('A' + (i % 26))) {
            msglen = sprintf(msgbuff, "Data error at item #%d\n", i);
            write(fh, msgbuff, msglen);
            haserr = true;
            break;
        }
    }

    if(!haserr) {
        msglen = sprintf(msgbuff, "test passed!\n");
        write(fh, msgbuff, msglen);
    }

    msglen = sprintf(msgbuff, "Try long write to FH %d\n", fh2);
    write(fh2, msgbuff, msglen);

    rs = write(fh2, malloctgt, MALLOC_SZ);
    
    close(fh);
    while(1){}

    int ctr = 0;
    calloc(123456789, 1);
    while(1) {
        for(int i=1000; i<=100000; ++i) {
            void* ptr = calloc(i, 1); //tes
            printf("malloc %d bytes result = %p\n", i, ptr);
            free(ptr);
        }
    }

    return 0;
}
