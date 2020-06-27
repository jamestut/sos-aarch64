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

#define MALLOC_SZ      128*1024*1024
#define MALLOC_TEST    MALLOC_SZ
#define WRITE_TEST_SZ  20000

char mymem[128];

extern int sos_errno;

void recurse_test(size_t depth)
{
    printf("Hello %d!\n", depth);
    recurse_test(depth + 1);
}

void read_test(int fh)
{
    int rs;
    printf("Read invalid pointer. \n");
    rs = read(fh, 1234, 100);
    printf("Got: %d\n", rs);

    puts("Read local stack. Please enter at least 100 chars");
    char test[100];
    strcpy(test, "for debugging");
    rs = read(fh, test, 100);
    printf("Got: %d\n", rs);
    puts("Data:");
    write(fh, test, 100);

    char* test_mmap = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_ANON, 0, 0);
    char* test_mmap2 = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_ANON, 0, 0);
    printf("mmap 1 = %p\n", test_mmap);
    printf("mmap 2 = %p\n", test_mmap2);
    
    puts("Read out of bound. Please enter at least 10 chars.");
    rs = read(fh, test_mmap2 + 16380, 10);
    printf("Got: %d\n", rs);

    puts("Read across page boundary. Please enter at least 100 chars.");
    rs = read(fh, test_mmap + 0x2FF0, 100);
    printf("Got: %d\n", rs);
    puts("Data:");
    write(fh, test_mmap + 0x2FF0, rs);
    putchar('\n');

    puts("Read across adjacent segment boundary. Please enter at least 100 chars.");
    rs = read(fh, test_mmap + 0x3FF0, 100);
    printf("Got: %d\n", rs);
    puts("Data:");
    write(fh, test_mmap + 0x3FF0, rs);
    putchar('\n');

    puts("Read large max 20000 chars");
    rs = read(fh, test_mmap + 0x1100, 20000);
    printf("Got: %d\n", rs);
    puts("Will show result in 2 sec. Be ready!");
    sleep(2);
    puts("Data:");
    write(fh, test_mmap + 0x1100, rs);
    putchar('\n');
}

void write_test(int fh)
{
    int rs;
    puts("Write from NULL buffer.");
    rs = write(fh, NULL, 10);
    printf("Result: %d\n", rs);

    puts("Write untouched mmap. Expect garbage (or emptyness).");
    char* testrw = mmap(NULL, 16384, PROT_WRITE | PROT_READ, MAP_ANON, 0, 0);
    printf("mmap addr: %p\n", testrw);
    rs = write(fh, testrw + 10, 15);
    putchar('\n');

    puts("Write across page boundary.");
    assert(rs == -1);
    strcpy(testrw + 4088, "This text spawns across page boundary!");
    rs = write(fh, testrw + 4088, 38);
    putchar('\n');

    puts("write data of several pages, consisting of repeating A-Z.");
    printf("Writing %d bytes\n", WRITE_TEST_SZ);
    char* data = malloc(WRITE_TEST_SZ);
    for(int i=0; i<WRITE_TEST_SZ; ++i)
        data[i] = 'A' + (i%26);
    write(fh, data, WRITE_TEST_SZ);
    putchar('\n');

    puts("PASS!");
}

void vmem_abuse()
{
    puts("Test many mmap and touches them!");
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
    munmap(ptr + 4096, 8192);
    printf("Unmapped\n");
    munmap(ptr4 + 8192, 32768);
    ptr4[7700] = 'z';
    puts("OK");
    ptr4[100000] = 'z';
    puts("OK");
    {
        // uncomment to test fault
        //ptr4[10000] = 'z';
        //puts("Success??");
    }

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
    {
        // uncomment to fault
        //bigmmap[0x54321DEFAB] = 'D';
        //puts("Success???");
    }

    printf("Malloc test of size %d\n", MALLOC_SZ);
    char* malloctgt = malloc(MALLOC_SZ);
    printf("malloc ptr is = %p\n", malloctgt);
    puts("Test write");
    for(int i=0; i<MALLOC_TEST; ++i) 
        malloctgt[i] = 'A' + (i % 26);
    puts("Write OK. Now reading back and confirm correctness.");

    bool haserr = false;
    for(int i=0; i<MALLOC_TEST; ++i) {
        if(malloctgt[i] != ('A' + (i % 26))) {
            haserr = true;
            printf("Data error at item #%d\n", i);
        }
    }
    if(!haserr)
        puts("Data confirmed correct!");
    puts("Finished read test.");
}

int main(void)
{
    long ret;
    sosapi_init_syscall_table();

    sos_debug_print("tty_test started\n", 17);

    /* initialise communication */
    ttyout_init();

    printf("Current stack is %d pages\n", sos_grow_stack(0));
    printf("New stack is now %d pages\n", sos_grow_stack(999999999));
    printf("Regrowing again. Stack is now %d pages\n", sos_grow_stack(999999999));

    int testfh = open("console", O_RDWR);

    // recurse_test(0);
    // read_test(testfh);
    vmem_abuse();
    // write_test(testfh);

    while(1)
        sleep(1000);

    return 0;
}
