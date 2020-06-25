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

#define MALLOC_SZ    1234
#define MALLOC_TEST  4000

char mymem[128];

extern int sos_errno;

void hello(size_t depth)
{
    printf("Hello %d!\n", depth);
    hello(depth + 1);
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
    write(fh, "Hello World!\n", 13);

    msglen = sprintf(msgbuff, "Test malloc size = %d, actual = %d\n", MALLOC_SZ, MALLOC_TEST);
    write(fh, msgbuff, msglen);

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
    ptr4[12000] = 'z';
    puts("OK");


    msglen = sprintf(msgbuff, "malloc ptr is = %p\n", ptr);
    write(fh, msgbuff, msglen);
    msglen = sprintf(msgbuff, "test write\n");
    write(fh, msgbuff, msglen);

    for(int i=0; i<MALLOC_TEST; ++i) {
        ptr[i] = 'A' + (i % 26);
        if(i % PAGE_SIZE_4K == 0) {
            //msglen = sprintf(msgbuff, "Wrote %d chars\n", i);
            //write(fh, msgbuff, msglen);
        }
    }

    msglen = sprintf(msgbuff, "test read\n");
    write(fh, msgbuff, msglen);

    bool haserr = false;
    for(int i=0; i<MALLOC_TEST; ++i) {
        if(ptr[i] != ('A' + (i % 26))) {
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
