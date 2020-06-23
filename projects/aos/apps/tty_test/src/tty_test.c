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

#include <sos.h>

#include "ttyout.h"

#define PAGE_SIZE_4K 0x1000

char mymem[128];

extern int sos_errno;

void hello(size_t depth)
{
    printf("Hello %d!\n", depth);
    hello(depth + 1);
}

int main(void)
{
    sosapi_init_syscall_table();

    /* initialise communication */
    ttyout_init();

    //hello(0);

    char* tst = malloc(13107);
    printf("malloc = %p\n", tst);

    int fh = open("console", O_RDWR);
    write(fh, "Hello World!\n", 13);
    close(fh);

    tst[0] = 'a';

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
