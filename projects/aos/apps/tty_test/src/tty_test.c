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

char mymem[40000];

// Block a thread forever
// we do this by making an unimplemented system call.
static void thread_block(void)
{
    /* construct some info about the IPC message tty_test will send
     * to sos -- it's 1 word long */
    seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 1);
    /* Set the first word in the message to 0 */
    seL4_SetMR(0, 1);
    /* Now send the ipc -- call will send the ipc, then block until a reply
     * message is received */
    seL4_Call(SYSCALL_ENDPOINT_SLOT, tag);
    /* Currently SOS does not reply -- so we never come back here */
}

static void test_syscall()
{
    const char * mystr = "Hello Syscall!";
    void* target = (uintptr_t)seL4_GetIPCBuffer() + PAGE_SIZE_4K;
    printf("Address of mystr = %p\n", mystr);
    printf("Address of IPC buff = %p\n", target);
    seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 4);
    seL4_SetMR(0, 555);
    seL4_SetMR(1, strlen(mystr));
    uintptr_t addr = mystr;
    strcpy(target, mystr);
    seL4_Call(SYSCALL_ENDPOINT_SLOT, tag);
}

int main(void)
{
    sosapi_init_syscall_table();

    /* initialise communication */
    ttyout_init();

    puts("TTY test = starting console test!");

    /* start testing timestamp */
    puts("TTY test = starting timestamp test!");
    
    printf("Timestamp: %d\n",(int)time(NULL));
    
    for (int i =0 ; i < 1000* 1000 * 1000 ; i++){
        // busy waiting
    }
    printf("New Timestamp: %d\n",(int)time(NULL));
    
    // do nothing :)
    while(1){}

    int rs;

    // initialize data for large writing
    for(int i=0; i<sizeof(mymem); ++i)
        mymem[i] = 'a' + (i % 26);

    // test write large
    int fh1 = open("console", O_RDWR);
    //printf("fh1 = %d\n", fh1);
    //printf("writing %d bytes\n", sizeof(mymem));
    //rs = write(fh1, mymem, sizeof(mymem));
    //printf("write result = %d\n", rs);
    
    puts("Test read");
    while(1) {
        // write(fh1, "Delaying. Type something @ console.\n", 36);
        // volatile uint64_t a;
        // for(int i=0; i<1000*1000*1000; ++i) { ++a; }

        write(fh1, "Write something: ", 17);
        int rd = read(fh1, mymem, sizeof(mymem));
        printf("Read %d bytes\n", rd);
        mymem[rd] = 0;
        printf("Read from console: %s\n", mymem);
    }

    close(fh1);

    // stop here and busy wait
    puts("Finished testing. Doing nothing :)");


    while(1) {}

    return 0;
}
