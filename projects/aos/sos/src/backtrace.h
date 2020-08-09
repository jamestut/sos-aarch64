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
#pragma once

#include <stdio.h>
#include "sys/execinfo.h"

#define MAX_BACKTRACE_DEPTH 20

static inline void print_backtrace(void)
{
    void *array[10] = {NULL};
    int size = 0;

    size = backtrace(array, 10);
    if (size) {
        printf("Backtracing stack PCs:  \n");
        for (int i = 0; i < size; i++) {
            printf("%p\n", array[i]);
        }
    }
}

// more reliable backtracing!
static inline void print_backtrace_2(void)
{
    puts("Backtracing stack PCs:");
    void *pcs[MAX_BACKTRACE_DEPTH] = {NULL};
    for(int pcctr = 1; pcctr <= MAX_BACKTRACE_DEPTH; ++pcctr) {
        if(backtrace(pcs, pcctr)) {
            if(pcs[pcctr-1]) 
                printf("%p\n", pcs[pcctr-1]);
            else 
                break;
        } else 
            break;
    }
    // if this ever reached!
    puts("Backtrace finished.");
}
