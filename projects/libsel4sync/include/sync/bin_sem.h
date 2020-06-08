/*
 * Copyright 2017, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DATA61_BSD)
 */

#pragma once

#include <autoconf.h>
#include <assert.h>
#include <sel4/sel4.h>
#include <stddef.h>
#include <sync/bin_sem_bare.h>

typedef struct {
    seL4_CPtr notification;
    volatile int value;
} sync_bin_sem_t;

/* Initialise an unmanaged binary semaphore with a notification object
 * @param sem           A semaphore object to be initialised.
 * @param notification  A notification object to use for the lock.
 * @param value         The initial value for the semaphore. Must be 0 or 1.
 * @return              0 on success, an error code on failure. */
static inline int sync_bin_sem_init(sync_bin_sem_t *sem, seL4_CPtr notification, int value) {
    if (sem == NULL) {
        ZF_LOGE("Semaphore passed to sync_bin_sem_init was NULL");
        return -1;
    }

    if (value != 0 && value != 1) {
        ZF_LOGE("Binary semaphore initial value neither 0 nor 1");
        return -1;
    }

#ifdef CONFIG_DEBUG_BUILD
    /* Check the cap actually is a notification. */
    assert(seL4_DebugCapIdentify(notification) == 6);
#endif

    sem->notification = notification;
    sem->value = value;
    return 0;
}

/* Wait on a binary semaphore
 * @param sem           An initialised semaphore to acquire.
 * @return              0 on success, an error code on failure. */
static inline int sync_bin_sem_wait(sync_bin_sem_t *sem) {
    if (sem == NULL) {
        ZF_LOGE("Semaphore passed to sync_bin_sem_wait was NULL");
        return -1;
    }
    return sync_bin_sem_bare_wait(sem->notification, &sem->value);
}

/* Signal a binary semaphore
 * @param sem           An initialised semaphore to release.
 * @return              0 on success, an error code on failure. */
static inline int sync_bin_sem_post(sync_bin_sem_t *sem) {
    if (sem == NULL) {
        ZF_LOGE("Semaphore passed to sync_bin_sem_post was NULL");
        return -1;
    }
    return sync_bin_sem_bare_post(sem->notification, &sem->value);
}

