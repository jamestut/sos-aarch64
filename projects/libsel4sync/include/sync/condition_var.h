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
#include <sel4/sel4.h>
#include <stdbool.h>

typedef struct {
    seL4_CPtr notification;
    volatile int waiters;
    volatile bool broadcasting;
} sync_cv_t;

/* Initialise an unmanaged condition variable
 * @param cv            A condition variable object to be initialised.
 * @param notification  A notification object to use for wake up.
 * @return              0 on success, an error code on failure. */
static inline int sync_cv_init(sync_cv_t *cv, seL4_CPtr notification)
{
    if (cv == NULL) {
        ZF_LOGE("Condition variable passed to sync_cv_init is NULL");
        return -1;
    }

#ifdef CONFIG_DEBUG_BUILD
    /* Check the cap actually is a notification. */
    assert(seL4_DebugCapIdentify(notification) == 6);
#endif

    cv->notification = notification;
    cv->waiters = 0;
    cv->broadcasting = false;
    return 0;
}

/* Wait on a condition variable.
 * This assumes that you already hold the lock and will block until notified
 * by sync_cv_signal or sync_cv_broadcast. It returns once you hold the lock
 * again. Note that a spurious wake up is possible and the condition should
 * always be checked again after sync_cv_wait returns.
 * @param lock          The lock on the monitor.
 * @param cv            The condition variable to wait on.
 * @return              0 on success, an error code on failure. */
static inline int sync_cv_wait(sync_bin_sem_t *lock, sync_cv_t *cv)
{
    if (cv == NULL) {
        ZF_LOGE("Condition variable passed to sync_cv_wait is NULL");
        return -1;
    }

    /* Increment waiters count and release the lock */
    cv->waiters++;
    cv->broadcasting = false;
    int error = sync_bin_sem_post(lock);
    if (error != 0) {
        return error;
    }

    /* Wait to be notified */
    seL4_Wait(cv->notification, NULL);

    /* Reacquire the lock */
    error = sync_bin_sem_wait(lock);
    if (error != 0) {
        return error;
    }

    /* Wake up and decrement waiters count */
    cv->waiters--;

    /* Handle the case where a broadcast is ongoing */
    if (cv->broadcasting) {
        if (cv->waiters > 0) {
            /* Signal the next thread and continue */
            seL4_Signal(cv->notification);
        } else {
            /* This is the last thread, so stop broadcasting */
            cv->broadcasting = false;
        }
    }

    return 0;
}

/* Signal a condition variable.
 * This assumes that you hold the lock and notifies one waiter
 * @param cv            The condition variable to signal.
 * @return              0 on success, an error code on failure. */
static inline int sync_cv_signal(sync_cv_t *cv)
{
    if (cv == NULL) {
        ZF_LOGE("Condition variable passed to sync_cv_signal is NULL");
        return -1;
    }
    if (cv->waiters > 0) {
        seL4_Signal(cv->notification);
    }

    return 0;
}

/* Broadcast to a condition variable.
 * This assumes that you hold the lock and notifies all waiters
 * @param cv            The condition variable to broadcast to.
 * @return              0 on success, an error code on failure. */
static inline int sync_cv_broadcast(sync_cv_t *cv)
{
    if (cv == NULL) {
        ZF_LOGE("Condition variable passed to sync_cv_broadcast is NULL");
        return -1;
    }

    if (cv->waiters > 0) {
        cv->broadcasting = true;
        seL4_Signal(cv->notification);
    }

    return 0;
}

/* Broadcast to a condition variable and release the lock.
 * This function is useful in situations where the scheduler might wake up a
 * waiter immediately after a signal (i.e. if the broadcaster is lower priority).
 * For performance reasons it is useful to release the lock prior to signalling
 * the condition variable in this case.
 * @param cv            The condition variable to broadcast to.
 * @return              0 on success, an error code on failure. */
static inline int sync_cv_broadcast_release(sync_bin_sem_t *lock, sync_cv_t *cv)
{
    if (cv == NULL) {
        ZF_LOGE("Condition variable passed to sync_cv_broadcast_release is NULL");
        return -1;
    }

    if (cv->waiters > 0) {
        cv->broadcasting = true;

        int error = sync_bin_sem_post(lock);
        if (error != 0) {
            return error;
        }

        seL4_Signal(cv->notification);
        return 0;
    } else {
        return sync_bin_sem_post(lock);
    }
}
