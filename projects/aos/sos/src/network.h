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

#include <sel4/sel4.h>
#include <cspace/cspace.h>
#include <sys/time.h>
#include <nfsc/libnfs.h>

/**
 * Initialises the network stack
 *
 * @param cspace         for creating slots for mappings
 * @param ntfn_irq       badged notification object bound to SOS's endpoint, for ethernet IRQs
 * @param ntfn_tick      badged notification object bound to SOS's endpoint, for network tick IRQs
 * @param timer_vaddr    mapped timer device. network_init will set up a periodic network_tick
 *                       using the SoC's watchdog timer (which is not used by your timer driver
 *                       and has a completely different programming model!)
 */
void network_init(cspace_t *cspace, void *timer_vaddr, seL4_CPtr irq_ntfn);

// NFS related functions
bool check_nfs_mount_status(void);

// call these NFS functions from main thread
int sos_libnfs_open_async(const char *path, int flags, nfs_cb cb, void *private_data);

int sos_libnfs_pread_async(struct nfsfh *nfsfh, uint64_t offset, 
    uint64_t count, nfs_cb cb, void *private_data);

int sos_libnfs_pwrite_async(struct nfsfh *nfsfh, uint64_t offset, 
    uint64_t count, const void *buf, nfs_cb cb, void *private_data);

int sos_libnfs_close_async(struct nfsfh *nfsfh, nfs_cb cb, void *private_data);

int sos_libnfs_stat_async(const char *path, nfs_cb cb, void *private_data);

int sos_libnfs_opendir_async(const char *path, nfs_cb cb, void *private_data);

const char* sos_libnfs_readdir(struct nfsdir *nfsdir, size_t pos);

void sos_libnfs_closedir(struct nfsdir *nfsfh);
