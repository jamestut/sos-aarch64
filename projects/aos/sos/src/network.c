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
#include "network.h"

#include <autoconf.h>
#include <sos/gen_config.h>
#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <poll.h>

#include <cspace/cspace.h>
#include <clock/timestamp.h>
#include <clock/watchdog.h>

#undef PACKED // picotcp complains as it redefines this macro
#include <pico_stack.h>
#include <pico_device.h>
#include <pico_config.h>
#include <pico_ipv4.h>
#include <pico_socket.h>
#include <pico_nat.h>
#include <pico_icmp4.h>
#include <pico_dns_client.h>
#include <pico_dev_loop.h>
#include <pico_dhcp_client.h>
#include <pico_dhcp_server.h>
#include <pico_ipfilter.h>
#include "pico_bsd_sockets.h"

#include <ethernet/ethernet.h>

#include <sync/bin_sem.h>
#include <sync/condition_var.h>

#include <nfsc/libnfs.h>

#include "vmem_layout.h"
#include "dma.h"
#include "mapping.h"
#include "irq.h"
#include "ut.h"
#include "utils.h"
#include "threads.h"


#ifndef SOS_NFS_DIR
#  ifdef CONFIG_SOS_NFS_DIR
#    define SOS_NFS_DIR CONFIG_SOS_NFS_DIR
#  else
#    define SOS_NFS_DIR ""
#  endif
#endif

#define NETWORK_IRQ (40)
#define WATCHDOG_TIMEOUT 1000

#define IRQ_IDENT_BIT  BIT(31)
#define IRQ_IDENT_MASK MASK(31)

#define DHCP_STATUS_WAIT        0
#define DHCP_STATUS_FINISHED    1
#define DHCP_STATUS_ERR         2 

static struct pico_device pico_dev;
struct nfs_context *nfs = NULL;
static int dhcp_status = DHCP_STATUS_WAIT;
static char nfs_dir_buf[PATH_MAX];
static uint8_t ip_octet;

// used during initialisation only.
// both ut and cap will be freed after finish 
struct {
    bool initialmountsuccess;
} nfs_status = {0};

// for network thread
struct {
    sos_thread_t* thrd;
    // multiple use kernel objects
    // used exclusively by network thread
    seL4_CPtr ntfn;
    seL4_CPtr ep;
    seL4_CPtr reply;
    // hardcoded IRQ handlers
    seL4_IRQHandler watchdog_irqhdl;
    seL4_IRQHandler network_irqhdl;
} netthrd = {0};

static void nfs_mount_cb(int status, struct nfs_context *nfs, void *data, void *private_data);

static void network_handle_irq(seL4_Word badge);

static void network_thread(void*);

static int pico_eth_send(UNUSED struct pico_device *dev, void *input_buf, int len)
{
    if (ethif_send(input_buf, len) != ETHIF_NOERROR) {
        /* If we get an error, just report that we didn't send anything */
        return 0;
    }
    /* Currently assuming that sending always succeeds unless we get an error code.
     * Given how the u-boot driver is structured, this seems to be a safe assumption. */
    return len;
}

static int pico_eth_poll(UNUSED struct pico_device *dev, int loop_score)
{
    while (loop_score > 0) {
        int len;
        int retval = ethif_recv(&len); /* This will internally call 'raw_recv_callback'
                                        * (if a packet is actually available) */
        if (retval == ETHIF_ERROR || len == 0) {
            break;
        }
        loop_score--;
    }

    /* return (original_loop_score - amount_of_packets_received) */
    return loop_score;
}

/* Called by ethernet driver when a frame is received (inside an ethif_recv()) */
void raw_recv_callback(uint8_t *in_packet, int len)
{
    /* Note that in_packet *must* be copied somewhere in this function, as the memory
     * will be re-used by the ethernet driver after this function returns. */
    pico_stack_recv(&pico_dev, in_packet, len);
}

/* This is a bit of a hack - we need a DMA size field in the ethif driver. */
ethif_dma_addr_t ethif_dma_malloc(uint32_t size, uint32_t align)
{
    dma_addr_t addr = sos_dma_malloc(size, align);
    ethif_dma_addr_t eaddr =
    { .paddr = addr.paddr, .vaddr = addr.vaddr, .size = size };
    ZF_LOGD("ethif_dma_malloc -> vaddr: %lx, paddr: %lx\n, sz: %lx",
            eaddr.vaddr, eaddr.paddr, eaddr.size);
    return eaddr;
}

void nfslib_poll()
{
    struct pollfd pfd = {
        .fd = nfs_get_fd(nfs),
        .events = nfs_which_events(nfs)
    };

    /* Poll with zero timeout, so we return immediately */
    int poll_ret = poll(&pfd, 1, 0);

    ZF_LOGF_IF(poll_ret < 0, "poll() failed");

    if (poll_ret == 0) {
        /* Nothing of interest to NFS happened on the IP stack since last
         * time we checked, so don't bother continuing */
        return;
    }

    if (nfs_service(nfs, pfd.revents) < 0) {
        printf("nfs_service failed\n");
    }
}

static void network_tick_internal(void)
{
    pico_bsd_stack_tick();
    nfslib_poll();
}

/* Handler for IRQs from the ethernet MAC */
static int network_irq(
    UNUSED void *data,
    UNUSED seL4_Word irq,
    seL4_IRQHandler irq_handler
)
{
    ethif_irq();
    seL4_IRQHandler_Ack(irq_handler);
    pico_bsd_stack_tick();
    return 0;
}

/* Handler for IRQs from the watchdog timer */
static int network_tick(
    UNUSED void *data,
    UNUSED seL4_Word irq,
    seL4_IRQHandler irq_handler
)
{
    network_tick_internal();
    watchdog_reset();
    seL4_IRQHandler_Ack(irq_handler);
    return 0;
}

void dhcp_callback(void *cli, int code)
{
    if (code != PICO_DHCP_SUCCESS) {
        dhcp_status = DHCP_STATUS_ERR;
        ZF_LOGE("DHCP negociation failed with code %d", code);
        return;
    }
    struct pico_ip4 ipaddr = pico_dhcp_get_address(cli);
    struct pico_ip4 netmask = pico_dhcp_get_netmask(cli);
    struct pico_ip4 gateway = pico_dhcp_get_gateway(cli);

    char ipstr[30];
    /* pico_ipv4_to_string(ipstr, ipaddr.addr); */
    /* ZF_LOGD("[DHCP] ip: %s", ipstr); */
    ip_octet = ((uint8_t *) &ipaddr.addr)[3];
    pico_ipv4_to_string(ipstr, netmask.addr);
    printf("DHCP client: netmask %s\n", ipstr);
    pico_ipv4_to_string(ipstr, gateway.addr);
    printf("DHCP client: gateway %s\n", ipstr);

    dhcp_status = DHCP_STATUS_FINISHED;
}

bool init_irq(seL4_Word irq, bool edge_triggered, seL4_IRQHandler* irqhdl)
{
    int err;
    *irqhdl = cspace_alloc_slot(&cspace);
    if(*irqhdl == seL4_CapNull) {
        ZF_LOGE("Cannot create cspace slot for IRQ");
        return false;
    }
    
    err = cspace_irq_control_get(&cspace, *irqhdl, seL4_CapIRQControl, irq, edge_triggered);
    if(err != seL4_NoError) {
        ZF_LOGE("Error seL4 IRQ trigger: %d", err);
        return false;
    }

    // we'renot going to free this cap later on, so we'll let it leak
    seL4_CPtr badgedntfn = cspace_alloc_slot(&cspace);
    if(badgedntfn == seL4_CapNull) {
        ZF_LOGE("Cannot allocate capability slot");
        return false;
    }

    err = cspace_mint(&cspace, badgedntfn, &cspace, netthrd.ntfn, seL4_AllRights, IRQ_IDENT_BIT | irq);
    if(err != seL4_NoError) {
        ZF_LOGE("Error minting notification: %d", err);
        return false;
    }

    err = seL4_IRQHandler_SetNotification(*irqhdl, badgedntfn);
    if(err != seL4_NoError) {
        ZF_LOGE("Error setting notification for network IRQ: %d", err);
        return false;
    }

    // ack and enable the interrupt!
    seL4_IRQHandler_Ack(*irqhdl);
    return true;
}

void network_init(cspace_t *cspace, void *timer_vaddr, seL4_CPtr irq_ntfn)
{
    int error;
    ZF_LOGI("\nInitialising network...\n\n");

    // setup sync variables so that clients know if we finished mount
    seL4_CPtr mount_ntfn;
    ut_t* mount_ntfn_ut = alloc_retype(&mount_ntfn, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!mount_ntfn_ut, "Failed to allocate notification for NFS mount");
    // set that notif to zero
    seL4_Poll(mount_ntfn, NULL);

    // create kernel objects for network thread
    ZF_LOGF_IF(!alloc_retype(&netthrd.ntfn, seL4_NotificationObject, seL4_NotificationBits),
        "Failed to create notification");
    ZF_LOGF_IF(!alloc_retype(&netthrd.ep, seL4_EndpointObject, seL4_EndpointBits),
        "Failed to create endpoint for network thread");
    ZF_LOGF_IF(!alloc_retype(&netthrd.reply, seL4_ReplyObject, seL4_ReplyBits),
        "Failed to create reply object for network thread");

    /* set up the network device irq */
    ZF_LOGF_IF(!init_irq(NETWORK_IRQ, true, &netthrd.network_irqhdl), 
        "Failed to initialize network IRQ");

    /* set up the network tick irq (watchdog timer) */
    ZF_LOGF_IF(!init_irq(WATCHDOG_IRQ, true, &netthrd.watchdog_irqhdl),
        "Failed to initialize network watchdog IRQ");

    /* Initialise ethernet interface first, because we won't bother initialising
     * picotcp if the interface fails to be brought up */

    /* Map the ethernet MAC MMIO registers into our address space */
    uint64_t eth_base_vaddr =
        (uint64_t)sos_map_device(cspace, ODROIDC2_ETH_PHYS_ADDR, ODROIDC2_ETH_PHYS_SIZE);

    /* Populate DMA operations required by the ethernet driver */
    ethif_dma_ops_t ethif_dma_ops;
    ethif_dma_ops.dma_malloc = &ethif_dma_malloc;
    ethif_dma_ops.dma_phys_to_virt = &sos_dma_phys_to_virt;
    ethif_dma_ops.flush_dcache_range = &sos_dma_cache_clean_invalidate;
    ethif_dma_ops.invalidate_dcache_range = &sos_dma_cache_invalidate;

    /* Try initializing the device.
     *
     * This function will also check what MAC address u-boot programmed into
     * the interface, copy it into mac_addr, and reprogram it into the interface */

    uint8_t mac_addr[6];
    error = ethif_init(eth_base_vaddr, mac_addr, &ethif_dma_ops, &raw_recv_callback);
    ZF_LOGF_IF(error != 0, "Failed to initialise ethernet interface");

    pico_bsd_init();
    pico_stack_init();

    memset(&pico_dev, 0, sizeof(struct pico_device));

    pico_dev.send = pico_eth_send;
    pico_dev.poll = pico_eth_poll;

    pico_dev.mtu = MAXIMUM_TRANSFER_UNIT;

    error = pico_device_init(&pico_dev, "sos picotcp", mac_addr);
    ZF_LOGF_IF(error, "Failed to init picotcp");

    /* Start DHCP negotiation */
    uint32_t dhcp_xid;
    error = pico_dhcp_initiate_negotiation(&pico_dev, dhcp_callback, &dhcp_xid);
    ZF_LOGF_IF(error != 0, "Failed to initialise DHCP negotiation");

    /* handle all interrupts until dhcp negotiation finished
     * this is needed so we can receive and handle dhcp response */
    puts("Handling IRQ for DHCP");
    do {
        seL4_Word badge;
        seL4_Wait(netthrd.ntfn, &badge);
        if(badge & IRQ_IDENT_BIT)
            network_handle_irq(badge & IRQ_IDENT_MASK);
        if (dhcp_status == DHCP_STATUS_ERR) {
            ZF_LOGD("restarting dhcp negotiation");
            error = pico_dhcp_initiate_negotiation(&pico_dev, dhcp_callback, &dhcp_xid);
            ZF_LOGF_IF(error != 0, "Failed to initialise DHCP negotiation");
        }
    } while (dhcp_status != DHCP_STATUS_FINISHED);

    /* Configure a watchdog IRQ for 1 millisecond from now. Whenever the watchdog is reset
     * using watchdog_reset(), we will get another IRQ 1ms later */
    watchdog_init(timer_vaddr, WATCHDOG_TIMEOUT);

    nfs = nfs_init_context();
    ZF_LOGF_IF(nfs == NULL, "Failed to init NFS context");

    nfs_set_debug(nfs, 10);
    sprintf(nfs_dir_buf, "%s-%d-root", SOS_NFS_DIR, ip_octet);
    int ret = nfs_mount_async(nfs, CONFIG_SOS_GATEWAY, nfs_dir_buf, nfs_mount_cb, &mount_ntfn);
    ZF_LOGF_IF(ret != 0, "NFS Mount failed: %s", nfs_get_error(nfs));

    // create network thread.
    netthrd.thrd = spawn(network_thread, NULL, "network_thread", 0, netthrd.ep, 0);
    ZF_LOGF_IF(!netthrd.thrd, "Error creating network thread");
    // bind ntfn to TCB so that the thread can receive IRQ
    error = seL4_TCB_BindNotification(netthrd.thrd->tcb, netthrd.ntfn);
    ZF_LOGF_IF(error, "Failed to bind notification object to TCB");

    // wait until NFS finishes mounting
    puts("Waiting for root NFS to finish mounting ...");
    seL4_Wait(mount_ntfn, NULL);
    
    // cleanup caps that we use to wait NFS to finish mount
    cspace_delete(cspace, mount_ntfn);
    cspace_free_slot(cspace, mount_ntfn);
    ut_free(mount_ntfn_ut);
}

void nfs_mount_cb(int status, UNUSED struct nfs_context *nfs, void *data,
                  UNUSED void *private_data)
{
    if (status < 0) {
        ZF_LOGF("mount/mnt call failed with \"%s\"\n", (char *)data);
    } else {
        printf("Mounted nfs dir %s\n", nfs_dir_buf);
        nfs_status.initialmountsuccess = true;
    }

    // wake up parent
    seL4_Signal(*((seL4_CPtr*)private_data));
}

bool check_nfs_mount_status(void)
{
    return nfs_status.initialmountsuccess;
}

static void network_thread(UNUSED void* data)
{
    for(;;) {
        seL4_Word badge;
        seL4_MessageInfo_t message = seL4_Recv(netthrd.ep, &badge, netthrd.reply);
        if(badge & IRQ_IDENT_BIT) {
            network_handle_irq(badge & IRQ_IDENT_MASK);
        } else {
            // TODO: delegate!
        }
    }
}

static void network_handle_irq(seL4_Word badge)
{
    switch(badge & IRQ_IDENT_MASK) {
        case WATCHDOG_IRQ:
            network_tick(NULL, WATCHDOG_IRQ, netthrd.watchdog_irqhdl);
            break;
        case NETWORK_IRQ:
            network_irq(NULL, NETWORK_IRQ, netthrd.network_irqhdl);
            break;
        default:
            ZF_LOGF("Unknown IRQ");
    }
}

int sos_libnfs_open_async(const char *path, int flags, nfs_cb cb, void *private_data)
{
    return nfs_open_async(nfs, path, flags, cb, private_data);
}

int sos_libnfs_pread_async(struct nfsfh *nfsfh, uint64_t offset, 
    uint64_t count, nfs_cb cb, void *private_data)
{
    return nfs_pread_async(nfs, nfsfh, offset, count, cb, private_data);
}

int sos_libnfs_pwrite_async(struct nfsfh *nfsfh, uint64_t offset, 
    uint64_t count, const void *buf, nfs_cb cb, void *private_data)
{
    return nfs_pwrite_async(nfs, nfsfh, offset, count, buf, cb, private_data);
}

int sos_libnfs_stat_async(const char *path, nfs_cb cb, void *private_data)
{
    return nfs_stat_async(nfs, path, cb, private_data);
}

int sos_libnfs_opendir_async(const char *path, nfs_cb cb, void *private_data)
{
    return nfs_opendir_async(nfs, path, cb, private_data);
}

int sos_libnfs_close_async(struct nfsfh *nfsfh, nfs_cb cb, void *private_data)
{
    return nfs_close_async(nfs, nfsfh, cb, private_data);
}

const char* sos_libnfs_readdir(struct nfsdir *nfsdir, size_t pos)
{
    nfs_seekdir(nfs, nfsdir, pos);
    struct nfsdirent * ent = nfs_readdir(nfs, nfsdir);
    if(!ent)
        return NULL;
    return ent->name;
}

void sos_libnfs_closedir(struct nfsdir *nfsfh)
{
    nfs_closedir(nfs, nfsfh);
}
