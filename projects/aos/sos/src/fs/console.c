#include <utils/zf_log.h>
#include <utils/zf_log_if.h>
#include <serial/serial.h>
#include <sync/bin_sem.h>
#include <sync/condition_var.h>
#include <fcntl.h>
#include <errno.h>
#include <utils/arith.h>

#include "../fileman.h"
#include "../utils.h"
#include "console.h"

#define TMP_BUFF_SZ 4096 // in line with libserial
#define TMP_POS_INC(v) ((v+1) % TMP_BUFF_SZ)

#define MTU 960U
#define MAX_SIZE 0x80000000U

// local variable section
struct serial * serhdl = NULL;

struct {
    // store read data here if no one is doing read now
    // only store the latest TMP_BUFF_SZ if full (old evicted)
    struct {
        char data[TMP_BUFF_SZ];
        uint16_t prod_pos;
        uint16_t cons_pos;
    } tmp;
    
    struct {
        bool active;
        uint8_t* ptr;
        size_t rem;
        bool stop;
    } client;

    // lock for this entire structure
    sync_bin_sem_t lock;
    // to be used by "consumer"
    sync_cv_t cv;
} readbuff;

enum perm {
    PERM_RD = 1,
    PERM_WR = 2
};

ssize_t console_fs_open(UNUSED seL4_Word pid, UNUSED const char* fn, int mode)
{
    // stateless!
    switch(mode) {
        case O_RDONLY:
            return PERM_RD;
        case O_WRONLY:
            return PERM_WR;
        case O_RDWR:
            return PERM_WR | PERM_RD;
        default:
            return 0;
    }
}

void console_fs_close(UNUSED seL4_Word pid, UNUSED ssize_t id) { /* stateless! do nothing! */ }

// platform specific functions
#ifdef CONFIG_PLAT_ODROIDC2
void libserial_handler(struct serial *serial, char c);

void console_fs_init(void)
{
    if(!serhdl) {
        serhdl = serial_init();
        ZF_LOGE_IF(!serhdl, "Failed to initialize libserial.");

        memset(&readbuff, 0, sizeof(readbuff));

        // sync primitives!
        seL4_CPtr ntfn;
        if(!alloc_retype(&ntfn, seL4_NotificationObject, seL4_NotificationBits))
            ZF_LOGF("Cannot create notification object for lock.");
        sync_bin_sem_init(&readbuff.lock, ntfn, 1);
        if(!alloc_retype(&ntfn, seL4_NotificationObject, seL4_NotificationBits))
            ZF_LOGF("Cannot create notification object for CV.");
        sync_cv_init(&readbuff.cv, ntfn);

        // register handler
        serial_register_handler(serhdl, libserial_handler);
    }
}

ssize_t console_fs_read(seL4_Word pid, ssize_t id, void* ptr, UNUSED off_t offset, size_t len)
{
    if(id & PERM_RD) {
        // truncate!
        if(len >= MAX_SIZE)
            len = MAX_SIZE - 1;

        size_t rem = len;
        uint8_t* tgt = ptr;

        sync_bin_sem_wait(&readbuff.lock);

        // copy from temporary buffer first
        bool auxstop = false;
        while(rem && (readbuff.tmp.prod_pos != readbuff.tmp.cons_pos) && !auxstop) {
            if((*(tgt++) = readbuff.tmp.data[readbuff.tmp.cons_pos]) == '\n')
                auxstop = true;
            readbuff.tmp.cons_pos = TMP_POS_INC(readbuff.tmp.cons_pos);
            --rem;
        }

        ssize_t ret;

        // delegate task to interrupt handler if we have remaining job
        if(rem && !auxstop) {
            // wait until it is our turn to write
            while(readbuff.client.active) {
                sync_cv_wait(&readbuff.lock, &readbuff.cv);
            }
            // our turn!
            readbuff.client.active = true;
            readbuff.client.stop = false;
            readbuff.client.rem = rem;
            readbuff.client.ptr = tgt;
            // wait until handler indicate finish
            while(!readbuff.client.stop) {
                sync_cv_wait(&readbuff.lock, &readbuff.cv);
            }
            
            // prepare return value
            ret = len - readbuff.client.rem;
            // indicate that we've finished
            readbuff.client.active = false;
        } else {
            ret = len - rem;
        }

        // leave critical section
        sync_bin_sem_post(&readbuff.lock);

        return ret;
    } else
        // not allowed to read!
        return EBADF * -1;
}

ssize_t console_fs_write(seL4_Word pid, ssize_t id, void* ptr, UNUSED off_t offset, size_t len)
{
    // WARNING! pico TCP might drop some data if it is larger than MTU
    if(id & PERM_WR) {
        size_t wr = 0;
        uint8_t * src = ptr;
        while(wr < len) {
            size_t to_write = MIN(MTU, len - wr);
            ssize_t written = serial_send(serhdl, (char*)src, to_write);
            if(written < 0)
                return EIO * -1;
            wr += written;
            src += written;
        }
        return wr;
    } else
        return EBADF * -1;
}

void libserial_handler(UNUSED struct serial *serial, char c)
{
    sync_bin_sem_wait(&readbuff.lock);
    
    if(readbuff.client.active && !readbuff.client.stop) {
        // write directly to target
        if((*(readbuff.client.ptr++) = c) == '\n')
            readbuff.client.stop = true;
        if(!--readbuff.client.rem)
            readbuff.client.stop = true;
        
        // wake up the consumer if needed!
        if(readbuff.client.stop) {
            sync_cv_signal(&readbuff.cv);
        }
    } else {
        // if not active, we'll write to the temporary buffer
        readbuff.tmp.data[readbuff.tmp.prod_pos] = c;
        uint16_t nxt_prod_pos = TMP_POS_INC(readbuff.tmp.prod_pos);
        
        // enforce FIFO (aka First In First Obliviated!)
        if(nxt_prod_pos == readbuff.tmp.cons_pos) 
            readbuff.tmp.cons_pos = TMP_POS_INC(readbuff.tmp.cons_pos);
        
        readbuff.tmp.prod_pos = nxt_prod_pos;
    }

    sync_bin_sem_post(&readbuff.lock);
}

#endif
