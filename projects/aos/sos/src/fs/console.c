#include <utils/zf_log.h>
#include <utils/zf_log_if.h>
#include <serial/serial.h>
#include <sync/bin_sem.h>
#include <sync/condition_var.h>
#include <fcntl.h>
#include <errno.h>

#include "../fileman.h"
#include "../utils.h"
#include "console.h"

#define CIRC_BUFF_SZ 128

#define INC_POS(v) ((v+1) % CIRC_BUFF_SZ)
#define MAX_SIZE 0x80000000U

// local variable section
struct serial * serhdl = NULL;

struct {
    // empty = prod == cons
    // full  = prod == cons - 1
    uint16_t prod_pos;
    uint16_t cons_pos;
    char data[CIRC_BUFF_SZ];
    sync_bin_sem_t lock;
    sync_cv_t cv;
} readbuff;

enum perm {
    PERM_RD = 1,
    PERM_WR = 2
};

int console_fs_open(UNUSED const char* fn, int mode)
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

void console_fs_close(UNUSED int id) { /* stateless! do nothing! */ }

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

int32_t console_fs_read(int id, void* ptr, uint32_t len)
{
    if(id & PERM_RD) {
        // truncate!
        if(len >= MAX_SIZE)
            len = MAX_SIZE - 1;

        int32_t read = 0;
        char * target = ptr;
        bool auxstop = false; //only for newline for now

        while((read < (int32_t)len) && !auxstop) {
            sync_bin_sem_wait(&readbuff.lock);
            // wait until we got something in buffer
            while(readbuff.cons_pos == readbuff.prod_pos) {
                sync_cv_wait(&readbuff.lock, &readbuff.cv);
            }
            // copy to buffer until we get a newline
            while((readbuff.cons_pos != readbuff.prod_pos) && (read < (int32_t)len)) {
                if((target[read++] = readbuff.data[readbuff.cons_pos]) == '\n') {
                    auxstop = true;
                    break;
                }
                readbuff.cons_pos = INC_POS(readbuff.cons_pos);
            }
            sync_bin_sem_post(&readbuff.lock);
        }
        return read;
    } else
        // not allowed to read!
        return EBADF * -1;
}

int32_t console_fs_write(int id, void* ptr, uint32_t len)
{
    if(id & PERM_WR) 
        return serial_send(serhdl, ptr, len);
    else
        return EBADF * -1;
}

void libserial_handler(UNUSED struct serial *serial, char c)
{
    // producer!
    sync_bin_sem_wait(&readbuff.lock);
    // check if full. if the buffer is full, we will drop the input :(
    if(INC_POS(readbuff.prod_pos) != readbuff.cons_pos) {
        readbuff.data[readbuff.prod_pos] = c;
        readbuff.prod_pos = INC_POS(readbuff.prod_pos);
        sync_cv_signal(&readbuff.cv);
    }
    sync_bin_sem_post(&readbuff.lock);
}

#endif
