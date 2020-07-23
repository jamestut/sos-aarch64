#include <utils/zf_log_if.h>
#include <sel4/sel4.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <utils/arith.h>
#include <limits.h>
#include "../mapping.h"
#include "../utils.h"

#include "console.h"

#ifndef CONFIG_PLAT_ODROIDC2

// from dts, but hardcoded
#define UART_PADDR 0x9000000

// presumably specs from primecell
#define PL011_UARTFR_TXFF         BIT(5)
#define PL011_UARTFR_RXFE         BIT(4)
#define UARTFR 0x018
#define UARTDR 0x000

volatile uintptr_t uart_reg_vaddr;

#define UART_REG(x) ((volatile uint32_t *)(uart_reg_vaddr + (x)))

void console_fs_init(void)
{
    uart_reg_vaddr = sos_map_device(&cspace, PAGE_ALIGN_4K(UART_PADDR), PAGE_SIZE_4K);
    ZF_LOGF_IF(uart_reg_vaddr == NULL, "Failed to map PL011 UART");
    ZF_LOGI("PL011 UART console initialized.");
}

static inline void uart_putchar(unsigned char c) {
    // wait until UART buffer is emptied
    while ((*UART_REG(UARTFR) & PL011_UARTFR_TXFF) != 0);
    // print!
    *UART_REG(UARTDR) = c;
}

static inline unsigned char uart_getchar(void) {
    while ((*UART_REG(UARTFR) & PL011_UARTFR_RXFE) != 0);
    return *UART_REG(UARTDR);
}

ssize_t console_fs_read(seL4_CPtr ep, ssize_t id, void* ptr, off_t offset, size_t len)
{
    char* target = ptr;
    if(len > LLONG_MAX)
        len = LLONG_MAX;
    for(ssize_t i = 0; i < len; ++i) {
        switch(target[i] = uart_getchar()) {
            case '\r':
                target[i] = '\n';
                uart_putchar('\n');
                return i + 1;
            case 127: // backspace
                if(i) {
                    uart_putchar('\b');
                    uart_putchar(' ');
                    uart_putchar('\b');
                    --i;
                }
                --i;
                break;
            case 27: // disallow escape sequences
                uart_getchar();
                --i;
                break;
            default:
                // echo, so that the behaviour is inline with AOS odroid serial
                uart_putchar(target[i]);
                break;
        }
    }
    return len;
}



ssize_t console_fs_write(seL4_CPtr ep, ssize_t id, void* ptr, off_t offset, size_t len)
{
    for(size_t i = 0; i < len; ++i)
        uart_putchar(*((unsigned char*)((uintptr_t)ptr + i)));
}

#endif