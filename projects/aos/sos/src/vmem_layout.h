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

// the largest vmem allowed in AArch64 (ARMv8.0)
#define VMEM_TOP             (0x1000000000000)

/* Constants for the layout of the SOS address space */

/* Address where memory used for DMA starts getting mapped.
 * Do not use the address range between SOS_DMA_VSTART and SOS_DMA_VEND */
#define SOS_DMA_SIZE_BITS    (seL4_LargePageBits)

// scratch vaddr for SOS is ideally the topmost
#define SOS_SCRATCH          (0x9000000000)
#define SOS_DEVICE_START     (0xB0000000)
#define SOS_STACK            (0xC0000000)
#define SOS_IPC_BUFFER       (0xD0000000)
#define SOS_STACK_PAGES      100
#define SOS_UT_TABLE         (0x8000000000)
#define SOS_FRAME_TABLE      (0x8100000000)
#define SOS_FRAME_CAP_TABLE  (0x8200000000)
#define SOS_FRAME_PF_BITMAP  (0x8300000000)
#define SOS_FRAME_DATA       (0x8400000000)
#define SOS_FAKE_FS          (0x8800000000)

/* Constants for how SOS will layout the address space of any processes it loads up */
#define PROCESS_STACK_TOP   (0x8F00000000)
#define PROCESS_STACK_MAX_PAGES (0xF00000)
#define PROCESS_STACK_MIN_PAGES (4)
#define PROCESS_IPC_BUFFER  (0xA0000000)
#define PROCESS_VMEM_START  (0xC0000000)

#define PROCESS_HEAP        (0x100000000)
#define PROCESS_HEAP_SIZE   (0x7000000000)
// bottommost of MMAP region
#define PROCESS_MMAP        (0x9000000000)
