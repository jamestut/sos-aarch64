#pragma once

#define SOS_SYSCALL_UNIMPLEMENTED 0x7FFFFFFF

#define SOS_SYSCALL_READ          0
#define SOS_SYSCALL_WRITE         1
#define SOS_SYSCALL_OPEN          2
#define SOS_SYSCALL_CLOSE         3
#define SOS_SYSCALL_STAT          4
#define SOS_SYSCALL_MMAP          9
#define SOS_SYSCALL_MUNMAP       11
#define SOS_SYSCALL_BRK          12
#define SOS_SYSCALL_USLEEP       35 // equivalent to linux's nanosleep
#define SOS_SYSCALL_TIMESTAMP   201 // linux's time 
#define SOS_SYSCALL_GROW_STACK 1001
#define SOS_SYSCALL_OPENDIR    1781
#define SOS_SYSCALL_DIRREAD    1782
