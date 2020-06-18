#pragma once

#define SOS_SYSCALL_READ  0
#define SOS_SYSCALL_WRITE 1
#define SOS_SYSCALL_OPEN  2
#define SOS_SYSCALL_CLOSE 3
#define SOS_SYSCALL_USLEEP 35 // equivalent to linux's nanosleep
#define SOS_SYSCALL_TIMESTAMP 201 // linux's time 
