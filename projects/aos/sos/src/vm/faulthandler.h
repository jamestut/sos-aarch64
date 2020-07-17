#pragma once

#include <sel4/sel4.h>
#include <grp01/dynaarray.h>

bool vm_fault(seL4_MessageInfo_t* tag, seL4_Word badge);