#pragma once

#include "grp01.h"

typedef void (*bgworker_callback_fn)(seL4_CPtr delegate_ep, void* data);

// initialize the backend thread
void bgworker_init();

bool bgworker_enqueue_callback(bgworker_callback_fn fn, void* args);
