#pragma once

#include "grp01.h"

typedef void (*bgworker_callback_fn)(void* data);

void bgworker_init();

// create a background thread for a pid
void bgworker_create(seL4_Word pid);

void bgworker_destroy(seL4_Word pid);

bool bgworker_enqueue_callback(seL4_Word pid, bgworker_callback_fn fn, void* args);
