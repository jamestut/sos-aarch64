#pragma once

#include "grp01.h"

typedef void (*bgworker_callback_fn)(void* data);

void bgworker_init();

// create a background thread for a pid
bool bgworker_create(sos_pid_t pid);

void bgworker_destroy(sos_pid_t pid);

bool bgworker_enqueue_callback(sos_pid_t pid, bgworker_callback_fn fn, void* args);
