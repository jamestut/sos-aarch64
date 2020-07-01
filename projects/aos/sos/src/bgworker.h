#pragma once

#include "grp01.h"

#define BACKEND_HANDLER_BADGE (INT_THRD_BADGE_FLAG + 1)

typedef void (*bgworker_callback_fn)(void*);

// initialize the backend thread
void bgworker_init();

bool bgworker_enqueue_callback(bgworker_callback_fn fn, void* args);
