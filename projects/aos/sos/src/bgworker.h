#pragma once

#define BACKEND_HANDLER_BADGE (10)

typedef void (*bgworker_callback_fn)(void*);

// initialize the backend thread
void bgworker_init();

bool bgworker_enqueue_callback(bgworker_callback_fn fn, void* args);
