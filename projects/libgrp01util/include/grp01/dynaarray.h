#pragma once

#include <stdbool.h>
#include <stdint.h>

struct dynarray_state {
    uint32_t capacity;
    uint32_t used; // populated by user! we won't judge!
    uint32_t itemsz;
    void* data;
};

typedef struct dynarray_state dynarray_t;

// initialize the structure with zero data.
void dynarray_init(struct dynarray_state* state, uint32_t itemsz);

// resizes the data field in the state object.
// if reallocation failed, old data is guaranteed to be valid.
// if reallocation happens, pointer to data may change.
bool dynarray_resize(struct dynarray_state* state, uint32_t target);

void dynarray_destroy(struct dynarray_state* state);
