// we'll be using malloc/free in this implementation

#include <grp01/dynaarray.h>
#include <string.h>
#include <stdlib.h>
#include <utils/arith.h>

void dynarray_init(struct dynarray_state* state, uint32_t itemsz)
{
    memset(state, 0, sizeof(struct dynarray_state));
    state->itemsz = itemsz;
}

bool dynarray_resize(struct dynarray_state* state, uint32_t target)
{
    if(target <= state->capacity)
        return true;

    // find nearest 2 power
    if(IS_POWER_OF_2(target))
        --target;
    target = NEXT_POWER_OF_2(target);
    
    // try allocate
    // we assume here that the realloc won't touch the old pointer if it fails
    void* newptr;
    if(state->data)
        newptr = realloc(state->data, state->itemsz * target);
    else
        newptr = malloc(state->itemsz * target);
    if(!newptr)
        return false;
    
    state->data = newptr;
    state->capacity = target;

    return true;
}

void dynarray_destroy(struct dynarray_state* state)
{
    if(state->data)
        free(state->data);
    memset(state, 0, sizeof(struct dynarray_state));
}
