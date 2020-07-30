#include <grp01/bitfield.h>
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <utils/builtin.h>

#define WORD_BITS 64

// slight adaptation from cspace.h
ssize_t bitfield_first_free(size_t words, uint64_t* arr)
{
    /* find the first free word */
    unsigned int i = 0;
    for (; i < words && arr[i] == ULONG_MAX; i++);
    if(i >= words)
        // full!
        return -1;

    size_t bit = i * WORD_BITS;

    /* we want to find the first 0 bit, do this by inverting the value */
    size_t val = ~arr[i];
    /* it's illegal to call CLZL on 0, so check first */
    assert(val != 0);

    if (i < words) {
        bit += (CTZL(val));
    }
    return bit;
}

ssize_t bitfield_first_used(size_t words, uint64_t* arr)
{
    /* find the first used word */
    unsigned int i = 0;
    for (; i < words && arr[i] == 0; i++);
    if(i >= words)
        // all is empty!
        return -1;

    size_t bit = i * WORD_BITS;

    /* we want to find the first 1 bit */
    size_t val = arr[i];
    /* it's illegal to call CLZL on 0, so check first */
    assert(val != 0);

    if (i < words) {
        bit += (CTZL(val));
    }
    return bit;
}
