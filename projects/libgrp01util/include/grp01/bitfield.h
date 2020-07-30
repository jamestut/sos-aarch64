#pragma once

#include <stdint.h>
#include <sys/types.h>

// bitmap represented as pointer to uint64_t
#define GET_BMP(arr, idx) (((arr)[(idx)/64] & (1ULL << ((idx)%64ULL))) && true)
#define TOGGLE_BMP(arr, idx) ((arr)[(idx)/64] ^= (1ULL << ((idx)%64ULL)))

ssize_t bitfield_first_free(size_t words, uint64_t* arr);

ssize_t bitfield_first_used(size_t words, uint64_t* arr);
