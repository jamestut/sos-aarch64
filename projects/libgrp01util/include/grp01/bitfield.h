#pragma once

#include <stdint.h>
#include <sys/types.h>

ssize_t bitfield_first_free(size_t words, uint64_t* arr);