#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

// must return negative if a < b, 0 if a == b, or positive if a > b
// a will be always used for "needle" in binary_search function, whereas
// b will be used for passing the data to be compared in the sorted array.
typedef int (*binsearch_comparator_fn)(const void* a, const void* b);

// @param haystack = sorted array to find needle of
//        needle   = object to be found
//        elemsz   = sizeof individual elements in haystack
//        count    = total number of elements in haystack
//        comp     = comparator function to compare between 2 needles
//        closest  = if true and no element matches, returns the index of the element as if the element is there.
// @return index of the element if found, or -1 if not found and closest is false.
ssize_t binary_search(const void* haystack, const void* needle, size_t elemsz, size_t count, binsearch_comparator_fn comp, bool closest);
