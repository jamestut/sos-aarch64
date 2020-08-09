#include <grp01/binsearch.h>
#include <stdint.h>

#define ITEM(idx) ((void*)(((uintptr_t)haystack) + ((idx) * elemsz)))

ssize_t binary_search(const void* haystack, const void* needle, size_t elemsz, size_t count, binsearch_comparator_fn comp, bool closest)
{
    if(count == 0)
        return closest ? 0 : -1;

    size_t lo = 0;
    size_t hi = count - 1;
    while(1) {
        size_t mid = (lo+hi) >> 1;
        int rs = comp(needle, ITEM(mid));
        if(rs == 0)
            return mid;
        else if (rs < 0) {
            if(mid == lo)
                return closest ? mid : -1;
            hi = mid - 1;
        } else if (rs > 0) {
            if(mid == hi)
                return closest ? (mid + 1) : -1;
            lo = mid + 1;
        }
    }
}
