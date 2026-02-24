#ifndef NATIVE_UTIL_H
#define NATIVE_UTIL_H

#include <unistd.h>
#include <unicorn/unicorn.h>

#define min(a, b) (a < b ? a : b)

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

#endif
