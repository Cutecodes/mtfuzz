#ifndef FUZZER_H
#define FUZZER_H

#include "types.h"
#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)


extern 

void init_count_class16(void);
#ifdef WORD_SIZE_64
void classify_counts(u64* mem);
#else
void classify_counts(u32* mem);
#endif

void setup_signal_handlers(void);
void setup_dirs_fds(void);
#endif
