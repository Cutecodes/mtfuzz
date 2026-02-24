#ifndef FUZZ_H
#define FUZZ_H

#include "unicorn/unicorn.h"


#define DEBUG_TIMER_TIMEOUT 100

typedef void (*exit_hook_t)(int, int);

extern int do_print_exit_info;
bool get_fuzz(uc_engine *uc, uint64_t addr, int size, uint8_t * val);
void do_exit(uc_engine *uc, uc_err err);
void force_crash(uc_engine *uc, uc_err error);
void add_exit_hook(exit_hook_t hook);
#endif
