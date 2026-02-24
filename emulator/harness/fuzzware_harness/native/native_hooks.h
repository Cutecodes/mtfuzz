#ifndef NATIVE_HOOKS_H
#define NATIVE_HOOKS_H

#include "unicorn/unicorn.h"

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

uc_err add_unmapped_mem_hook(uc_engine *uc);
uc_err add_debug_hooks(uc_engine *uc);

uc_err remove_function_handler_hook_address(uc_engine *uc, uint64_t address);
uc_err register_cond_py_handler_hook(uc_engine *uc, uc_cb_hookcode_t py_callback, uint64_t *addrs, int num_addrs, void *user_data);

#endif
