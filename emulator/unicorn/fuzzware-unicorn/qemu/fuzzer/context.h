#ifndef AFL_QEMU_CONTEXT_H
#define AFL_QEMU_CONTEXT_H

#include "uc_priv.h"

extern unsigned long ctx_sensitive;
extern unsigned long ctx_shadow_hash;
extern unsigned long ctx_mode;

void fuzzer_init_context(uc_engine *uc, uint32_t sensitive ,uint32_t mode);
void fuzzer_reset_context(uc_engine *uc, int do_clear);
void* fuzzer_snapshot_context(uc_engine *uc);
void fuzzer_restore_context(uc_engine *uc, void* buff);

#endif
