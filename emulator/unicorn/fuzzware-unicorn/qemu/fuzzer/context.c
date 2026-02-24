#include "log.h"
#include "context.h"

unsigned long ctx_sensitive = 0;
unsigned long ctx_shadow_hash = 0;
unsigned long ctx_mode = 0;

void fuzzer_init_context(uc_engine *uc, uint32_t sensitive ,uint32_t mode) {
    ctx_sensitive = sensitive;
    ctx_shadow_hash = 0;
    ctx_mode = mode;     
};

void fuzzer_reset_context(uc_engine *uc, int do_clear) {
    if (do_clear && ctx_sensitive){
        ctx_shadow_hash = 0;
    }
};

void* fuzzer_snapshot_context(uc_engine *uc) {
    if (ctx_sensitive == 0) {
        return NULL;
    }

    uint8_t* buff = malloc(sizeof(ctx_shadow_hash) + sizeof(ctx_mode));
    if (!buff) {
        return buff;
    }

    *(unsigned long*)(buff) = ctx_shadow_hash;
    *(unsigned long*)(buff + sizeof(ctx_shadow_hash)) = ctx_mode;

    return buff;
}

void fuzzer_restore_context(uc_engine *uc, void* buffer) {
    uint8_t* buff = buffer;
    if (ctx_sensitive == 0) {
        return;
    }
    

    ctx_shadow_hash = *(unsigned long*)(buff);
    ctx_mode = *(unsigned long*)(buff + sizeof(ctx_shadow_hash));
    
    return;
}
