#ifndef MMIO_H
#define MMIO_H

#include "unicorn/unicorn.h"

#define MAX_MMIO_CALLBACKS 4096
#define MAX_IGNORED_ADDRESSES 4096
#define MMIO_HOOK_PC_ALL_ACCESS_SITES (0xffffffffuL)

extern uint32_t num_mmio_regions;
extern uint64_t *mmio_region_starts;
extern uint64_t *mmio_region_ends;

struct mmio_callback
{
    uint64_t start;
    uint64_t end;
    uint32_t pc;
    void *user_data;
    uc_cb_hookmem_t callback;
};

typedef void (*mmio_region_added_cb_t)(uint64_t, uint64_t);
uc_err add_mmio_region(uc_engine *uc, uint64_t begin, uint64_t end);
uc_err add_mmio_subregion_handler(uc_engine *uc, uc_cb_hookmem_t callback, uint64_t start, uint64_t end, uint32_t pc, void *user_data);
uc_err set_ignored_mmio_addresses(uc_engine *uc, uint64_t *addresses, uint32_t *pcs, int num_addresses);
uc_err add_ignored_mmio_addresses(uc_engine *uc, uint64_t *addresses, uint32_t *pcs, int num_addresses);


void *mmio_models_take_snapshot(uc_engine *uc);
void mmio_models_restore_snapshot(uc_engine *uc, void *snapshot);
void mmio_models_discard_snapshot(uc_engine *uc, void *snapshot);

#endif
