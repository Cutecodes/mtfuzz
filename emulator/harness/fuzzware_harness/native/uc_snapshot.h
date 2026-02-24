#ifndef UC_SNAPSHOT_H
#define UC_SNAPSHOT_H

#include "unicorn/unicorn.h"
#include "mmio.h"


#define PAGE_SIZE 0x1000
#define MAX_IGNORED_STATE_RESTORE_MEM_ADDRESSES 4096

extern uint32_t num_ignored_state_restore_mem_addresses;
extern uint64_t ignored_state_restore_mem_addresses[MAX_IGNORED_STATE_RESTORE_MEM_ADDRESSES];

struct NativeHooksState {
    uc_hook on_demand_pages_handle;
    uint32_t curr_exit_at_hit_num;
    uc_context *uc_saved_context;
    uint32_t num_orig_regions;
    uc_mem_region *orig_regions;
    uint32_t num_content_regions;
    uint64_t *content_sizes;
    uint64_t *content_guest_addrs;
    uint8_t **contents_ptrs;
    uint32_t num_nullregions;
    uint64_t *nullregion_sizes;
    uint64_t *nullregion_starts;
    uint32_t num_restore_content_regions;
    uint64_t *restore_content_sizes;
    uint64_t *restore_content_guest_addrs;
    uint8_t **restore_contents_ptrs;
    uint32_t num_restore_nullregions;
    uint64_t *restore_nullregion_sizes;
    uint64_t *restore_nullregion_starts;
};

extern struct NativeHooksState native_hooks_state;

void init_uc_state_snapshotting(uc_engine *uc);
uc_err set_ignored_state_restore_addresses(uint64_t *addresses, uint32_t num_addresses);
uc_err add_ignored_state_restore_addresses(uint64_t *addresses, uint32_t num_addresses);
#endif
