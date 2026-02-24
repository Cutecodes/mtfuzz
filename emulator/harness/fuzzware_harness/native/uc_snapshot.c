#include "uc_snapshot.h"
#include "state_snapshotting.h"
#include <string.h>
#include <assert.h>

// 0. Constants

uint32_t num_ignored_state_restore_mem_addresses = 0;
uint64_t ignored_state_restore_mem_addresses[MAX_IGNORED_STATE_RESTORE_MEM_ADDRESSES];

// 3. Dynamic State (required for state restore)
struct NativeHooksState native_hooks_state = {
    .curr_exit_at_hit_num = 0
};

uc_err set_ignored_state_restore_addresses(uint64_t *addresses, uint32_t num_addresses) {
    assert(sizeof(*addresses) == sizeof(*ignored_state_restore_mem_addresses));

    if(num_addresses <= MAX_IGNORED_STATE_RESTORE_MEM_ADDRESSES) {
        #ifdef DEBUG
        for(int i = 0; i < num_addresses; ++i) {
            printf("Registering passthrough address: %lx\n", addresses[i]);
        }
        #endif
        memcpy(ignored_state_restore_mem_addresses, addresses, num_addresses * sizeof(*ignored_state_restore_mem_addresses));
        num_ignored_state_restore_mem_addresses = num_addresses;
        return UC_ERR_OK;
    } else {
        printf("Too many ignored addresses to be registered");
        return UC_ERR_EXCEPTION;
    }

}

uc_err add_ignored_state_restore_addresses(uint64_t *addresses, uint32_t num_addresses) {
    assert(sizeof(*addresses) == sizeof(*ignored_state_restore_mem_addresses));

    if(num_addresses + num_ignored_state_restore_mem_addresses <= MAX_IGNORED_STATE_RESTORE_MEM_ADDRESSES) {
        #ifdef DEBUG
        for(int i = 0; i < num_addresses; ++i) {
            printf("Registering passthrough address: %lx\n", addresses[i]);
        }
        #endif
        memcpy(ignored_state_restore_mem_addresses + num_ignored_state_restore_mem_addresses, addresses, num_addresses * sizeof(*ignored_state_restore_mem_addresses));
        num_ignored_state_restore_mem_addresses += num_addresses;
        return UC_ERR_OK;
    } else {
        printf("Too many ignored addresses to be registered");
        return UC_ERR_EXCEPTION;
    }

}

void add_staterestore_region(struct NativeHooksState * result, uint8_t *contents, uint64_t guest_addr, int cursor, uint64_t region_size, int prev_is_nullpage) {
    #ifdef DEBUG_STATE_RESTORE
    printf("Adding %s region at 0x%08lx with size 0x%lx\n", prev_is_nullpage ? "null" : "content", guest_addr, region_size);
    #endif

    if(prev_is_nullpage) {
        // only registering null region
        ++result->num_nullregions;
        result->nullregion_sizes = realloc(result->nullregion_sizes, result->num_nullregions*sizeof(*result->nullregion_sizes));
        result->nullregion_starts = realloc(result->nullregion_starts, result->num_nullregions*sizeof(*result->nullregion_starts));
        result->nullregion_sizes[result->num_nullregions-1] = region_size;
        result->nullregion_starts[result->num_nullregions-1] = guest_addr;
    } else {
        // need to register actual contents region
        ++result->num_content_regions;
        result->content_sizes = realloc(result->content_sizes, result->num_content_regions * sizeof(*result->content_sizes));
        result->content_guest_addrs = realloc(result->content_guest_addrs, result->num_content_regions * sizeof(*result->content_guest_addrs));
        result->contents_ptrs = realloc(result->contents_ptrs, result->num_content_regions * sizeof(*result->contents_ptrs));
        result->content_sizes[result->num_content_regions-1] = region_size;
        result->content_guest_addrs[result->num_content_regions-1] = guest_addr;
        result->contents_ptrs[result->num_content_regions-1] = malloc(region_size);
        memcpy(result->contents_ptrs[result->num_content_regions-1], contents, region_size);
    }
}


void *native_hooks_take_snapshot(uc_engine *uc) {
    size_t size = sizeof(native_hooks_state);
    uint32_t permissions;
    uint32_t num_regions;

    uc_mem_region *regions;
    // Set up all null pointers in initial state
    struct NativeHooksState *result = calloc(1, size);
    result->curr_exit_at_hit_num = native_hooks_state.curr_exit_at_hit_num;

    // memcpy(result, native_hooks_state.curr_exit_at_hit_num, size);
    uc_context_alloc(uc, &result->uc_saved_context);
    uc_context_save(uc, result->uc_saved_context);

    uc_mem_regions(uc, &regions, &num_regions);
    result->num_orig_regions = num_regions;
    result->orig_regions = regions;

    result->num_nullregions = result->num_content_regions = 0;
    result->nullregion_starts = result->nullregion_sizes = result->content_guest_addrs = result->content_sizes = NULL;
    result->contents_ptrs = NULL;

    // Copy all memory contents of writeable regions
    for(int i=0; i < num_regions; ++i) {
        size = regions[i].end - regions[i].begin + 1;
        permissions = regions[i].perms;

        // Only writeable regions get restored
        if(!(permissions & UC_PROT_WRITE)) {
            size = 0;
        }

        // Do not restore MMIO-based regions
        #ifdef DEBUG_STATE_RESTORE
        printf("[STATE SNAPSHOTTING] Checking mapped address 0x%lx\n", regions[i].begin); fflush(stdout);
        #endif
        for(int j=0; size && j < num_mmio_regions; ++j) {
            #ifdef DEBUG_STATE_RESTORE
            printf("[STATE SNAPSHOTTING] Comparing against MMIO address 0x%lx\n", mmio_region_starts[j]); fflush(stdout);
            #endif

            if(regions[i].begin == mmio_region_starts[j]) {
                #ifdef DEBUG_STATE_RESTORE
                printf("[STATE SNAPSHOTTING] Ignoring address 0x%lx\n", mmio_region_starts[j]); fflush(stdout);
                #endif

                size = 0;
            }
        }

        for(int j=0; size && j < num_ignored_state_restore_mem_addresses; ++j) {
            #ifdef DEBUG_STATE_RESTORE
            printf("[STATE SNAPSHOTTING] Comparing against ignored state restore address 0x%lx\n", ignored_state_restore_mem_addresses[j]); fflush(stdout);
            #endif

            if(regions[i].begin == ignored_state_restore_mem_addresses[j]) {
                #ifdef DEBUG_STATE_RESTORE
                printf("[STATE SNAPSHOTTING] Ignoring address 0x%lx\n", ignored_state_restore_mem_addresses[j]); fflush(stdout);
                #endif

                size = 0;
                break;
            }
        }

        if(size) {
            int k;
            int num_adjacent_regions = 1;
            int cursor = 0;
            int is_nullpage = -1, prev_is_nullpage = -1;
            uint8_t *contents = malloc(size);
            uc_mem_read(uc, regions[i].begin, contents, size);

            for(cursor = 0; cursor < size; cursor += PAGE_SIZE) {
                is_nullpage = 1;
                for(k=0; k < PAGE_SIZE; ++k) {
                    if(contents[cursor+k] != 0) {
                        is_nullpage = 0;
                        break;
                    }
                }

                #ifdef DEBUG_STATE_RESTORE
                if(is_nullpage) {
                    printf("nullpage at 0x%08lx\n", regions[i].begin+cursor);
                } else {
                    printf("content page at 0x%08lx\n", regions[i].begin+cursor);
                }
                #endif

                if(prev_is_nullpage != -1) {
                    if(prev_is_nullpage == is_nullpage) {
                        ++num_adjacent_regions;
                    } else {
                        uint64_t region_size = num_adjacent_regions * PAGE_SIZE;
                        uint64_t guest_addr = regions[i].begin + cursor - region_size;
                        add_staterestore_region(result, contents + cursor - region_size, guest_addr, cursor, region_size, prev_is_nullpage);

                        num_adjacent_regions = 1;
                    }
                }
                prev_is_nullpage = is_nullpage;
            }
            uint64_t region_size = num_adjacent_regions * PAGE_SIZE;
            uint64_t guest_addr = regions[i].begin + cursor - region_size;
            add_staterestore_region(result, contents + cursor - region_size, guest_addr, cursor, region_size, prev_is_nullpage);
            free(contents);

        }
    }

    // Setup on-demand memory restore ranges
    result->num_restore_content_regions = 0;
    result->num_restore_nullregions = 0;

    return result;
}

void native_hooks_restore_snapshot(uc_engine *uc, void *snapshot) {
    struct NativeHooksState *snapshot_state = (struct NativeHooksState *) snapshot;

    uc_context_restore(uc, snapshot_state->uc_saved_context);
    native_hooks_state.curr_exit_at_hit_num = snapshot_state->curr_exit_at_hit_num;

    // memory restore
    for(int i=0; i < snapshot_state->num_content_regions; ++i) {
        #ifdef DEBUG_STATE_RESTORE
        printf("[] restoring 0x%lx bytes to 0x%lx\n", snapshot_state->content_sizes[i], snapshot_state->content_guest_addrs[i]);
        fflush(stdout);
        #endif
        uc_mem_write(uc, snapshot_state->content_guest_addrs[i], snapshot_state->contents_ptrs[i], snapshot_state->content_sizes[i]);
    }

    // nullpages
    for(int i=0; i < snapshot_state->num_nullregions; ++i) {
        #ifdef DEBUG_STATE_RESTORE
        printf("[] memsetting 0x%lx bytes at 0x%lx\n", snapshot_state->nullregion_starts[i], snapshot_state->nullregion_sizes[i]);
        #endif     
        uc_mem_set(uc, snapshot_state->nullregion_starts[i], 0, snapshot_state->nullregion_sizes[i]);
    }
}

void native_hooks_discard_snapshot(uc_engine *uc, void *snapshot) {
    struct NativeHooksState *snapshot_state = (struct NativeHooksState *) snapshot;
    uc_free(snapshot_state->uc_saved_context);

    for(int i=0; i < snapshot_state->num_content_regions; ++i) {
        free(snapshot_state->contents_ptrs[i]);
    }
    
    uc_free(snapshot_state->orig_regions);

    free(snapshot);
}

void init_uc_state_snapshotting(uc_engine *uc) {
    subscribe_state_snapshotting(uc, native_hooks_take_snapshot, native_hooks_restore_snapshot, native_hooks_discard_snapshot);
}
