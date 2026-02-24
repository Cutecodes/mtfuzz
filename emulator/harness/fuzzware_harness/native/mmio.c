/* handle mmio*/

#include "mmio.h"
#include "state_snapshotting.h"
#include "fuzzware_mmio_model.h"
#include <unicorn/unicorn.h>
#include <assert.h>
#include <string.h>
#include "arch.h"
#include "fuzz.h"

// 0. Constants
// 1. Static (after initialization) configs
uint32_t num_mmio_regions = 0;
uint64_t *mmio_region_starts = 0;
uint64_t *mmio_region_ends = 0;
int num_mmio_callbacks = 0;
struct mmio_callback *mmio_callbacks[MAX_MMIO_CALLBACKS];
uint32_t num_ignored_addresses = 0;
uint64_t ignored_addresses[MAX_IGNORED_ADDRESSES];
uint32_t ignored_address_pcs[MAX_IGNORED_ADDRESSES];


// 3. Dynamic State (required for state restore)


void hook_mmio_access(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data)
{
    uint32_t pc = 0;
    
    arch_get_pc(uc, &pc);

    // TODO: optimize this lookup
    for (int i = 0; i < num_ignored_addresses; ++i)
    {
        if(addr == ignored_addresses[i] && (ignored_address_pcs[i] == MMIO_HOOK_PC_ALL_ACCESS_SITES || ignored_address_pcs[i] == pc)) {
            #ifdef DEBUG
            printf("Hit passthrough address 0x%08lx - pc: 0x%08x - returning\n", addr, pc); fflush(stdout);
            #endif
            goto out;
        }
    }

    for (int i = 0; i < num_mmio_callbacks; ++i)
    {
        if (addr >= mmio_callbacks[i]->start && addr <= mmio_callbacks[i]->end &&
                (mmio_callbacks[i]->pc == MMIO_HOOK_PC_ALL_ACCESS_SITES || mmio_callbacks[i]->pc == pc))
        {
            if(mmio_callbacks[i]->user_data != NULL) {
                user_data = mmio_callbacks[i]->user_data;
            }
            #ifdef DEBUG
            printf("Hit mmio callback address 0x%08lx - pc: 0x%08x - returning\n", addr, pc); fflush(stdout);
            #endif
            mmio_callbacks[i]->callback(uc, type, addr, size, value, user_data);
            goto out;
        }
    }

    #ifdef DEBUG
    printf("warning: serving %d byte(s) fuzz for mmio access to 0x%08lx, pc: 0x%08x!!!\n", size, addr, pc); fflush(stdout);
    #endif
    uint64_t val = 0;
    if(get_fuzz(uc, addr, size, (uint8_t *)&val)) {
        return;
    }
    #ifdef DEBUG
    printf(", value: 0x%lx\n", val); fflush(stdout);
    #endif
    if (uc_mem_write(uc, addr, (uint8_t *)&val, size) != UC_ERR_OK){
        do_exit(uc, UC_ERR_OK);
    };
    out:
    return;
}

uc_err add_mmio_region(uc_engine *uc, uint64_t begin, uint64_t end) {
    uc_hook tmp;
    printf("add_mmio_region called! hooking 0x%08lx - 0x%08lx\n", begin, end);
    return uc_hook_add(uc, &tmp, UC_HOOK_MEM_READ, hook_mmio_access, NULL, begin, end);
}

uc_err set_ignored_mmio_addresses(uc_engine *uc, uint64_t *addresses, uint32_t *pcs, int num_addresses) {
    assert(sizeof(*addresses) == sizeof(*ignored_addresses));
    assert(sizeof(*pcs) == sizeof(*ignored_address_pcs));

    if(num_addresses <= MAX_IGNORED_ADDRESSES) {
        #ifdef DEBUG
        for(int i = 0; i < num_addresses; ++i) {
            printf("Registering passthrough address: [%x] %lx\n", pcs[i], addresses[i]);
        }
        #endif
        memcpy(ignored_addresses, addresses, num_addresses * sizeof(*ignored_addresses));
        memcpy(ignored_address_pcs, pcs, num_addresses * sizeof(*ignored_address_pcs));
        num_ignored_addresses = num_addresses;
        return UC_ERR_OK;
    } else {
        printf("Too many ignored addresses to be registered");
        return UC_ERR_EXCEPTION;
    }
}

uc_err add_ignored_mmio_addresses(uc_engine *uc, uint64_t *addresses, uint32_t *pcs, int num_addresses) {
    assert(sizeof(*addresses) == sizeof(*ignored_addresses));
    assert(sizeof(*pcs) == sizeof(*ignored_address_pcs));

    if(num_addresses + num_ignored_addresses <= MAX_IGNORED_ADDRESSES) {
        #ifdef DEBUG
        for(int i = 0; i < num_addresses; ++i) {
            printf("Registering passthrough address: [%x] %lx\n", pcs[i], addresses[i]);
        }
        #endif
        
        #ifdef USE_FUZZWARE_MODEL
        memcpy(ignored_addresses + num_ignored_addresses, addresses, num_addresses * sizeof(*ignored_addresses));
        memcpy(ignored_address_pcs + num_ignored_addresses, pcs, num_addresses * sizeof(*ignored_address_pcs));
        num_ignored_addresses = num_ignored_addresses + num_addresses;
        #else
        if(num_addresses + num_addresses > MAX_MODEL_CONFIG_SIZE) num_addresses = MAX_MODEL_CONFIG_SIZE - passthrough_model_size;
        for(int i = passthrough_model_size; i < passthrough_model_size + num_addresses; ++i) {
            passthrough_model[i].pc = pcs[i];
            passthrough_model[i].start_addr = addresses[i];
            passthrough_model[i].end_addr = addresses[i]; 
        }
        passthrough_model_size += num_addresses;
        
        #endif
        return UC_ERR_OK;
    } else {
        printf("Too many ignored addresses to be registered");
        return UC_ERR_EXCEPTION;
    }
}


uc_err add_mmio_subregion_handler(uc_engine *uc, uc_cb_hookmem_t callback, uint64_t start, uint64_t end, uint32_t pc, void *user_data) {
    if(num_mmio_callbacks >= MAX_MMIO_CALLBACKS) {
        printf("ERROR add_mmio_subregion_handler: Maximum number of mmio callbacks exceeded\n");
        return -1;
    }

    if(!num_mmio_regions) {
        printf("ERROR add_mmio_subregion_handler: mmio start and end addresses not configured, yet\n");
        return UC_ERR_EXCEPTION;
    }

    int custom_region = 1;
    for (int i = 0; i < num_mmio_regions; ++i)
    {
        if (! (start < mmio_region_starts[i] || end > mmio_region_ends[i]))
        {
            custom_region = 0;
        }
    }

    if(custom_region) {
        printf("Attaching native listener to custom mmio subregion 0x%08lx-0x%08lx", start, end);
        add_mmio_region(uc, start, end);
    }

    struct mmio_callback *cb = calloc(1, sizeof(struct mmio_callback));
    cb->callback = callback;
    cb->start = start;
    cb->user_data = user_data;
    cb->end = end;
    cb->pc = pc;

    mmio_callbacks[num_mmio_callbacks++] = cb;

    return UC_ERR_OK;
}

void *mmio_models_take_snapshot(uc_engine *uc) {
    size_t size = num_ignored_addresses * sizeof(uint32_t);
    uint32_t *passthrough_init_vals = malloc(size);

    for(int i = 0; i < num_ignored_addresses; ++i) {
        uc_mem_read(uc, ignored_addresses[i], &passthrough_init_vals[i], sizeof(*passthrough_init_vals));
    }

    return passthrough_init_vals;
}

void mmio_models_restore_snapshot(uc_engine *uc, void *snapshot) {
    uint32_t *passthrough_init_vals = (uint32_t *) snapshot;

    // Restore the initial passthrough MMIO values
    for(int i = 0; i < num_ignored_addresses; ++i) {
        uc_mem_write(uc, ignored_addresses[i], &passthrough_init_vals[i], sizeof(*passthrough_init_vals));
    }
}

void mmio_models_discard_snapshot(uc_engine *uc, void *snapshot) {
    free(snapshot);
}



