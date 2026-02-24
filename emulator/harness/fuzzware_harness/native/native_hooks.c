/* Low level unicorn hooks for fuzzing */

/* Porting Considerations
- Memory handlers currently assume shared endianness between host and emulated target (uc_mem_write)
*/

#include <string.h>

#include "native_hooks.h"
#include "arch.h"

// 0. Constants

// 1. Static (after initialization) configs

uc_hook hook_block_cond_py_handlers_handle;
uc_cb_hookcode_t py_hle_handler_hook = (uc_cb_hookcode_t)0;
int num_handlers = 0;
uint64_t *bb_handler_locs = 0;

// 2. Transient variables (not required to be included in state restore)


// 3. Dynamic State (required for state restore)


void hook_block_debug(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    printf("Basic Block: addr= 0x%016lx \n", address);
    fflush(stdout);
}

void hook_debug_mem_access(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data) {
    uint32_t pc, sp;
    arch_get_pc(uc, &pc);
    arch_get_sp(uc, &sp);

    int64_t sp_offset = sp - address;
    if(sp_offset > -0x1000 && sp_offset < 0x2000) {
        if(type == UC_MEM_WRITE) {
            printf("        >>> Write: addr= 0x%08lx[SP:%c%04lx] size=%d data=0x%08lx (pc 0x%08x)\n", address, sp_offset >= 0 ? '+' : '-', sp_offset >= 0 ? sp_offset : -sp_offset, size, value, pc);
        } else {
            uint32_t read_value = 0;
            uc_mem_read(uc, address, &read_value, size);
            printf("        >>> Read: addr= 0x%08lx[SP:%c%04lx] size=%d data=0x%08x (pc 0x%08x)\n", address, sp_offset >= 0 ? '+' : '-', sp_offset >= 0 ? sp_offset : -sp_offset, size, read_value, pc);
        }
    } else {
        if(type == UC_MEM_WRITE) {
            printf("        >>> Write: addr= 0x%016lx size=%d data=0x%08lx (pc 0x%08x)\n", address, size, value, pc);
        } else {
            uint32_t read_value = 0;
            uc_mem_read(uc, address, &read_value, size);
            printf("        >>> Read: addr= 0x%016lx size=%d data=0x%08x (pc 0x%08x)\n", address, size, read_value, pc);
        }
    }
    fflush(stdout);
}

uc_err add_debug_hooks(uc_engine *uc) {
    uc_hook tmp;
    uc_err res = UC_ERR_OK;
    // Register unconditional hook for checking for handler presence
    res |= uc_hook_add(uc, &tmp, UC_HOOK_BLOCK_UNCONDITIONAL, hook_block_debug, NULL, 1, 0);
    res |= uc_hook_add(uc, &tmp, UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, hook_debug_mem_access, 0, 1, 0);
    return res;
}

void hook_block_cond_py_handlers(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    uint64_t next_val;

    // Search for address in value list and invoke python handler if found
    for (int i = 0; i < num_handlers; ++i) {
        next_val = bb_handler_locs[i];
        if (next_val > address) {
            break;
        } else if(next_val == address) {
            py_hle_handler_hook(uc, address, size, user_data);
        }
    }
}

uc_err register_cond_py_handler_hook(uc_engine *uc, uc_cb_hookcode_t py_mmio_callback, uint64_t *addrs, int num_addrs, void *user_data) {
    py_hle_handler_hook = py_mmio_callback;
    num_handlers = num_addrs;

    bb_handler_locs = malloc(num_addrs * sizeof(uint64_t));
    if(!bb_handler_locs) {
        perror("allocating handler location struct failed\n");
        return -1;
    }

    memcpy(bb_handler_locs, addrs, num_addrs * sizeof(uint64_t));

    // shouldn't be many entries, just sort ascending this way
    for (int i = 0; i < num_addrs; i++)
	{
		for (int j = 0; j < num_addrs; j++)
		{
			if (bb_handler_locs[j] > bb_handler_locs[i])
			{
				uint64_t tmp = bb_handler_locs[i];
			    bb_handler_locs[i] = bb_handler_locs[j];
				bb_handler_locs[j] = tmp;
			}
		}
	}

    // Register unconditional hook for checking for handler presence
    return uc_hook_add(uc, &hook_block_cond_py_handlers_handle, UC_HOOK_BLOCK_UNCONDITIONAL, hook_block_cond_py_handlers, user_data, 1, 0);
}

uc_err remove_function_handler_hook_address(uc_engine *uc, uint64_t address) {
    for (int i = 0; i < num_handlers ; i++)	{
		if (bb_handler_locs[i] == address) {
            // Found the handler location, now move everything else to the front
            for(int j = i; j < num_handlers-1; ++j) {
                bb_handler_locs[j] = bb_handler_locs[j+1];
            }

            --num_handlers;
            // Now fully remove the (unconditional) hook if we can
            if(!num_handlers) {
                uc_hook_del(uc, hook_block_cond_py_handlers_handle);
            }
            return UC_ERR_OK;
        }
    }

    perror("[NATIVE ERROR] remove_function_handler_hook_address: could not find address to be removed\n");
    exit(-1);
}






















