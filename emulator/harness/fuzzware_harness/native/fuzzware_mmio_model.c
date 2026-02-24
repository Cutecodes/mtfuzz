#include "fuzzware_mmio_model.h"
#include "mmio.h"
#include "fuzz.h"


struct passthrough_mmio_model_config passthrough_model[MAX_MODEL_CONFIG_SIZE];
uint32_t passthrough_model_size = 0;
struct constant_mmio_model_config constant_model[MAX_MODEL_CONFIG_SIZE];
uint32_t constant_model_size = 0;
struct bitextract_mmio_model_config bitextract_model[MAX_MODEL_CONFIG_SIZE];
uint32_t bitextract_model_size = 0;
struct value_set_mmio_model_config value_set_model[MAX_MODEL_CONFIG_SIZE];
uint32_t value_set_model_size = 0;

uc_err register_py_handled_mmio_ranges(uc_engine *uc, uc_cb_hookmem_t py_mmio_callback, uint64_t *starts, uint64_t *ends, int num_ranges, void* user_data) {
    uint64_t start, end;


    for (int i = 0; i < num_ranges; ++i) {
        start = starts[i];
        end = ends[i];
        if(add_mmio_subregion_handler(uc, py_mmio_callback, start, end, MMIO_HOOK_PC_ALL_ACCESS_SITES, user_data) != UC_ERR_OK) {
            return UC_ERR_EXCEPTION;
        }
    }

    return UC_ERR_OK;
}

void linear_mmio_model_handler(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data) {
    struct linear_mmio_model_config *model_state = (struct linear_mmio_model_config *) user_data;

    model_state->val += model_state->step;

    #ifdef DEBUG
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("[0x%08x] Native Linear MMIO handler: [0x%08lx] = [0x%x]\n", pc, addr, model_state->val); fflush(stdout);
    #endif

    uc_mem_write(uc, addr, &model_state->val, sizeof(model_state->val));
}

void constant_mmio_model_handler(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data) {
    struct constant_mmio_model_config *model_state = (struct constant_mmio_model_config *) user_data;
    uint64_t val = model_state->val;

    #ifdef DEBUG
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("[0x%08x] Native Constant MMIO handler: [0x%08lx] = [0x%lx]\n", pc, addr, val); fflush(stdout);
    #endif

    // TODO: This assumes shared endianness between host and target
    uc_mem_write(uc, addr, &val, size);
}

void bitextract_mmio_model_handler(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data)
{
    struct bitextract_mmio_model_config *config = (struct bitextract_mmio_model_config *) user_data;
    uint64_t result_val = 0;
    uint64_t fuzzer_val = 0;

    // TODO: this currently assumes little endianness on both sides to be correct
    if(get_fuzz(uc, addr, config->byte_size, (uint8_t *)(&fuzzer_val))) {
        return;
    }

    result_val = fuzzer_val << config->left_shift;
    uc_mem_write(uc, addr, &result_val, size);

    #ifdef DEBUG
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("[0x%08x] Native Bitextract MMIO handler: [0x%08lx] = [0x%lx] from %d byte input: %lx\n", pc, addr, result_val, config->byte_size, fuzzer_val); fflush(stdout);
    #endif
}

void value_set_mmio_model_handler(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data) {
    struct value_set_mmio_model_config *config = (struct value_set_mmio_model_config *) user_data;

    uint64_t result_val;
    uint8_t fuzzer_val = 0;
    #ifdef DEBUG
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    #endif

    if(config->num_vals > 1) {
        if(get_fuzz(uc, addr, 1, (uint8_t *)&fuzzer_val)) {
            return;
        }

        result_val = config->values[fuzzer_val % config->num_vals];
    } else {
        result_val = config->values[0];
    }

    #ifdef DEBUG
    printf("[0x%08x] Native Set MMIO handler: [0x%08lx] = [0x%lx] from input: %x [values: ", pc, addr, result_val, fuzzer_val);
    for (uint32_t i = 0; i < config->num_vals; ++i) {
        if(i) {
            printf(", ");
        }
        printf("%x", config->values[i]);
    }
    printf("]\n");
    fflush(stdout);
    #endif

    uc_mem_write(uc, addr, (uint8_t *)&result_val, size);
}

uc_err register_constant_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *vals, int num_ranges) {
    struct constant_mmio_model_config *model_configs = calloc(num_ranges, sizeof(struct constant_mmio_model_config));

    for (int i = 0; i < num_ranges; ++i) {
        #ifdef DEBUG
        printf("Registering constant model for range: [%x] %lx - %lx with val: %x\n", pcs[i], starts[i], ends[i], vals[i]); fflush(stdout);
        #endif
        
        model_configs[i].pc = pcs[i];
        model_configs[i].start_addr = starts[i];
        model_configs[i].end_addr = ends[i];
        model_configs[i].val = vals[i];
        
        #ifdef USE_FUZZWARE_MODEL
        if(add_mmio_subregion_handler(uc, constant_mmio_model_handler, starts[i], ends[i], pcs[i], &model_configs[i]) != UC_ERR_OK) {
            return UC_ERR_EXCEPTION;
        }
        #endif

    }

    constant_model_size = num_ranges;
    memcpy(constant_model, model_configs, num_ranges * sizeof(struct constant_mmio_model_config));

    return UC_ERR_OK;
}

uc_err register_linear_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *init_vals, uint32_t *steps, int num_ranges) {
    // TODO: support cleanup, currently we just allocate, hand out pointers and forget about them
    struct linear_mmio_model_config *model_configs = calloc(num_ranges, sizeof(struct linear_mmio_model_config));

    for (int i = 0; i < num_ranges; ++i) {
        #ifdef DEBUG
        printf("Registering linear model for range: [%x] %lx - %lx with step: %x\n", pcs[i], starts[i], ends[i], steps[i]); fflush(stdout);
        #endif
        model_configs[i].val = init_vals[i];
        model_configs[i].step = steps[i];
        
        #ifdef USE_FUZZWARE_MODEL
        if(add_mmio_subregion_handler(uc, linear_mmio_model_handler, starts[i], ends[i], pcs[i], &model_configs[i]) != UC_ERR_OK) {
            return UC_ERR_EXCEPTION;
        }
        #endif
    }

    return UC_ERR_OK;
}

uc_err register_bitextract_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint8_t *byte_sizes, uint8_t *left_shifts, uint32_t *masks, int num_ranges) {
    struct bitextract_mmio_model_config *model_configs = calloc(num_ranges, sizeof(struct bitextract_mmio_model_config));

    for (int i = 0; i < num_ranges; ++i) {
        model_configs[i].pc = pcs[i];
        model_configs[i].start_addr = starts[i];
        model_configs[i].end_addr = ends[i];
        model_configs[i].mask = masks[i];
        model_configs[i].byte_size = byte_sizes[i];
        model_configs[i].left_shift = left_shifts[i];
        model_configs[i].mask_hamming_weight = 0;

        uint32_t mask = masks[i];
        while(mask) {
            if(mask & 1) {
                ++model_configs[i].mask_hamming_weight;
            }
            mask >>= 1;
        }

        #ifdef DEBUG
        printf("Registering bitextract model for range: [%x] %lx - %lx with size, left_shift: %d, %d. Mask: %08x, hw: %d\n", pcs[i], starts[i], ends[i], byte_sizes[i], left_shifts[i], masks[i], model_configs[i].mask_hamming_weight); fflush(stdout);
        #endif
        
        #ifdef USE_FUZZWARE_MODEL
        if(add_mmio_subregion_handler(uc, bitextract_mmio_model_handler, starts[i], ends[i], pcs[i], &model_configs[i]) != UC_ERR_OK) {
            return UC_ERR_EXCEPTION;
        }
        #endif
    }
    bitextract_model_size = num_ranges;
    memcpy(bitextract_model, model_configs, num_ranges * sizeof(struct value_set_mmio_model_config));

    return UC_ERR_OK;
}

uc_err register_value_set_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *value_nums, uint32_t **value_lists, int num_ranges) {
    struct value_set_mmio_model_config *model_configs = calloc(num_ranges, sizeof(struct value_set_mmio_model_config));

    printf("Registering incoming Value Set models\n");

    for (int i = 0; i < num_ranges; ++i) {
        #ifdef DEBUG
        uint32_t pc;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);

        printf("Registering value set model: [%x] %lx - %lx with numvalues, value_set: %d, [", pcs[i], starts[i], ends[i], value_nums[i]);
        for (uint32_t j = 0; j < value_nums[i]; ++j) {
            if(j) {
                printf(", ");
            }
            printf("%x", value_lists[i][j]);
        }
        printf("]\n");
        fflush(stdout);
        #endif

        model_configs[i].pc = pcs[i];
        model_configs[i].start_addr = starts[i];
        model_configs[i].end_addr = ends[i];
        model_configs[i].num_vals = value_nums[i];
        model_configs[i].values = calloc(value_nums[i], sizeof(**value_lists));
        for (int j = 0; j < value_nums[i]; ++j) {
            model_configs[i].values[j] = value_lists[i][j];
        }
        
        #ifdef USE_FUZZWARE_MODEL
        if(add_mmio_subregion_handler(uc, value_set_mmio_model_handler, starts[i], ends[i], pcs[i], &model_configs[i]) != UC_ERR_OK) {
            return UC_ERR_EXCEPTION;
        }
        #endif
    }
    
    value_set_model_size = num_ranges;
    memcpy(value_set_model, model_configs, num_ranges * sizeof(struct value_set_mmio_model_config));
    

    return UC_ERR_OK;
}
