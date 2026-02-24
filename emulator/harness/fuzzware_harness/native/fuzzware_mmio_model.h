#ifndef FUZZWARE_MMIO_MODEL_H
#define FUZZWARE_MMIO_MODEL_H

#include "unicorn/unicorn.h"

#define MAX_MODEL_CONFIG_SIZE 65536

#define USE_FUZZWARE_MODEL 1

struct linear_mmio_model_config {
    uint32_t step;
    uint32_t val;
};

struct passthrough_mmio_model_config {
    uint64_t pc;
    uint64_t start_addr;
    uint64_t end_addr;    
};

struct constant_mmio_model_config {
    uint64_t pc;
    uint64_t start_addr;
    uint64_t end_addr;
    uint32_t val;
};

struct bitextract_mmio_model_config {
    uint64_t pc;
    uint64_t start_addr;
    uint64_t end_addr;
    uint8_t byte_size;
    uint8_t left_shift;
    uint8_t mask_hamming_weight;
    uint32_t mask;
};

struct value_set_mmio_model_config {
    uint64_t pc;
    uint64_t start_addr;
    uint64_t end_addr;
    uint32_t num_vals;
    uint32_t *values;
};

uc_err register_py_handled_mmio_ranges(uc_engine *uc, uc_cb_hookmem_t py_callback, uint64_t *starts, uint64_t *ends, int num_ranges, void* user_data);
uc_err register_linear_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *init_vals, uint32_t *steps, int num_ranges);
uc_err register_constant_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *vals, int num_ranges);
uc_err register_bitextract_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint8_t *byte_sizes, uint8_t *left_shifts, uint32_t *masks, int num_ranges);
uc_err register_value_set_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *value_nums, uint32_t **value_lists, int num_ranges);


extern struct passthrough_mmio_model_config passthrough_model[MAX_MODEL_CONFIG_SIZE];
extern uint32_t passthrough_model_size;
extern struct constant_mmio_model_config constant_model[MAX_MODEL_CONFIG_SIZE];
extern uint32_t constant_model_size;
extern struct bitextract_mmio_model_config bitextract_model[MAX_MODEL_CONFIG_SIZE];
extern uint32_t bitextract_model_size;
extern struct value_set_mmio_model_config value_set_model[MAX_MODEL_CONFIG_SIZE];
extern uint32_t value_set_model_size;

#endif
