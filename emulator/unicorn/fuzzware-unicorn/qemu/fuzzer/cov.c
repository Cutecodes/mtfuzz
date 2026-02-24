#include "log.h"
#include "cov.h"

unsigned long cov_prev_loc = 0;
unsigned char *cov_area_ptr = NULL;
unsigned long cov_area_size = 0;
unsigned long cov_mode = 0;
/* Ensure a meaningful power of 2 */
static int check_bitmap_size(uint32_t size) {
    for(uint32_t valid = COV_AREA_SIZE_MIN; valid <= COV_AREA_SIZE_MAX; valid<<=1) {
        if(size == valid) {
            return true;
        }
    }
    return false;
}

void fuzzer_init_cov(uc_engine *uc, void *bitmap_region, uint32_t bitmap_size, uint32_t mode) {
    if(bitmap_size == 0) {
        bitmap_size = COV_AREA_SIZE_MAX;
    }

    /* As soon as MAP_SIZE is not enforced, also sync this in afl_add_instrumentation */
    FW_ASSERT1(cov_area_ptr == NULL && check_bitmap_size(bitmap_size));

    if(bitmap_region == NULL) {
        cov_area_ptr = malloc(bitmap_size);
    } else {
        cov_area_ptr = bitmap_region;
    }

    cov_area_size = bitmap_size;
    cov_prev_loc = 0;
    cov_mode = mode;
}

void fuzzer_reset_cov(uc_engine *uc, int do_clear) {
    if(do_clear && cov_area_ptr) {
        memset(cov_area_ptr, 0, cov_area_size);
    }

    cov_prev_loc = 0;
}

void* fuzzer_snapshot_cov(uc_engine *uc) {
    if (cov_area_ptr == NULL || cov_area_size == 0) {
        return NULL;
    }

    uint8_t* buff = malloc(cov_area_size + sizeof(cov_prev_loc) + sizeof(cov_mode));
    if (!buff) {
        return buff;
    }

    memcpy(buff, cov_area_ptr, cov_area_size);

    *(unsigned long*)(buff + cov_area_size) = cov_prev_loc;
    *(unsigned long*)(buff + cov_area_size + sizeof(cov_prev_loc)) = cov_mode;

    return buff;
}

void fuzzer_restore_cov(uc_engine *uc, void* buffer) {
    uint8_t* buff = buffer;
    if (buff == NULL || cov_area_ptr == NULL || cov_area_size == 0) {
        return;
    }
    
    memcpy(cov_area_ptr, buff, cov_area_size);

    cov_prev_loc = *(unsigned long*)(buff+cov_area_size);
    cov_mode = *(unsigned long*)(buff + cov_area_size + sizeof(cov_prev_loc));
    
    return;
}

unsigned long fuzzer_get_cov_prev_loc(uc_engine *uc){
    return cov_prev_loc;
}

void fuzzer_set_cov_prev_loc(uc_engine *uc, unsigned long prev_loc){
    cov_prev_loc = prev_loc;
}