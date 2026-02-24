#include "log.h"
#include "cmplog.h"



struct cmp_header* cmp_headers = NULL;
struct cmp_operands* cmp_log = NULL;
unsigned long cmp_map_w = CMP_MAP_W;
unsigned long cmp_map_h = CMP_MAP_H;
unsigned long cmp_counter = 0;
unsigned long cmp_mode = 0;

/* Ensure a meaningful power of 2 */
static int check_size(uint32_t size) {
    for(uint32_t valid = CMPLOG_AREA_W_MIN; valid <= CMPLOG_AREA_W_MAX; valid<<=1) {
        if(size == valid) {
            return true;
        }
    }
    return false;
}


void fuzzer_init_cmplog(uc_engine *uc, void *headers, void* log,  uint32_t w, uint32_t h, uint32_t mode) {
    if (headers == NULL || log == NULL || !check_size(w)) {
        printf("init cmplog failed!!!");
        return;
    }
    cmp_headers = headers;
    cmp_log = log;
    cmp_map_w = w; 
    cmp_map_h = h;

    cmp_counter = 0;
    cmp_mode = mode;
};
void fuzzer_reset_cmplog(uc_engine *uc, int do_clear) {
    if (do_clear) {
        if (cmp_headers) {
            memset(cmp_headers, 0, cmp_map_w * sizeof(struct cmp_header));
        }
    }
    cmp_counter = 0;

};

void* fuzzer_snapshot_cmplog(uc_engine *uc) {
    if (cmp_headers  == NULL || cmp_log == NULL || cmp_map_w == 0 || cmp_map_h ==0) {
        return NULL;
    }

    unsigned long size = cmp_map_w * sizeof(struct cmp_header) \
            + cmp_map_w * cmp_map_h * sizeof(struct cmp_operands) + sizeof(cmp_counter) + sizeof(cmp_mode);

    uint8_t* buff = malloc(size);
    if (!buff) {
        return buff;
    }
    
    unsigned long offset = 0;
    memcpy(buff, cmp_headers, cmp_map_w * sizeof(struct cmp_header));

    offset +=  cmp_map_w * sizeof(struct cmp_header);
    memcpy(buff+offset, cmp_log, cmp_map_w * cmp_map_h * sizeof(struct cmp_operands));

    offset +=  cmp_map_w * cmp_map_h * sizeof(struct cmp_operands);
    *(unsigned long*)(buff+offset) = cmp_counter;

    offset += sizeof(cmp_counter);
    *(unsigned long*)(buff+offset) = cmp_mode;

    return buff;
}

void fuzzer_restore_cmplog(uc_engine *uc, void* buffer) {
    uint8_t* buff = buffer;
    if (buff == NULL || cmp_headers  == NULL || cmp_log == NULL || cmp_map_w == 0 || cmp_map_h ==0) {
        return;
    }
    
    unsigned long offset = 0;
    memcpy(cmp_headers, buff, cmp_map_w * sizeof(struct cmp_header));

    offset +=  cmp_map_w * sizeof(struct cmp_header);
    memcpy(cmp_log, buff+offset, cmp_map_w * cmp_map_h * sizeof(struct cmp_operands));

    offset +=  cmp_map_w * cmp_map_h * sizeof(struct cmp_operands);
    cmp_counter = *(unsigned long*)(buff+offset);

    offset += sizeof(cmp_counter);
    cmp_mode = *(unsigned long*)(buff+offset);
    
    return;
}
