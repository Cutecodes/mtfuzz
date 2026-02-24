#include "arch.h"
#include "fuzz.h"
#include "timer.h"
#include "mmio.h"
#include "state_snapshotting.h"
#include "uc_snapshot.h"
#include "interrupt_triggers.h"
#include "cmplog.h"
#include "stream.h"
#include "khash.h"

#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <sys/shm.h>
#include <sys/wait.h>

#include "./fuzzer/fuzzer.h"


//#define DEBUG
#define COUNT
// 0. Constants
// ~10 MB of preallocated fuzzing buffer size
#define DEFAULT_MAX_EXIT_HOOKS 32
#define PREALLOCED_FUZZ_BUF_SIZE 10000000
#define FREAD_NMAX_CHUNKS 5
// AFL-related constants
// 64k bitmap size
//#define MAP_SIZE_POW2       16
//#define MAP_SIZE            (1 << MAP_SIZE_POW2)
#define FORKSRV_FD          198
#define SHM_ENV_VAR         "__AFL_SHM_ID"
// AFL++ compatibility constants
#define SHM_FUZZ_ENV_VAR "__AFL_SHM_FUZZ_ID"
#define CMPLOG_SHM_ENV_VAR "__AFL_CMPLOG_SHM_ID"
#define FS_OPT_SHDMEM_FUZZ 0x01000000
#define FS_OPT_ENABLED 0x80000001
#define FS_OPT_NEWCMPLOG 0x02000000


uc_err mem_errors[] = {
    UC_ERR_READ_UNMAPPED,
    UC_ERR_READ_PROT,
    UC_ERR_READ_UNALIGNED,
    UC_ERR_WRITE_UNMAPPED,
    UC_ERR_WRITE_PROT,
    UC_ERR_WRITE_UNALIGNED,
    UC_ERR_FETCH_UNMAPPED,
    UC_ERR_FETCH_PROT,
    UC_ERR_FETCH_UNALIGNED,
};

// 1. Static (after initialization) configs
uc_hook invalid_mem_hook_handle = 0;
int do_print_exit_info = 0;
uint32_t exit_at_hit_limit = 1;
uint32_t fuzz_consumption_timer_id;
uint64_t fuzz_consumption_timeout;
uint32_t instr_limit_timer_id;
uint64_t instr_limit = 0;

uint32_t do_fuzz = 0;
uint32_t cov_mode = 0;
uint32_t cmplog_mode = 0;
uint32_t do_emu = 0;
uint32_t fix_checksum_mode = 0;
uint32_t smart_stream = 0;
uint32_t its_mode = 0;

uint32_t use_stream = 0;

// 2. Transient variables (not required to be included in state restore)
uint32_t num_exit_hooks = 0;
exit_hook_t exit_hooks[DEFAULT_MAX_EXIT_HOOKS] = {NULL};

uint32_t is_discovery_child = 0;
static int pipe_to_parent[2] = {-1};

uint8_t *fuzz = NULL;
bool input_mode_SHM = false;
long fuzz_size = 0;
long fuzz_cursor = 0;
char *input_path = NULL;

// 3. Dynamic State (required for state restore)
uint32_t input_already_given = 0;
int duplicate_exit = false;
uc_err custom_exit_reason = UC_ERR_OK;


// Fuzzer shm
uint8_t  fuzz_area_initial[MAP_SIZE];
uint8_t  fuzz_area_initial_backup[MAP_SIZE];
uint8_t *fuzz_area_ptr_backup = fuzz_area_initial_backup;
uint8_t        *fuzz_area_ptr = fuzz_area_initial;
__thread uint32_t  fuzz_prev_loc;

struct stream_feedback stream_map_initial;
struct stream_feedback stream_map_initial_backup;
struct stream_feedback* stream_map = &stream_map_initial;

struct cmp_map fuzz_cmp_map_initial;
struct cmp_map fuzz_cmp_map_initial_backup;
struct cmp_map *fuzz_cmp_map = &fuzz_cmp_map_initial;


#ifdef COUNT
KHASH_SET_INIT_INT64(64);
KHASH_SET_INIT_INT(32);
khash_t(32) *kh_basic_block_set = NULL;
int cov_block = 0;
int num_streams = 0;
int num_mmios = 0;
#endif


void add_exit_hook(exit_hook_t hook) {
    if(num_exit_hooks == DEFAULT_MAX_EXIT_HOOKS) {
        perror("ERROR. add_exit_hook: Out of exit hook slots\n");
        exit(-1);
    }
    exit_hooks[num_exit_hooks++] = hook;
}

static void determine_input_mode() {
    char *id_str;
    int shm_id;
    int tmp;

    id_str = getenv(SHM_FUZZ_ENV_VAR);
    if (id_str) {
        shm_id = atoi(id_str);
        fuzz = shmat(shm_id, NULL, 0);
        if (!fuzz || fuzz == (void *)-1) {
            perror("[!] could not access fuzzing shared memory");
            exit(1);
        }

        // AFL++ detected. Read its status value
        if(read(FORKSRV_FD, &tmp, 4) != 4) {
            perror("[!] did not receive AFL++ status value");
            exit(1);
        }

        input_mode_SHM = true;
    }
}

int uc_err_to_sig(uc_err error) {
    for (uint32_t i = 0; i < sizeof(mem_errors) / sizeof(*mem_errors); ++i) {
        if(error == mem_errors[i]) {
            return SIGSEGV;
        }
    }
    if(error == UC_ERR_INSN_INVALID) {
        return SIGILL;
    } else {
        return SIGABRT;
    }
}



void do_exit(uc_engine *uc, uc_err err) {
    if(do_print_exit_info) {
        fflush(stdout);
    }

    if(!duplicate_exit) {
        custom_exit_reason = err;
        duplicate_exit = true;
        uc_emu_stop(uc);
    }
}

void force_crash(uc_engine *uc, uc_err error)
{
    do_exit(uc, error);
}

bool hook_debug_mem_invalid_access(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data) {
    uint64_t pc = 0;

    arch_get_pc(uc, &pc);
    
    if(type == UC_MEM_WRITE_UNMAPPED || type == UC_MEM_WRITE_PROT) {
        printf("        >>> [ 0x%08lx ] INVALID Write: addr= 0x%016lx size=%d data=0x%016lx\n", pc, address, size, value);
    } else if (type == UC_MEM_READ_UNMAPPED || type == UC_MEM_READ_PROT){
        printf("        >>> [ 0x%08lx ] INVALID READ: addr= 0x%016lx size=%d data=0x%016lx\n", pc, address, size, value);
    } else if (type == UC_MEM_FETCH_UNMAPPED || type == UC_MEM_FETCH_PROT) {
        printf("        >>> [ 0x%08lx ] INVALID FETCH: addr= 0x%016lx\n", pc, address);
    }
    
    fflush(stdout);
    return false;
}

void fuzz_consumption_timeout_cb(uc_engine *uc, uint32_t id, void *user_data) {
    if(do_print_exit_info) {
        printf("Fuzzing input not consumed for %ld basic blocks, exiting\n", fuzz_consumption_timeout);
    }
    do_exit(uc, UC_ERR_OK);
}


#ifdef DEBUG_INJECT_TIMER
void test_timeout_cb(uc_engine *uc, uint32_t id, void *user_data) {
    if(!is_discovery_child) {
        uint32_t pc;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        printf("Test timer triggered at pc 0x%08x\n", pc);
        fflush(NULL);
    }
}
#endif

void instr_limit_timeout_cb(uc_engine *uc, uint32_t id, void *user_data) {
    if(do_print_exit_info) {
        uint32_t pc = 0;
        arch_get_pc(uc, &pc);
        printf("Ran into instruction limit of %lu at 0x%08x - exiting\n", get_timer_reload_val(instr_limit_timer_id), pc);
    }
    do_exit(uc, UC_ERR_OK);
}

void hook_block_exit_at(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    if(++native_hooks_state.curr_exit_at_hit_num == exit_at_hit_limit) {
        if(do_print_exit_info) {
            printf("Hit exit basic block address: %08lx, times: %d\n", address, native_hooks_state.curr_exit_at_hit_num); fflush(stdout);
        }
        do_exit(uc, UC_ERR_OK);
    }
}

#ifdef COUNT
void hook_block_count(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    int kh_res;
    int cur_num_streams = 0;
    if(kh_get(32, kh_basic_block_set, address) == kh_end(kh_basic_block_set)) {
        kh_put(32, kh_basic_block_set, address, &kh_res);
        //cur_num_streams = get_num_stream();
        cur_num_streams = get_num_stream(&g_stream_input);
        if (cov_block < kh_size(kh_basic_block_set) || num_streams < cur_num_streams) {
            printf("count:%05lu stream count:%05d\n",kh_size(kh_basic_block_set),cur_num_streams);
            cov_block = cov_block < kh_size(kh_basic_block_set)?kh_size(kh_basic_block_set):cov_block;
            num_streams = num_streams < cur_num_streams ? cur_num_streams : num_streams;
        }
    }
}
#endif

uc_err init_fuzz(uc_engine *uc, exit_hook_t p_exit_hook, int p_num_mmio_regions, uint64_t *p_mmio_starts, uint64_t *p_mmio_ends, int p_num_ignored_mmio_addresses, uint64_t *p_ignored_mmio_addressed, uint32_t *p_ignored_address_pcs, uint32_t num_exit_at_bbls, 
       uint64_t *exit_at_bbls, uint32_t p_exit_at_hit_limit, int p_do_print_exit_info, uint64_t p_fuzz_consumption_timeout, uint32_t p_instr_limit, uint32_t p_cov_mode, uint32_t p_cmp_mode, uint32_t p_use_stream, uint32_t p_fix_checksum_mode, uint32_t p_smart_stream,
           uint32_t p_its_mode) {

    if(p_exit_hook) {
        add_exit_hook(p_exit_hook);
    }
    
    cov_mode = p_cov_mode;
    cmplog_mode = p_cmp_mode;
    use_stream = p_use_stream;
    
    fix_checksum_mode = p_fix_checksum_mode;
    smart_stream = p_smart_stream;
    its_mode = p_its_mode;

    exit_at_hit_limit = p_exit_at_hit_limit;
    do_print_exit_info = p_do_print_exit_info;
 
    
    if(do_print_exit_info) {
        uc_hook_add(uc, &invalid_mem_hook_handle, UC_HOOK_MEM_WRITE_INVALID | UC_HOOK_MEM_READ_INVALID | UC_HOOK_MEM_FETCH_INVALID, hook_debug_mem_invalid_access, 0, 1, 0);
    }
    
    
    // Add fuzz consumption timeout as timer
    fuzz_consumption_timeout = p_fuzz_consumption_timeout;
    fuzz_consumption_timer_id = add_timer(fuzz_consumption_timeout, fuzz_consumption_timeout_cb, NULL, TIMER_IRQ_NOT_USED);
    if(fuzz_consumption_timeout) {
        start_timer(uc, fuzz_consumption_timer_id);
    }



    #ifdef DEBUG_INJECT_TIMER
    // debug timer to debug precise timing consistencies
    start_timer(uc,add_timer(DEBUG_TIMER_TIMEOUT, test_timeout_cb, NULL, TIMER_IRQ_NOT_USED));
    #endif

    instr_limit = p_instr_limit;
    instr_limit_timer_id = add_timer(instr_limit, instr_limit_timeout_cb, NULL, TIMER_IRQ_NOT_USED);
    if(instr_limit) {
        start_timer(uc, instr_limit_timer_id);
    }


    for (uint32_t i = 0; i < num_exit_at_bbls; ++i)
    {
        uint64_t tmp;
        uint64_t bbl_addr = exit_at_bbls[i] & (~1LL);
        if (uc_hook_add(uc, &tmp, UC_HOOK_BLOCK, hook_block_exit_at, 0, bbl_addr, bbl_addr) != UC_ERR_OK)
        {
            perror("Could not register exit-at block hook...\n");
            return -1;
        }
    }

    // Register read hooks for mmio regions
    num_mmio_regions = p_num_mmio_regions;
    mmio_region_starts = calloc(num_mmio_regions, sizeof(*p_mmio_starts));
    mmio_region_ends = calloc(num_mmio_regions, sizeof(*p_mmio_ends));
    memcpy(mmio_region_starts, p_mmio_starts, num_mmio_regions * sizeof(*p_mmio_starts));
    memcpy(mmio_region_ends, p_mmio_ends, num_mmio_regions * sizeof(*p_mmio_ends));

    for (int i = 0; i < num_mmio_regions; ++i) {
        if(add_mmio_region(uc, mmio_region_starts[i], mmio_region_ends[i]) != UC_ERR_OK) {
            perror("[native init] could not register mmio region.\n");
            return UC_ERR_EXCEPTION;
        }
    }

    add_ignored_mmio_addresses(uc, p_ignored_mmio_addressed, p_ignored_address_pcs, p_num_ignored_mmio_addresses);
    
    // Snapshotting
    init_interrupt_triggering(uc);
    init_uc_state_snapshotting(uc);

    subscribe_state_snapshotting(uc, mmio_models_take_snapshot, mmio_models_restore_snapshot, mmio_models_discard_snapshot);
 
#ifdef SMART_STREAM
    init_CircularQueue(&last_read_mmio);
#endif

#ifdef COUNT
    uint64_t tmp_handle;
    kh_basic_block_set = kh_init(32);
    uc_hook_add(uc, &tmp_handle, UC_HOOK_BLOCK, hook_block_count, NULL, 1, 0);
#endif
    return UC_ERR_OK;
}


uc_err load_fuzz(const char *path) {
    FILE *fp;
    long leftover_size;
    if(input_mode_SHM) {
        // shm inputs: <size_u32> contents ...
        fuzz_size = (*(uint32_t *)fuzz) + sizeof(uint32_t);
        fuzz_cursor = sizeof(uint32_t);
        return 0;
    }

    leftover_size = fuzz_size - fuzz_cursor;
    if(leftover_size != 0) {
        perror("Got prefix input which is not fully consumed. Exiting...\n");
        exit(-1);
    }

    if(!(fp=fopen(path, "r"))) {
        perror("Opening file failed\n");
        return -1;
    }

    if(fseek(fp, 0L, SEEK_END)) {
        perror("fseek failed\n");
        return -1;
    }

    if((fuzz_size = ftell(fp)) < 0) {
        perror("ftell failed\n");
        return -1;
    }
    rewind(fp);

    #ifdef DEBUG
    printf("leftover_size = %ld, fuzz_size = %ld (path: %s)\n", leftover_size, fuzz_size, path);
    #endif

    if (fuzz_size > PREALLOCED_FUZZ_BUF_SIZE) {
        // As we may need to copy over leftover contents, keep ref

        if (!(fuzz = calloc(fuzz_size, 1)))
        {
            perror("Allocating fuzz buffer failed\n");
            return -1;
        }

        #ifdef DEBUG
        printf("Allocated new oversized fuzz buffer of size 0x%lx\n", fuzz_size);
        #endif
    }else if(!fuzz) {
        // first load_fuzz
        if(!(fuzz = calloc(PREALLOCED_FUZZ_BUF_SIZE, 1))) {
            perror("Allocating fuzz buffer failed\n");
            return -1;
        }    
    }

    fuzz_cursor = 0;

    // Give reading the input multiple chunk tries
    size_t num_chunks, already_read = 0, last_read, to_be_read=fuzz_size;
    for(num_chunks=0; to_be_read && num_chunks<FREAD_NMAX_CHUNKS; ++num_chunks) {
        last_read = fread(&fuzz[already_read], 1, to_be_read, fp);
        to_be_read -= last_read;
        already_read += last_read;
    }
    fclose(fp);

    if(to_be_read) {
        perror("fread failed\n");
        return -1;
    }
    
    if (use_stream) {
        if (!init_streams_input(&g_stream_input, fuzz, fuzz_size, 0)){
        //if (!init_streams(fuzz, fuzz_size, 1)) {
            printf("[load_fuzz] init_streams failed! using empty stream\n");
        }
    }
    return 0;
}

void load_delayed_input(uc_engine *uc) {
    // Having spun up the fork server, we can now load the input file
    
    if (do_emu) {
        if(load_fuzz(input_path) != 0) {
             _exit(-1);
        }
       
    }
        //fuzz = get_file(&fuzz_size); 
    get_streams_input_file(&g_stream_input, &fuzz, &fuzz_size);   
    fuzz_cursor = 0;
    

    input_already_given = 1;
}

bool get_stream_fuzz(uc_engine *uc, uint64_t addr, int size, uint8_t * buf) {
    // ok consuming fuzz input
    #ifdef DEBUG
    printf("get_stream_fuzz:%016lx %d\n",addr,size);
    #endif



//#if 0  
    uint64_t pc = 0;
    arch_get_pc(uc, &pc);
    addr = (pc<< 32) | addr;
    
//#endif
    //printf("kkkkk\n");
    //struct stream_mem* stream = get_stream_by_addr(addr);
    struct stream* stream = get_stream_by_addr(&g_stream_input, addr);
    //printf("%016lx\n",stream);
    if (!stream) {
        stream_map->status.addr = addr;
        stream_map->status.size = size;
        stream_map->status.new_stream = 1;
        
       
        if(do_print_exit_info) {
            printf("\n>>> Failed to get stream %016lx\n",addr);
        }
        do_exit(uc, UC_ERR_OK);
        return 1;
    } else {

#ifdef SMART_STREAM
        enqueue_CircularQueue(&last_read_mmio, addr);
#endif
        uint32_t cursor = stream_map->cursors[stream->id];
        //printf("%016lx,%d\n",addr,cursor);
        #ifdef DSBUG
        printf("Find stream at %016lx, id:%d, len:%d\n",(uint64_t)stream,stream->id,stream->len);
        for(int i=0;i<stream->len;i++){
            printf("%02x ",stream->data[i]);
        }
        printf("\n");
        #endif
        if(size && cursor+size <= stream->len) {
            memcpy(buf, &(stream->data[cursor]), size);
            stream_map->cursors[stream->id] += size;
        }else {
            if(do_print_exit_info) {
                puts("\n>>> Stream ran out of fuzz\n");
            }
            stream_map->status.addr = addr;
            stream_map->status.size = size;
            stream_map->status.new_stream = 0;
            do_exit(uc, UC_ERR_OK);
            return 1;
        }
    }

    return 0;
};

bool get_fuzz(uc_engine *uc, uint64_t addr, int size, uint8_t * buf) {
    /*
     * Consuming input is more complex here than one might expect.
     * The reason for this is that we support a prefix input as well
     * as detecting the number of basic blocks that we can execute
     * before consuming fuzzing input.
     *
     * a) The ordinary case is having input, consuming it, and progressing
     * the cursor as one would expect.
     * b) The second case makes the discovery child report the number of
     * translation blocks to run as part of the execution prefix as soon
     * as new fuzzing input would have to be consumed.
     * c) Once after a snapshot, we want to load the fuzzing input. We
     * do this in a delayed manner to support pre-loaded prefix inputs
     * (which are consumed as part of the execution prefix).
     * d) In case we have already loaded the dynamic input once, we
     * finally ran out of input to provide and conclude the run.
     */
    #ifdef DEBUG
    printf("[NATIVE FUZZ] Requiring %d fuzz bytes\n", size); fflush(stdout);
    #endif

    // Deal with copying over the (remaining) fuzzing bytes
    if(size && fuzz_cursor+size <= fuzz_size) {
        #ifdef DEBUG
        printf("[NATIVE FUZZ] Returning %d fuzz bytes\n", size); fflush(stdout);
        #endif
        
        // We are consuming fuzzing input, reset watchdog
        reload_timer(fuzz_consumption_timer_id);
        if (use_stream) {
            return get_stream_fuzz(uc, addr, size, buf);
        }else {
            memcpy(buf, &fuzz[fuzz_cursor], size);
            fuzz_cursor += size;
        }
        
        return 0;
    } else if(unlikely(is_discovery_child)) {
        // We are the discovery child, report the current tick count
        uint64_t ticks_so_far = get_global_ticker();
        if(write(pipe_to_parent[1], &ticks_so_far, sizeof(ticks_so_far)) != sizeof(ticks_so_far)) {
           puts("[Discovery Child] Error: could not write number of ticks to parent"); fflush(stdout);
        }
        _exit(0);
    } else if (!input_already_given) {
        // Load file-based input now
        load_delayed_input(uc);

        return get_fuzz(uc, addr, size, buf);
    } else {
        if(do_print_exit_info) {
            puts("\n>>> Ran out of fuzz\n");
        }

        do_exit(uc, UC_ERR_OK);
        return 1;
    }

}


static void fuzz_map_shm(uc_engine *uc) {
    // Use local backup bitmap to run without AFL
    
    fuzz_area_ptr_backup = fuzz_area_initial;
    fuzz_area_ptr = fuzz_area_initial;

    // Indicate to possible afl++ that we can use SHM fuzzing
    uint32_t tmp = FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ | FS_OPT_NEWCMPLOG;
    char *id_str;
    int shm_id;

    /* Tell AFL once that we are here  */
    id_str = getenv(SHM_ENV_VAR);
    if (id_str) {
        shm_id = atoi(id_str);
        fuzz_area_ptr = shmat(shm_id, NULL, 0);

        if (fuzz_area_ptr == (void *)-1) {
            // We allow this case so we can use the emulator in a forkserver-aware trace gen worker
            puts("[FORKSERVER SETUP] Could not map SHM, reverting to local buffer");
            fuzz_area_ptr = fuzz_area_initial;
        }

        id_str = getenv(STREAM_SHM_ENV_VAR);
        if (id_str) {
            shm_id = atoi(id_str);
            stream_map = shmat(shm_id, NULL, 0);
            if (stream_map == (void *)-1) {
                // We allow this case so we can use the emulator in a forkserver-aware trace gen worker
                puts("[FORKSERVER SETUP] Could not map SHM, reverting to local buffer");
                stream_map = &stream_map_initial;
            }else {
                puts("[FORKSERVER SETUP] setup stream feedback successfully");
            }
        }else{
            puts("[FORKSERVER SETUP] It looks like we are not running AFL with stream, using local buffer instead");
        }
        
        if(write(FORKSRV_FD + 1, &tmp, 4) == 4) {
            do_fuzz = 1;
        } else {
            puts("[FORKSERVER SETUP] Got shared memory region, but no pipe. going for single input");
            do_fuzz = 0;
        }
    } else {
        puts("[FORKSERVER SETUP] It looks like we are not running under AFL, going for single input");
        do_fuzz = 0;
    }
    
    if (cmplog_mode){
        id_str = getenv(CMPLOG_SHM_ENV_VAR);
        if (id_str) {
            shm_id = atoi(id_str);

            fuzz_cmp_map = (struct cmp_map *)shmat(shm_id, NULL, 0);
            if (fuzz_cmp_map == (void *)-1) {
                // We allow this case so we can use the emulator in a forkserver-aware trace gen worker
                puts("[FORKSERVER SETUP] Could not map CMP_SHM, reverting to local buffer");
                fuzz_cmp_map = &fuzz_cmp_map_initial;
            }
        }else{
            puts("[FORKSERVER SETUP] It looks like we are not running AFL with cmplog, using local buffer instead");
        }
        uc_fuzzer_init_cmplog(uc, &fuzz_cmp_map->headers, &fuzz_cmp_map->log,  CMP_MAP_W, CMP_MAP_H, cmplog_mode);
    }
    
    uc_fuzzer_init_cov(uc, fuzz_area_ptr, MAP_SIZE, cov_mode);

}

int run_single(uc_engine *uc) {
    int status;
    uint64_t pc = 0;
    int sig = -1;

    arch_get_pc(uc, &pc);

    if (g_arch == UC_ARCH_ARM) {
         status = uc_emu_start(uc, pc | 1, 0, 0, 0);
    }else{
         status = uc_emu_start(uc, pc, 0, 0, 0);
    }
    fflush(stdout);
    if(custom_exit_reason != UC_ERR_OK) {
        status = custom_exit_reason;
    }

    if (status != UC_ERR_OK) {
        if(do_print_exit_info) {
            printf("Execution failed with error code: %d -> %s\n", status, uc_strerror(status));
        }
        sig = uc_err_to_sig(status);
    }
    
    for (uint32_t i = 0; i < num_exit_hooks; ++i) {
        exit_hooks[i](status, sig);
    }

    return sig == -1 ? status : sig;
}


static void restore_snapshot(uc_engine *uc) {
    // Restore all subscribed snapshot parts
    trigger_restore(uc);

    // Also reset fuzzing input cursor and exit detection
    fuzz_cursor = fuzz_size;
    input_already_given = 0;
    duplicate_exit = false;
    custom_exit_reason = UC_ERR_OK;
}

uc_err emulate(uc_engine *uc, char *p_input_path, char *prefix_input_path) {
    uint64_t pc = 0;
    fflush(stdout);
    
    arch_get_pc(uc, &pc);
    fuzz_map_shm(uc);
    do_emu = 1;
    /*
     * Pre-execute deterministic part of target execution (the execution prefix)
     * Anything before consuming dynamic fuzzing input for the first time is deterministic.
     * This includes a potential prefix input which we will also consume during this stage
     * to effectively restore a snapshot (which the prefix input leads us to).
     */

    // Set input path for the fuzz reading handler to pick up on later
    input_path = p_input_path;
    // Pre-load prefix input
    if(prefix_input_path) {
        if(load_fuzz(prefix_input_path) != 0) {
            _exit(-1);
        }
    }
    
    
    /*
     * This part of executing the execution prefix is a bit tricky:
     * We cannot simply run up to the first MMIO access, as this will leave our
     * execution context in the middle of an MMIO access, which would leave unicorn
     * in a state which we cannot snapshot.
     * So instead, we fork and discover how much execution we have ahead of us before
     * running into the first fuzzing input-consuming MMIO access. We report this number
     * from the forked child to the parent via a pipe.
     */
    pid_t child_pid;
    uint64_t required_ticks = -1;
    if(pipe(pipe_to_parent)) {
        puts("[ERROR] Could not create pipe for discovery forking");
        exit(-1);
    }

    // For every run (and to keep consistency between single and fuzzing runs), find out how many basic blocks we can execute before hitting the first MMIO read
    child_pid = fork();
    if(child_pid) {
        // parent: wait for the discovery child to report back the number of tbs we need to execute

        if(read(pipe_to_parent[0], &required_ticks, sizeof(required_ticks)) != sizeof(required_ticks)) {
            puts("[ERROR] Could not retrieve the number of required ticks during discovery forking");
            exit(-1);
        }
        waitpid(child_pid, &child_pid, 0);

        close(pipe_to_parent[0]);
        close(pipe_to_parent[1]);

        printf("[DISCOVERY FORK PARENT] Got number of ticks to step: %ld\n", required_ticks);

        if(required_ticks > 2) {
            // Set up a timer that will make use stop after executing the prefix
            set_timer_reload_val(instr_limit_timer_id, required_ticks-2);

            // Execute the prefix
            if (g_arch == UC_ARCH_ARM) {
                if(uc_emu_start(uc, pc | 1, 0, 0, 0)) {
                    puts("[ERROR] Could not execute the first some steps");
                    exit(-1);
                }            
            }else {
                
                if(uc_emu_start(uc, pc , 0, 0, 0)) {
                    puts("[ERROR] Could not execute the first some steps");
                    exit(-1);
                }
                
            }
        }
        puts("[+] Initial constant execution (including optional prefix input) done, starting input execution."); fflush(stdout);
    } else {
        // child: Run until we hit an input consumption
        is_discovery_child = 1;
        uc_err child_emu_status;
        if (g_arch == UC_ARCH_ARM) {
            child_emu_status = uc_emu_start(uc, pc | 1, 0, 0, 0);
        }else{
            child_emu_status = uc_emu_start(uc, pc , 0, 0, 0);
        }
        // We do not expect to get here. The child should exit by itself in get_fuzz
        printf("[ERROR] Emulation stopped using just the prefix input (%d: %s)\n", child_emu_status, uc_strerror(child_emu_status));

        // Write wrong amount of data to notify parent of failure
        if(write(pipe_to_parent[1], emulate, 1) != 1) {
            puts("[Discovery Child] Error: Could not notify parent of failure..."); fflush(stdout);
        }
        _exit(-1);
    }
    

    // After consuming first part of input and executing the prefix, set input mode
    determine_input_mode();
    // Set the proper instruction limit (after using a fake one to execute exec prefix)
    set_timer_reload_val(instr_limit_timer_id, instr_limit);

    // Upon exiting emulation, Unicorn will trigger basic block hits.
    // This ticks off timers two times. This is an issue because this
    // makes timings slightly differ when splitting an input to an input prefix
    // and the remaining input file. Adjust for this offset here.
    // TODO: adjusting the timer has to be done when it is caused.
    // TODO: This seems to be the case when unicorn is stopped, but need to re-visit
    // adjust_timers_for_unicorn_exit();

    
    if(do_fuzz) {
        uc_fuzzer_reset_cov(uc, 1);
        if (cmplog_mode) {
            uc_fuzzer_reset_cmplog(uc, 1);
        }
        trigger_snapshotting(uc);

        // AFL-compatible Forkserver loop
        child_pid = getpid();
        int count = 0;
        int tmp = 0;
        int sig;
        input_already_given = 0;
        duplicate_exit = false;
        for(;;) {
            ++count;

            /* Wait until we are allowed to run  */
            if(read(FORKSRV_FD, &tmp, 4) != 4) {
                if(count == 1) {
                    puts("[FORKSERVER MAIN LOOP] ERROR: Read from FORKSRV_FD to start new execution failed. Exiting");
                    exit(-1);
                } else {
                    puts("[FORKSERVER MAIN LOOP] Forkserver pipe now closed. Exiting");
                    exit(0);
                }
            }

            uc_fuzzer_reset_cov(uc, 1);
            if (cmplog_mode) {
                 uc_fuzzer_reset_cmplog(uc, 1);
            }
            memset(stream_map, 0, sizeof(struct stream_feedback));
            /* Send AFL the child pid thus it can kill it on timeout   */
            if(write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
                printf("[FORKSERVER MAIN LOOP] ERROR: Write to FORKSRV_FD+1 to send fake child PID failed. errno: %d. Description: '%s'. Count: %d\n", errno, strerror(errno), count); fflush(stdout);
                exit(-1);
            }
            
            sig = run_single(uc);
            
            
            if(write(FORKSRV_FD + 1, &sig, 4) != 4) {
                puts("[MAIN LOOP] Write to FORKSRV_FD+1 to send status failed");
                _exit(-1);
            }

            restore_snapshot(uc);
        }
    } else {
        puts("Running without a fork server");
        duplicate_exit = false;
        input_already_given = 0;
        uc_fuzzer_reset_cov(uc, 1);
        if (cmplog_mode) {
            uc_fuzzer_reset_cmplog(uc, 1);
        }
        
        trigger_snapshotting(uc);
        // Not running under fork server
        int sig = run_single(uc);
        
        if(do_print_exit_info) {
            if(sig) {
                // Crash occurred
                printf("Emulation crashed with signal %d\n", sig);
            } else {
                // Non-crashing exit (includes different timeouts)
                uint32_t pc;
                arch_get_pc(uc, &pc);
                printf("Exited without crash at 0x%08x - If no other reason, we ran into one of the limits\n", pc);
            }
        }
    }

    return UC_ERR_OK;
}


static struct snapshotting_state_t initial_state;
uc_err snapshot_initial(uc_engine *uc) {
    uint64_t pc = 0;
    arch_get_pc(uc, &pc);
    
    /*
     * This part of executing the execution prefix is a bit tricky:
     * We cannot simply run up to the first MMIO access, as this will leave our
     * execution context in the middle of an MMIO access, which would leave unicorn
     * in a state which we cannot snapshot.
     * So instead, we fork and discover how much execution we have ahead of us before
     * running into the first fuzzing input-consuming MMIO access. We report this number
     * from the forked child to the parent via a pipe.
     */
    pid_t child_pid;
    uint64_t required_ticks = -1;
    if(pipe(pipe_to_parent)) {
        puts("[ERROR] Could not create pipe for discovery forking");
        exit(-1);
    }

    // For every run (and to keep consistency between single and fuzzing runs), find out how many basic blocks we can execute before hitting the first MMIO read
    child_pid = fork();
    if(child_pid) {
        // parent: wait for the discovery child to report back the number of tbs we need to execute

        if(read(pipe_to_parent[0], &required_ticks, sizeof(required_ticks)) != sizeof(required_ticks)) {
            puts("[ERROR] Could not retrieve the number of required ticks during discovery forking");
            exit(-1);
        }
        waitpid(child_pid, &child_pid, 0);

        close(pipe_to_parent[0]);
        close(pipe_to_parent[1]);

        printf("[DISCOVERY FORK PARENT] Got number of ticks to step: %ld\n", required_ticks);

        if(required_ticks > 2) {
            // Set up a timer that will make use stop after executing the prefix
            set_timer_reload_val(instr_limit_timer_id, required_ticks-2);

            // Execute the prefix
            if (g_arch == UC_ARCH_ARM) {
                if(uc_emu_start(uc, pc | 1, 0, 0, 0)) {
                    puts("[ERROR] Could not execute the first some steps");
                    exit(-1);
                }            
            }else {
                if(uc_emu_start(uc, pc , 0, 0, 0)) {
                    puts("[ERROR] Could not execute the first some steps");
                    exit(-1);
                }
            }
        }
        puts("[+] Initial constant execution (including optional prefix input) done, starting input execution."); fflush(stdout);
    } else {
        // child: Run until we hit an input consumption
        is_discovery_child = 1;
        uc_err child_emu_status;
        if (g_arch == UC_ARCH_ARM) {
            child_emu_status = uc_emu_start(uc, pc | 1, 0, 0, 0);
        }else{
            child_emu_status = uc_emu_start(uc, pc , 0, 0, 0);
        }
        // We do not expect to get here. The child should exit by itself in get_fuzz
        printf("[ERROR] Emulation stopped using just the prefix input (%d: %s)\n", child_emu_status, uc_strerror(child_emu_status));

        // Write wrong amount of data to notify parent of failure
        if(write(pipe_to_parent[1], emulate, 1) != 1) {
            puts("[Discovery Child] Error: Could not notify parent of failure..."); fflush(stdout);
        }
        _exit(-1);
    }

    // Set the proper instruction limit (after using a fake one to execute exec prefix)
    set_timer_reload_val(instr_limit_timer_id, instr_limit);
    
    trigger_snapshotting(uc);
    
    struct snapshotting_state_t* state = get_global_snapshotting(uc);
    
    initial_state.num_used = state->num_used;
    initial_state.num_allocated = state->num_allocated;
    initial_state.snapshots = calloc(initial_state.num_allocated, sizeof(*initial_state.snapshots));
    
    for(int i = 0; i < state->num_used; ++i) {
        initial_state.snapshots[i] = state->snapshots[i];
    }
    return UC_ERR_OK;
}

uc_err restore_snapshot_initial(uc_engine *uc) {
    // we must free current snapshot?
    //trigger_teardown(uc);
    struct snapshotting_state_t* state = get_global_snapshotting(uc);
    
    state->num_used = initial_state.num_used;
    state->num_allocated = initial_state.num_allocated;
    state->snapshots = calloc(state->num_allocated, sizeof(*state->snapshots));
    
    for(int i = 0; i < state->num_used; ++i) {
        state->snapshots[i] = initial_state.snapshots[i];
    }
#ifdef SMART_STREAM
    init_CircularQueue(&last_read_mmio);
#endif
    restore_snapshot(uc);
    return UC_ERR_OK;
}

