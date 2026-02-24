/*
  Copyright 2013 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - fuzzer code
   --------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

*/

#define AFL_MAIN
#include "android-ashmem.h"
#define MESSAGES_TO_STDOUT

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _FILE_OFFSET_BITS 64

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"
#include "../stream.h"
#include "../state_snapshotting.h"
#include "../fuzzware_mmio_model.h"
#include "cmplog.h"
#include "unicorn/unicorn.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <termios.h>
#include <dlfcn.h>
#include <sched.h>

#ifndef USEMMAP
#include <sys/ipc.h>
#endif

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/file.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)
#  include <sys/sysctl.h>
#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

/* For systems that have sched_setaffinity; right now just Linux, but one
   can hope... */

#ifdef __linux__
#  define HAVE_AFFINITY 1
#endif /* __linux__ */

/* A toggle to export some variables when building as a library. Not very
   useful for the general public. */

#ifdef AFL_LIB
#  define EXP_ST
#else
#  define EXP_ST static
#endif /* ^AFL_LIB */

/* Lots of globals, but mostly for the status UI and other things where it
   really makes no sense to haul them around as function parameters. */


EXP_ST u8 *in_dir,                    /* Input directory with test cases  */
          *out_file,                  /* File to fuzz, if any             */
          *out_dir,                   /* Working & output directory       */
          *sync_dir,                  /* Synchronization directory        */
          *use_banner,                /* Display banner                   */
          *in_bitmap,                 /* Input bitmap                     */
          *orig_cmdline;              /* Original command line            */

EXP_ST u32 exec_tmout = EXEC_TIMEOUT; /* Configurable exec timeout (ms)   */
static u32 hang_tmout = EXEC_TIMEOUT; /* Timeout used for hang det (ms)   */

EXP_ST u64 mem_limit  = MEM_LIMIT;    /* Memory cap for child (MB)        */

EXP_ST u32 cpu_to_bind = 0;           /* id of free CPU core to bind      */

static u32 stats_update_freq = 1;     /* Stats update frequency (execs)   */

EXP_ST u8  skip_deterministic,        /* Skip deterministic stages?       */
           force_deterministic,       /* Force deterministic stages?      */
           use_splicing,              /* Recombine input files?           */
           dumb_mode,                 /* Run in non-instrumented mode?    */
           score_changed,             /* Scoring for favorites changed?   */
           kill_signal,               /* Signal that killed the child     */
           resuming_fuzz,             /* Resuming an older fuzzing job?   */
           timeout_given,             /* Specific timeout given?          */
           cpu_to_bind_given,         /* Specified cpu_to_bind given?     */
           not_on_tty,                /* stdout is not a tty              */
           term_too_small,            /* terminal dimensions too small    */
           uses_asan,                 /* Target uses ASAN?                */
           no_forkserver,             /* Disable forkserver?              */
           crash_mode,                /* Crash mode! Yeah!                */
           in_place_resume,           /* Attempt in-place resume?         */
           auto_changed,              /* Auto-generated tokens changed?   */
           no_cpu_meter_red,          /* Feng shui on the status screen   */
           no_arith,                  /* Skip most arithmetic ops         */
           shuffle_queue,             /* Shuffle input queue?             */
           bitmap_changed = 1,        /* Time to update bitmap?           */
           qemu_mode,                 /* Running in QEMU mode?            */
           skip_requested,            /* Skip request, via SIGUSR1        */
           run_over10m,               /* Run time over 10 minutes?        */
           persistent_mode,           /* Running in persistent mode?      */
           deferred_mode,             /* Deferred forkserver mode?        */
           fast_cal;                  /* Try to calibrate faster?         */

static s32 out_fd,                    /* Persistent fd for out_file       */
           dev_urandom_fd = -1,       /* Persistent fd for /dev/urandom   */
           dev_null_fd = -1,          /* Persistent fd for /dev/null      */
           fsrv_ctl_fd,               /* Fork server control pipe (write) */
           fsrv_st_fd;                /* Fork server status pipe (read)   */

static s32 child_pid = -1,            /* PID of the fuzzed program        */
           out_dir_fd = -1;           /* FD of the lock file              */

EXP_ST u8* trace_bits;                /* SHM with instrumentation bitmap  */

EXP_ST u8  virgin_bits[MAP_SIZE],     /* Regions yet untouched by fuzzing */
           virgin_tmout[MAP_SIZE],    /* Bits we haven't seen in tmouts   */
           virgin_crash[MAP_SIZE];    /* Bits we haven't seen in crashes  */

static u8  var_bytes[MAP_SIZE];       /* Bytes that appear to be variable */

#ifndef USEMMAP
static s32 shm_id;                    /* ID of the SHM region             */
#endif
static volatile u8 stop_soon,         /* Ctrl-C pressed?                  */
                   clear_screen = 1,  /* Window resized?                  */
                   child_timed_out;   /* Traced process timed out?        */

EXP_ST u32 queued_paths,              /* Total number of queued testcases */
           queued_variable,           /* Testcases with variable behavior */
           queued_at_start,           /* Total number of initial inputs   */
           queued_discovered,         /* Items discovered during this run */
           queued_imported,           /* Items imported via -S            */
           queued_favored,            /* Paths deemed favorable           */
           queued_with_cov,           /* Paths with new coverage bytes    */
           pending_not_fuzzed,        /* Queued but not done yet          */
           pending_favored,           /* Pending favored paths            */
           cur_skipped_paths,         /* Abandoned inputs in cur cycle    */
           cur_depth,                 /* Current path depth               */
           max_depth,                 /* Max path depth                   */
           useless_at_start,          /* Number of useless starting paths */
           var_byte_count,            /* Bitmap bytes with var behavior   */
           current_entry,             /* Current queue entry ID           */
           havoc_div = 1;             /* Cycle count divisor for havoc    */

EXP_ST u64 total_crashes,             /* Total number of crashes          */
           unique_crashes,            /* Crashes with unique signatures   */
           total_tmouts,              /* Total number of timeouts         */
           unique_tmouts,             /* Timeouts with unique signatures  */
           unique_hangs,              /* Hangs with unique signatures     */
           total_execs,               /* Total execve() calls             */
           slowest_exec_ms,           /* Slowest testcase non hang in ms  */
           start_time,                /* Unix start time (ms)             */
           last_path_time,            /* Time for most recent path (ms)   */
           last_crash_time,           /* Time for most recent crash (ms)  */
           last_hang_time,            /* Time for most recent hang (ms)   */
           last_crash_execs,          /* Exec counter at last crash       */
           queue_cycle,               /* Queue round counter              */
           cycles_wo_finds,           /* Cycles without any new paths     */
           trim_execs,                /* Execs done to trim input files   */
           bytes_trim_in,             /* Bytes coming into the trimmer    */
           bytes_trim_out,            /* Bytes coming outa the trimmer    */
           blocks_eff_total,          /* Blocks subject to effector maps  */
           blocks_eff_select;         /* Blocks selected as fuzzable      */

static u32 subseq_tmouts;             /* Number of timeouts in a row      */

static char *stage_name = "init",       /* Name of the current fuzz stage   */
          *stage_short,               /* Short stage name                 */
          *syncing_party;             /* Currently syncing with...        */

static s32 stage_cur, stage_max;      /* Stage progression                */
static s32 splicing_with = -1;        /* Splicing with which test case?   */

static u32 master_id, master_max;     /* Master instance job splitting    */

static u32 syncing_case;              /* Syncing with case #...           */

static s32 stage_cur_byte,            /* Byte offset of current stage op  */
           stage_cur_val;             /* Value used for stage op          */

static u8  stage_val_type;            /* Value type (STAGE_VAL_*)         */

static u64 stage_finds[32],           /* Patterns found per fuzz stage    */
           stage_cycles[32];          /* Execs per fuzz stage             */

static u32 rand_cnt;                  /* Random number counter            */

static u64 total_cal_us,              /* Total calibration time (us)      */
           total_cal_cycles;          /* Total calibration cycles         */

static u64 total_bitmap_size,         /* Total bit count for all bitmaps  */
           total_bitmap_entries;      /* Number of bitmaps counted        */

static s32 cpu_core_count;            /* CPU core count                   */

#ifdef HAVE_AFFINITY

static s32 cpu_aff = -1;       	      /* Selected CPU core                */

#endif /* HAVE_AFFINITY */

static FILE* plot_file;               /* Gnuplot output file              */

struct queue_entry {

  char* fname;                        /* File name for the test case      */
  u32 len;                            /* Input length                     */

  u8  cal_failed,                     /* Calibration failed?              */
      trim_done,                      /* Trimmed?                         */
      was_fuzzed,                     /* Had any fuzzing done yet?        */
      passed_det,                     /* Deterministic stages passed?     */
      has_new_cov,                    /* Triggers new coverage?           */
      var_behavior,                   /* Variable behavior?               */
      favored,                        /* Currently favored?               */
      fs_redundant;                   /* Marked as redundant in the fs?   */

  u32 bitmap_size,                    /* Number of bits set in bitmap     */
      exec_cksum;                     /* Checksum of the execution trace  */

  u64 exec_us,                        /* Execution time (us)              */
      handicap,                       /* Number of queue cycles behind    */
      depth;                          /* Path depth                       */

  u8* trace_mini;                     /* Trace bytes, if kept             */
  u32 tc_ref;                         /* Trace bytes ref count            */

  struct queue_entry *next,           /* Next element, if any             */
                     *next_100;       /* 100 elements ahead               */
  
  u32 num_mmios;                      /* when use stream                   */ 

  void *fti_info;

};

static struct queue_entry *queue,     /* Fuzzing queue (linked list)      */
                          *queue_cur, /* Current offset within the queue  */
                          *queue_top, /* Top of the list                  */
                          *q_prev100; /* Previous 100 marker              */

static struct queue_entry*
  top_rated[MAP_SIZE];                /* Top entries for bitmap bytes     */

struct extra_data {
  u8* data;                           /* Dictionary token data            */
  u32 len;                            /* Dictionary token length          */
  u32 hit_cnt;                        /* Use count in the corpus          */
};

static struct extra_data* extras;     /* Extra tokens to fuzz with        */
static u32 extras_cnt;                /* Total number of tokens read      */

static struct extra_data* a_extras;   /* Automatically selected extras    */
static u32 a_extras_cnt;              /* Total number of tokens available */

static u8* (*post_handler)(u8* buf, u32* len);

static void extend_stream_single(struct queue_entry* q);


/* Interesting values, as per config.h */

static s8  interesting_8[]  = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };

/*https://github.com/Proteas/afl-ios/blob/ios-afl-clang-fast/afl-fuzz.c*/ 
/* ================ Proteas ================ */
#ifdef USEMMAP
static int g_shm_fd = -1;
static unsigned char *g_shm_base = NULL;
static char *g_shm_file_path = NULL;
#endif
/* ========================================= */

/* Fuzzing stages */

enum {
  /* 00 */ STAGE_FLIP1,
  /* 01 */ STAGE_FLIP2,
  /* 02 */ STAGE_FLIP4,
  /* 03 */ STAGE_FLIP8,
  /* 04 */ STAGE_FLIP16,
  /* 05 */ STAGE_FLIP32,
  /* 06 */ STAGE_ARITH8,
  /* 07 */ STAGE_ARITH16,
  /* 08 */ STAGE_ARITH32,
  /* 09 */ STAGE_INTEREST8,
  /* 10 */ STAGE_INTEREST16,
  /* 11 */ STAGE_INTEREST32,
  /* 12 */ STAGE_EXTRAS_UO,
  /* 13 */ STAGE_EXTRAS_UI,
  /* 14 */ STAGE_EXTRAS_AO,
  /* 15 */ STAGE_HAVOC,
  /* 16 */ STAGE_SPLICE,
  /* 17 */ STAGE_EXTEND,
  /* 18 */ STAGE_FTI,
  /* 19 */ STAGE_COLORIZATION,
  /* 20 */ STAGE_ITS
};

/* Stage value types */

enum {
  /* 00 */ STAGE_VAL_NONE,
  /* 01 */ STAGE_VAL_LE,
  /* 02 */ STAGE_VAL_BE
};

/* Execution status fault codes */

enum {
  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_TMOUT,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,
  /* 04 */ FAULT_NOINST,
  /* 05 */ FAULT_NOBITS
};



struct transform_operands {
  u32 reverse : 8;
  u32 shape : 8;
  u32 transform : 8;
  u32 arith : 8;
};

struct I2S_CK {
  u32 is_v0;                     /* v0 or v1       */
  u32 key;                       /* cmplog key     */
  u32 idx;                       /* input idx      */
  u32 hits;                      /* hits in cmplog */
  struct transform_operands t_op;/* trans op       */
  struct I2S_CK* prev;           /* prev           */
  struct I2S_CK* next;           /* next           */
};

struct tainted {
  u32             pos;
  u32             len;
  struct tainted *next;
  struct tainted *prev;
};

struct fti_taint{
  u32 num_byte;
  u32 num_branch;
  u64 mask_num;
  u32 mask_buf_len;
  u8* mask_buf;
  u8 colorized;                       /* Do not run redqueen stage again  */
  u8*  cmplog_colorinput;             /* the result buf of colorization   */
  struct tainted *taint;              /* Taint information from CmpLog    */
  struct I2S_CK* I2S;                 /* Maybe checksum?                  */
};


struct byte_cmp{
  u32 idx;
  u32 h;
  bool v1d;
  bool v0d;
};

struct stream_byte_cmps{
  struct byte_cmp* byte_cmp;
  u32 count;
};


struct passthrough_mmio_model_config* is_passthrough_model(u64 pc, u64 addr){
    for (int i = 0; i < passthrough_model_size; ++i) {      
        if (pc == passthrough_model[i].pc && addr == passthrough_model[i].start_addr){
            return &passthrough_model[i];
        }
    }
    return NULL;
}

struct constant_mmio_model_config* is_constant_model(u64 pc, u64 addr){
    for (int i = 0; i < constant_model_size; ++i) {      
        if (pc == constant_model[i].pc && addr == constant_model[i].start_addr){
            return &constant_model[i];
        }
    }
    return NULL;
}

struct bitextract_mmio_model_config* is_bitextract_model(u64 pc, u64 addr){
    for (int i = 0; i < bitextract_model_size; ++i) {      
        if (pc == bitextract_model[i].pc && addr == bitextract_model[i].start_addr){
            return &bitextract_model[i];
        }
    }
    return NULL;
}

struct value_set_mmio_model_config* is_value_set_model(u64 pc, u64 addr){
    for (int i = 0; i < value_set_model_size; ++i) {      
        if (pc == value_set_model[i].pc && addr == value_set_model[i].start_addr){
            return &value_set_model[i];
        }
    }
    return NULL;
}

struct fti_info{
  khash_t(PTR) *visited;
  khash_t(PTR) *direct;
  khash_t(PTR) *indirect;
};

void init_fti_info(struct fti_info* fti) {
  fti->visited = kh_init(PTR);
  fti->direct = kh_init(PTR);
  fti->indirect = kh_init(PTR);
};

void add_visited_fti_info(struct fti_info* fti, u64 mmio_id){
  khiter_t k = kh_get(PTR, fti->visited, mmio_id);
  
  if (k == kh_end(fti->visited)) {
    int kh_res;
    k = kh_put(PTR, fti->visited, mmio_id, &kh_res);
    kh_value(fti->visited, k) = NULL;
  }
  
};

bool is_visited_fti_info(struct fti_info* fti, u64 mmio_id) {
  khiter_t k = kh_get(PTR, fti->visited, mmio_id);
  
  if (k == kh_end(fti->visited)) {
    return false;
  }else{
    if(kh_exist(fti->visited, k)) {
       return true;
    }
    return false;
  }
};

struct stream_byte_cmps* get_stream_byte_cmps(khash_t(PTR) *cmp_set, u64 cmp_id, u64 mmio_id){
  khiter_t k = kh_get(PTR, cmp_set, cmp_id);
  
  khash_t(PTR) *stream_cmp_set = NULL;
  
  if (k != kh_end(cmp_set)) {
    if(kh_exist(cmp_set, k)) {
       stream_cmp_set = kh_value(cmp_set, k);
    }
  }else{
    stream_cmp_set = kh_init(PTR);
    
    int kh_res;
    k = kh_put(PTR, cmp_set, cmp_id, &kh_res);
    kh_value(cmp_set, k) = stream_cmp_set;
  }
  
  
  k = kh_get(PTR, stream_cmp_set, mmio_id);
  
  struct stream_byte_cmps* ret = NULL;
  
  if (k != kh_end(stream_cmp_set)) {
    if(kh_exist(stream_cmp_set, k)) {
       ret = kh_value(stream_cmp_set, k);
    }
  }else{
    ret = ck_alloc(sizeof(struct stream_byte_cmps));
    ret->byte_cmp = NULL;
    ret->count = 0;
    
    int kh_res;
    k = kh_put(PTR, stream_cmp_set, mmio_id, &kh_res);
    kh_value(stream_cmp_set, k) = ret;
  }
  
  return ret;
}

struct stream_byte_cmps* get_direct_fti_info(struct fti_info* fti, u64 cmp_id, u64 mmio_id) {
  return get_stream_byte_cmps(fti->direct, cmp_id, mmio_id);
}

bool add_direct_fti_info(struct fti_info* fti, u64 cmp_id, u64 mmio_id, u32 idx, u32 h, bool v0d, bool v1d) {
  struct stream_byte_cmps* byte_cmps = get_stream_byte_cmps(fti->direct, cmp_id, mmio_id);
  
  for(int i=0;i<byte_cmps->count;i++){
    if(byte_cmps->byte_cmp[i].idx == idx) {
      return false;
    }
  }
  
  byte_cmps->count++;
  byte_cmps->byte_cmp = ck_realloc(byte_cmps->byte_cmp, byte_cmps->count * sizeof(struct byte_cmp));
  byte_cmps->byte_cmp[byte_cmps->count-1].idx = idx;
  byte_cmps->byte_cmp[byte_cmps->count-1].h = h;
  byte_cmps->byte_cmp[byte_cmps->count-1].v0d = v0d;
  byte_cmps->byte_cmp[byte_cmps->count-1].v1d = v1d;
  return true;
  
}

struct stream_byte_cmps* get_indirect_fti_info(struct fti_info* fti, u64 cmp_id, u64 mmio_id) {
  return get_stream_byte_cmps(fti->indirect, cmp_id, mmio_id);
}

bool add_indirect_fti_info(struct fti_info* fti, u64 cmp_id, u64 mmio_id, u32 idx, u32 h, bool v0d, bool v1d) {
  struct stream_byte_cmps* byte_cmps = get_stream_byte_cmps(fti->indirect, cmp_id, mmio_id);
  
  for(int i=0;i<byte_cmps->count;i++){
    if(byte_cmps->byte_cmp[i].idx == idx) {
      return false;
    }
  }
  
  byte_cmps->count++;
  byte_cmps->byte_cmp = ck_realloc(byte_cmps->byte_cmp, byte_cmps->count * sizeof(struct byte_cmp));
  byte_cmps->byte_cmp[byte_cmps->count-1].idx = idx;
  byte_cmps->byte_cmp[byte_cmps->count-1].h = h;
  byte_cmps->byte_cmp[byte_cmps->count-1].v0d = v0d;
  byte_cmps->byte_cmp[byte_cmps->count-1].v1d = v1d;
  return true;
  
}

void debug_fti_info(struct fti_info* fti, FILE *file) {
  
  khiter_t k,kk;
  
  fprintf(file,"visited:\n");
  for (k = kh_begin(fti->visited); k != kh_end(fti->visited); ++k){
    if (kh_exist(fti->visited, k)) {
      fprintf(file, "  mmio_id:%016lx\n", kh_key(fti->visited, k));             
    }
  }
  
  fprintf(file,"direct:\n");
  for (k = kh_begin(fti->direct); k != kh_end(fti->direct); ++k){
    if (kh_exist(fti->direct, k)) {
      fprintf(file, "  cmpid:%d\n", kh_key(fti->direct, k));
      khash_t(PTR) *stream_cmp_set = kh_value(fti->direct, k);
      
      for (kk = kh_begin(stream_cmp_set); kk != kh_end(stream_cmp_set); ++kk) {
        if (kh_exist(stream_cmp_set, kk)) {
          fprintf(file, "    mmio_id:%016lx\n", kh_key(stream_cmp_set, kk));
          struct stream_byte_cmps* cmps = kh_value(stream_cmp_set, kk);
          
          for(int i=0;i<cmps->count;i++){
            fprintf(file, "        idx:%d v0d:%d v1d:%d\n",cmps->byte_cmp[i].idx, cmps->byte_cmp[i].v0d, cmps->byte_cmp[i].v1d);
          }
        }
      }             
    }
  }
  
  fprintf(file,"indirect:\n");
  for (k = kh_begin(fti->indirect); k != kh_end(fti->indirect); ++k){
    if (kh_exist(fti->indirect, k)) {
      fprintf(file, "  cmpid:%d\n", kh_key(fti->indirect, k));
      khash_t(PTR) *stream_cmp_set = kh_value(fti->indirect, k);
      
      for (kk = kh_begin(stream_cmp_set); kk != kh_end(stream_cmp_set); ++kk) {
        if (kh_exist(stream_cmp_set, kk)) {
          fprintf(file, "    mmio_id:%016lx\n", kh_key(stream_cmp_set, kk));
          struct stream_byte_cmps* cmps = kh_value(stream_cmp_set, kk);
          
          for(int i=0;i<cmps->count;i++){
            fprintf(file, "        idx:%d v0d:%d v1d:%d\n",cmps->byte_cmp[i].idx, cmps->byte_cmp[i].v0d, cmps->byte_cmp[i].v1d);
          }
        }
      }             
    }
  }
}

struct stream_cmps {
  u32 count;
  khash_t(PTR) *cmps;
};

struct cmp_info {
  khash_t(PTR) *touched;
  khash_t(PTR) *untouched;
  khash_t(PTR) *stream_cmps_info;
};

struct cmp_attr {
  u32 count;
  u32 attr;
  u32 type;
  u32 shape;
};

struct cmp_info g_cmp_info;

void init_cmp_info(struct cmp_info* cmp_info) {
  cmp_info->touched = kh_init(PTR);
  cmp_info->untouched = kh_init(PTR);
  cmp_info->stream_cmps_info = kh_init(PTR);
};



struct cmp_attr* get_touched(struct cmp_info* cmp_info, u64 cmp_id) {
  khiter_t k = kh_get(PTR, cmp_info->touched, cmp_id);
  
  if (k != kh_end(cmp_info->touched)) {
    if(kh_exist(cmp_info->touched, k)) {
       return kh_value(cmp_info->touched, k);
    }
  }
  
  return NULL;
};

struct cmp_attr* get_untouched(struct cmp_info* cmp_info, u64 cmp_id) {
  khiter_t k = kh_get(PTR, cmp_info->untouched, cmp_id);
  
  if (k != kh_end(cmp_info->untouched)) {
    if(kh_exist(cmp_info->untouched, k)) {
       return kh_value(cmp_info->untouched, k);
    }
  }
  
  return NULL;
};

khash_t(PTR) *get_stream_cmps_info(struct cmp_info* cmp_info, u64 mmio_id) {
  khiter_t k = kh_get(PTR, cmp_info->stream_cmps_info, mmio_id);
  
  khash_t(PTR) *cmps_info = NULL;
  
  if (k != kh_end(cmp_info->stream_cmps_info)) {
    if(kh_exist(cmp_info->stream_cmps_info, k)) {
       return kh_value(cmp_info->stream_cmps_info, k);
    }
  }

    
  int kh_res;
  k = kh_put(PTR, cmp_info->stream_cmps_info, mmio_id, &kh_res);
  kh_value(cmp_info->stream_cmps_info, k) = kh_init(PTR);
  
  return kh_value(cmp_info->stream_cmps_info, k);
}

void add_stream_cmps_info(struct cmp_info* cmp_info, u64 mmio_id, u64 cmp_id){

  khash_t(PTR) *cmps_info = get_stream_cmps_info(cmp_info, mmio_id);
  khiter_t k = kh_get(PTR, cmps_info, cmp_id);
  
  if (k == kh_end(cmps_info) || !kh_exist(cmps_info, k)) {
    int kh_res;
    k = kh_put(PTR, cmps_info, cmp_id, &kh_res);
    kh_value(cmps_info, k) = cmp_id;
  }
  
};

bool add_touched(struct cmp_info* cmp_info, u64 cmp_id, u32 count, u32 attr, u32 type, u32 shape) {
  bool ret = true;
  
  
  struct cmp_attr* cmp = get_touched(cmp_info, cmp_id);
  
  if (cmp == NULL) {
    ret = false;
    cmp = malloc(sizeof(struct cmp_attr));
    memset(cmp, 0, sizeof(struct cmp_attr));
    khiter_t k = kh_get(PTR, cmp_info->touched, cmp_id);
    
    int kh_res;
    k = kh_put(PTR, cmp_info->touched, cmp_id, &kh_res);
    
    kh_value(cmp_info->touched, k) = cmp;
  }
  
  cmp->count += count;
  cmp->attr = attr;
  cmp->type = type;
  cmp->shape = shape;
  
  return ret;
};

bool add_untouched(struct cmp_info* cmp_info, u64 cmp_id, u32 count, u32 attr, u32 type, u32 shape) {
  bool ret = true;
  
  
  struct cmp_attr* cmp = get_untouched(cmp_info, cmp_id);
  
  if (cmp == NULL) {
    ret = false;
    cmp = malloc(sizeof(struct cmp_attr));
    memset(cmp, 0, sizeof(struct cmp_attr));
    khiter_t k = kh_get(PTR, cmp_info->untouched, cmp_id);
    
    int kh_res;
    k = kh_put(PTR, cmp_info->untouched, cmp_id, &kh_res);
    
    kh_value(cmp_info->untouched, k) = cmp;
  }
  cmp->count += count;
  cmp->attr = attr;
  cmp->type = type;
  cmp->shape = shape;  
  
  return ret;
};

struct schedule_stream_info {
  u32 success;
  u32 total;
};

struct schedule_info {
  u32 num_streams;
  khash_t(PTR) *stream_info;
};

struct schedule_info g_schedule_info;

void init_schedule_info(){
  g_schedule_info.num_streams = 0;
  g_schedule_info.stream_info = kh_init(PTR);
};

bool insert_schedule_info(u64 mmio){
  
  if (g_schedule_info.stream_info == NULL) {
    return false;
  }
  
  khiter_t k = kh_get(PTR, g_schedule_info.stream_info, mmio);
  
  
  if (k != kh_end(g_schedule_info.stream_info)) {
    return true;
  }else{
    int kh_res;
    k = kh_put(PTR, g_schedule_info.stream_info, mmio, &kh_res);
    
    struct schedule_stream_info* stream_info = malloc(sizeof(struct schedule_stream_info));
    stream_info->success = 1;
    stream_info->total = 1;
    
    kh_value(g_schedule_info.stream_info, k) = stream_info;
    g_schedule_info.num_streams++;
    return true;
  }
};

bool add_schedule_info(u64 mmio, u32 success, u32 total) {
  if (g_schedule_info.stream_info == NULL) {
    return false;
  }
  
  khiter_t k = kh_get(PTR, g_schedule_info.stream_info, mmio);
  
  if (k == kh_end(g_schedule_info.stream_info)) {
    if(insert_schedule_info(mmio)){
      k = kh_get(PTR, g_schedule_info.stream_info, mmio);
    }else{
      return false;
    };
  }
  
  if(kh_exist(g_schedule_info.stream_info, k)) {
    struct schedule_stream_info* stream_info = kh_value(g_schedule_info.stream_info, k);
    stream_info->success += success;
    stream_info->total += total;
    return true;
  }else{
    return false;
  }
  
};


u64 schedule(u64* mmios, u32 len_mmios){
  
  u64 ret_mmio = mmios[random() % len_mmios];
  if(random() % 10 < 2){
    return ret_mmio;
  }
  
  float p_max = 0.0;
  khiter_t k = kh_get(PTR, g_schedule_info.stream_info, ret_mmio);
  
  if (k != kh_end(g_schedule_info.stream_info)) {
    if(kh_exist(g_schedule_info.stream_info, k)) {
      struct schedule_stream_info* stream_info = kh_value(g_schedule_info.stream_info, k);
      
      p_max = ((float)stream_info->success)/((float)stream_info->total);
    }
  }
    
    
  
  for (int i=0;i<len_mmios;i++){
    u64 cur_mmio = mmios[i];
    
    k = kh_get(PTR, g_schedule_info.stream_info, cur_mmio);
  
    if (k == kh_end(g_schedule_info.stream_info)) {
      continue;
    }
    
    if(kh_exist(g_schedule_info.stream_info, k)) {
      struct schedule_stream_info* stream_info = kh_value(g_schedule_info.stream_info, k);
      
      float cur_p = ((float)stream_info->success)/((float)stream_info->total);
      if (cur_p > p_max) {
        p_max = cur_p;
        ret_mmio = cur_mmio;
      }
    }
    
  }

#ifdef _DEBUG
  fprintf(stderr,"select mmio:%016lx\n",ret_mmio);
#endif
  return ret_mmio;
  
};

struct range {
  u32           start;
  u32           end;
  struct range *next;
  struct range *prev;
  u8            ok;
};

struct afl_pass_stat {
  u8 total;
  u8 faileds;
};

// CMPLOG LVL
enum {
  LVL1 = 1,  // Integer solving
  LVL2 = 2,  // unused except for setting the queue entry
  LVL3 = 4   // expensive tranformations
};

struct afl_pass_stat* pass_stats = NULL;

extern uint32_t cov_mode;
extern uint32_t cmplog_mode;
extern uint32_t use_stream;
extern uint32_t fix_checksum_mode;
extern uint32_t smart_stream;
extern uint32_t its_mode;

u32 colorize_success = 0;

extern uint8_t  fuzz_area_initial[MAP_SIZE];
extern uint8_t  fuzz_area_initial_backup[MAP_SIZE];
extern uint8_t *fuzz_area_ptr_backup;
extern uint8_t *fuzz_area_ptr;

extern struct stream_feedback stream_map_initial;
extern struct stream_feedback stream_map_initial_backup;
extern struct stream_feedback* stream_map;

extern struct cmp_map fuzz_cmp_map_initial;
extern struct cmp_map fuzz_cmp_map_initial_backup;
extern struct cmp_map *fuzz_cmp_map;

extern uc_err snapshot_initial(uc_engine *uc);
extern int run_single(uc_engine *uc);
extern uc_err restore_snapshot_initial(uc_engine *uc);

extern uc_err arch_get_pc(uc_engine *uc, void *value);

extern uint32_t instr_limit_timer_id;
extern uint64_t instr_limit;

extern int duplicate_exit;

uc_engine *g_uc = 0;

uint32_t enable_merge_stream = 0;
struct stream_feedback* stream_bits;
struct cmp_map* cmplog_ptr = NULL;
struct cmp_map cmplog_backup;
struct cmp_map cmplog_backup2;

#ifndef USEMMAP
static s32 stream_shm_id;                    /* ID of the stream SHM region             */
static s32 cmplog_shm_id;                    /* ID of the cmplog SHM region             */
#endif


static bool is_printable(uint8_t c){
  if(c > 126)
    return false;
  if(c > 31)
    return true;
  if(c == 9 || c == 10 || c == 13)
    return true;
  return false;
}

/* Get unix time in milliseconds */
static u64 get_cur_time(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}


/* Get unix time in microseconds */

static u64 get_cur_time_us(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;

}


/* Generate a random number (from 0 to limit - 1). This may
   have slight bias. */

static inline u32 UR(u32 limit) {

  if (unlikely(!rand_cnt--)) {

    u32 seed[2];

    ck_read(dev_urandom_fd, &seed, sizeof(seed), "/dev/urandom");

    srandom(seed[0]);
    rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);

  }

  return random() % limit;

}


/* Shuffle an array of pointers. Might be slightly biased. */

static void shuffle_ptrs(void** ptrs, u32 cnt) {

  u32 i;

  for (i = 0; i < cnt - 2; i++) {

    u32 j = i + UR(cnt - i);
    void *s = ptrs[i];
    ptrs[i] = ptrs[j];
    ptrs[j] = s;

  }

}


#ifdef HAVE_AFFINITY

/* Build a list of processes bound to specific cores. Returns -1 if nothing
   can be found. Assumes an upper bound of 4k CPUs. */

static void bind_to_free_cpu(void) {

  DIR* d;
  struct dirent* de;
  cpu_set_t c;

  u8 cpu_used[4096] = { 0 };
  u32 i;

  if (cpu_core_count < 2) return;

  if (getenv("AFL_NO_AFFINITY")) {

    WARNF("Not binding to a CPU core (AFL_NO_AFFINITY set).");
    return;

  }

  d = opendir("/proc");

  if (!d) {

    WARNF("Unable to access /proc - can't scan for free CPU cores.");
    return;

  }

  ACTF("Checking CPU core loadout...");

  /* Introduce some jitter, in case multiple AFL tasks are doing the same
     thing at the same time... */

  usleep(R(1000) * 250);

  /* Scan all /proc/<pid>/status entries, checking for Cpus_allowed_list.
     Flag all processes bound to a specific CPU using cpu_used[]. This will
     fail for some exotic binding setups, but is likely good enough in almost
     all real-world use cases. */

  while ((de = readdir(d))) {

    char* fn;
    FILE* f;
    char tmp[MAX_LINE];
    u8 has_vmsize = 0;

    if (!isdigit(de->d_name[0])) continue;

    fn = (char*)alloc_printf("/proc/%s/status", de->d_name);

    if (!(f = fopen(fn, "r"))) {
      ck_free(fn);
      continue;
    }

    while (fgets(tmp, MAX_LINE, f)) {

      u32 hval;

      /* Processes without VmSize are probably kernel tasks. */

      if (!strncmp(tmp, "VmSize:\t", 8)) has_vmsize = 1;

      if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) &&
          !strchr(tmp, '-') && !strchr(tmp, ',') &&
          sscanf(tmp + 19, "%u", &hval) == 1 && hval < sizeof(cpu_used) &&
          has_vmsize) {

        cpu_used[hval] = 1;
        break;

      }

    }

    ck_free(fn);
    fclose(f);

  }

  closedir(d);
  if (cpu_to_bind_given) {

    if (cpu_to_bind >= cpu_core_count)
      FATAL("The CPU core id to bind should be between 0 and %u", cpu_core_count - 1);
    
    if (cpu_used[cpu_to_bind])
      FATAL("The CPU core #%u to bind is not free!", cpu_to_bind);

    i = cpu_to_bind;
    
  } else {

    for (i = 0; i < cpu_core_count; i++) if (!cpu_used[i]) break;
    
  }

  if (i == cpu_core_count) {

    SAYF("\n" cLRD "[-] " cRST
         "Uh-oh, looks like all %u CPU cores on your system are allocated to\n"
         "    other instances of afl-fuzz (or similar CPU-locked tasks). Starting\n"
         "    another fuzzer on this machine is probably a bad plan, but if you are\n"
         "    absolutely sure, you can set AFL_NO_AFFINITY and try again.\n",
         cpu_core_count);

    FATAL("No more free CPU cores");

  }

  OKF("Found a free CPU core, binding to #%u.", i);

  cpu_aff = i;

  CPU_ZERO(&c);
  CPU_SET(i, &c);

  if (sched_setaffinity(0, sizeof(c), &c))
    PFATAL("sched_setaffinity failed");

}

#endif /* HAVE_AFFINITY */

#ifndef IGNORE_FINDS

/* Helper function to compare buffers; returns first and last differing offset. We
   use this to find reasonable locations for splicing two files. */

static void locate_diffs(u8* ptr1, u8* ptr2, u32 len, s32* first, s32* last) {

  s32 f_loc = -1;
  s32 l_loc = -1;
  u32 pos;

  for (pos = 0; pos < len; pos++) {

    if (*(ptr1++) != *(ptr2++)) {

      if (f_loc == -1) f_loc = pos;
      l_loc = pos;

    }

  }

  *first = f_loc;
  *last = l_loc;

  return;

}

#endif /* !IGNORE_FINDS */


/* Describe integer. Uses 12 cyclic static buffers for return values. The value
   returned should be five characters or less for all the integers we reasonably
   expect to see. */

static u8* DI(u64 val) {

  static u8 tmp[12][16];
  static u8 cur;

  cur = (cur + 1) % 12;

#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast) do { \
    if (val < (_divisor) * (_limit_mult)) { \
      sprintf((char*)tmp[cur], _fmt, ((_cast)val) / (_divisor)); \
      return tmp[cur]; \
    } \
  } while (0)

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1000, 99.95, "%0.01fk", double);

  /* 100k - 999k */
  CHK_FORMAT(1000, 1000, "%lluk", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1000 * 1000, 9.995, "%0.02fM", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1000 * 1000, 99.95, "%0.01fM", double);

  /* 100M - 999M */
  CHK_FORMAT(1000 * 1000, 1000, "%lluM", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000, 9.995, "%0.02fG", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1000LL * 1000 * 1000, 99.95, "%0.01fG", double);

  /* 100G - 999G */
  CHK_FORMAT(1000LL * 1000 * 1000, 1000, "%lluG", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 9.995, "%0.02fT", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 99.95, "%0.01fT", double);

  /* 100T+ */
  strcpy((char*)tmp[cur], "infty");
  return tmp[cur];

}


/* Describe float. Similar to the above, except with a single 
   static buffer. */

static u8* DF(double val) {

  static u8 tmp[16];

  if (val < 99.995) {
    sprintf((char*)tmp, "%0.02f", val);
    return tmp;
  }

  if (val < 999.95) {
    sprintf((char*)tmp, "%0.01f", val);
    return tmp;
  }

  return DI((u64)val);

}


/* Describe integer as memory size. */

static u8* DMS(u64 val) {

  static u8 tmp[12][16];
  static u8 cur;

  cur = (cur + 1) % 12;

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu B", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

  /* 100k - 999k */
  CHK_FORMAT(1024, 1000, "%llu kB", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

  /* 100M - 999M */
  CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

  /* 100G - 999G */
  CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

  /* 100T+ */
  strcpy((char*)tmp[cur], "infty");
  return tmp[cur];

}


/* Describe time delta. Returns one static buffer, 34 chars of less. */

static u8* DTD(u64 cur_ms, u64 event_ms) {

  static u8 tmp[64];
  u64 delta;
  s32 t_d, t_h, t_m, t_s;

  if (!event_ms) {
      sprintf((char*)tmp, "none seen yet");
      return tmp;
  }

  delta = cur_ms - event_ms;

  t_d = delta / 1000 / 60 / 60 / 24;
  t_h = (delta / 1000 / 60 / 60) % 24;
  t_m = (delta / 1000 / 60) % 60;
  t_s = (delta / 1000) % 60;

  sprintf((char*)tmp, "%s days, %u hrs, %u min, %u sec", DI(t_d), t_h, t_m, t_s);
  return tmp;

}


/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */

static void mark_as_det_done(struct queue_entry* q) {

  u8* fn = (u8*)strrchr((char*)q->fname, '/');
  s32 fd;

  fn = alloc_printf("%s/queue/.state/deterministic_done/%s", out_dir, fn + 1);

  fd = open((char*)fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  close(fd);

  ck_free(fn);

  q->passed_det = 1;

}


/* Mark as variable. Create symlinks if possible to make it easier to examine
   the files. */

static void mark_as_variable(struct queue_entry* q) {

  u8 *fn = (u8*)strrchr((char*)q->fname, '/') + 1, *ldest;

  ldest = alloc_printf("../../%s", fn);
  fn = alloc_printf("%s/queue/.state/variable_behavior/%s", out_dir, fn);

  if (symlink((char*)ldest, (char*)fn)) {

    s32 fd = open((char*)fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  }

  ck_free(ldest);
  ck_free(fn);

  q->var_behavior = 1;

}


/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */

static void mark_as_redundant(struct queue_entry* q, u8 state) {

  u8* fn;
  s32 fd;

  if (state == q->fs_redundant) return;

  q->fs_redundant = state;

  fn = (u8*)strrchr(q->fname, '/');
  fn = alloc_printf("%s/queue/.state/redundant_edges/%s", out_dir, fn + 1);

  if (state) {

    fd = open((char*)fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  } else {

    if (unlink((char*)fn)) PFATAL("Unable to remove '%s'", fn);

  }

  ck_free(fn);

}


/* Append new test case to the queue. */

static void add_to_queue(u8* fname, u32 len, u8 passed_det) {

  struct queue_entry* q = ck_alloc(sizeof(struct queue_entry));

  q->fname        = (char*)fname;
  q->len          = len;
  q->depth        = cur_depth + 1;
  q->passed_det   = passed_det;

  if (q->depth > max_depth) max_depth = q->depth;

  if (queue_top) {

    queue_top->next = q;
    queue_top = q;

  } else q_prev100 = queue = queue_top = q;

  queued_paths++;
  pending_not_fuzzed++;

  cycles_wo_finds = 0;

  /* Set next_100 pointer for every 100th element (index 0, 100, etc) to allow faster iteration. */
  if ((queued_paths - 1) % 100 == 0 && queued_paths > 1) {

    q_prev100->next_100 = q;
    q_prev100 = q;

  }

  last_path_time = get_cur_time();

}


/* Destroy the entire queue. */

EXP_ST void destroy_queue(void) {

  struct queue_entry *q = queue, *n;

  while (q) {

    n = q->next;
    ck_free(q->fname);
    ck_free(q->trace_mini);
    ck_free(q);
    q = n;

  }

}


/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

EXP_ST void write_bitmap(void) {

  u8* fname;
  s32 fd;

  if (!bitmap_changed) return;
  bitmap_changed = 0;

  fname = alloc_printf("%s/fuzz_bitmap", out_dir);
  fd = open((char*)fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_write(fd, virgin_bits, MAP_SIZE, fname);

  close(fd);
  ck_free(fname);

}


/* Read bitmap from file. This is for the -B option again. */

EXP_ST void read_bitmap(u8* fname) {

  s32 fd = open((char*)fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_read(fd, virgin_bits, MAP_SIZE, fname);

  close(fd);

}


/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen. 
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

static inline u8 has_new_bits(u8* virgin_map) {

#ifdef WORD_SIZE_64

  u64* current = (u64*)trace_bits;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (MAP_SIZE >> 3);

#else

  u32* current = (u32*)trace_bits;
  u32* virgin  = (u32*)virgin_map;

  u32  i = (MAP_SIZE >> 2);

#endif /* ^WORD_SIZE_64 */

  u8   ret = 0;

  while (i--) {

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */

    if (unlikely(*current) && unlikely(*current & *virgin)) {

      if (likely(ret < 2)) {

        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

#ifdef WORD_SIZE_64

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
        else ret = 1;

#else

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff)) ret = 2;
        else ret = 1;

#endif /* ^WORD_SIZE_64 */

      }

      *virgin &= ~*current;

    }

    current++;
    virgin++;

  }

  if (ret && virgin_map == virgin_bits) bitmap_changed = 1;

  return ret;

}


/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */

static u32 count_bits(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (v == 0xffffffff) {
      ret += 32;
      continue;
    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return ret;

}


#define FF(_b)  (0xff << ((_b) << 3))

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

static u32 count_bytes(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (!v) continue;
    if (v & FF(0)) ret++;
    if (v & FF(1)) ret++;
    if (v & FF(2)) ret++;
    if (v & FF(3)) ret++;

  }

  return ret;

}


/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */

static u32 count_non_255_bytes(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (v == 0xffffffff) continue;
    if ((v & FF(0)) != FF(0)) ret++;
    if ((v & FF(1)) != FF(1)) ret++;
    if ((v & FF(2)) != FF(2)) ret++;
    if ((v & FF(3)) != FF(3)) ret++;

  }

  return ret;

}


/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */

static const u8 simplify_lookup[256] = { 

  [0]         = 1,
  [1 ... 255] = 128

};

#ifdef WORD_SIZE_64

static void simplify_trace(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u8* mem8 = (u8*)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];
      mem8[4] = simplify_lookup[mem8[4]];
      mem8[5] = simplify_lookup[mem8[5]];
      mem8[6] = simplify_lookup[mem8[6]];
      mem8[7] = simplify_lookup[mem8[7]];

    } else *mem = 0x0101010101010101ULL;

    mem++;

  }

}

#else

static void simplify_trace(u32* mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u8* mem8 = (u8*)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];

    } else *mem = 0x01010101;

    mem++;
  }

}

#endif /* ^WORD_SIZE_64 */


/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

static const u8 count_class_lookup8[256] = {

  [0]           = 0,
  [1]           = 1,
  [2]           = 2,
  [3]           = 4,
  [4 ... 7]     = 8,
  [8 ... 15]    = 16,
  [16 ... 31]   = 32,
  [32 ... 127]  = 64,
  [128 ... 255] = 128

};

static u16 count_class_lookup16[65536];


EXP_ST void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) 
    for (b2 = 0; b2 < 256; b2++)
      count_class_lookup16[(b1 << 8) + b2] = 
        (count_class_lookup8[b1] << 8) |
        count_class_lookup8[b2];

}


#ifdef WORD_SIZE_64

static inline void classify_counts(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
      mem16[2] = count_class_lookup16[mem16[2]];
      mem16[3] = count_class_lookup16[mem16[3]];

    }

    mem++;

  }

}

#else

static inline void classify_counts(u32* mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];

    }

    mem++;

  }

}

#endif /* ^WORD_SIZE_64 */


/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {
  // we need't do it
}


/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */

static void minimize_bits(u8* dst, u8* src) {

  u32 i = 0;

  while (i < MAP_SIZE) {

    if (*(src++)) dst[i >> 3] |= 1 << (i & 7);
    i++;

  }

}


/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of top_rated[] entries
   for every byte in the bitmap. We win that slot if there is no previous
   contender, or if the contender has a more favorable speed x size factor. */

static void update_bitmap_score(struct queue_entry* q) {

  u32 i;
  u64 fav_factor = q->exec_us * q->len;

  /* For every byte set in trace_bits[], see if there is a previous winner,
     and how it compares to us. */

  for (i = 0; i < MAP_SIZE; i++)

    if (trace_bits[i]) {

       if (top_rated[i]) {

         /* Faster-executing or smaller test cases are favored. */
         //if (q->num_mmios <= top_rated[i]->num_mmios)
             if (fav_factor > top_rated[i]->exec_us * top_rated[i]->len) continue;
             if (q->len > top_rated[i]->len) continue;
         
         /* Looks like we're going to win. Decrease ref count for the
            previous winner, discard its trace_bits[] if necessary. */

         if (!--top_rated[i]->tc_ref) {
           ck_free(top_rated[i]->trace_mini);
           top_rated[i]->trace_mini = 0;
         }

       }

       /* Insert ourselves as the new winner. */

       top_rated[i] = q;
       q->tc_ref++;
       
       if (!q->trace_mini) {
         q->trace_mini = ck_alloc(MAP_SIZE >> 3);
         minimize_bits(q->trace_mini, trace_bits);
       }
       
       score_changed = 1;

     }
}


/* The second part of the mechanism discussed above is a routine that
   goes over top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. */

static void cull_queue(void) {

  struct queue_entry* q;
  static u8 temp_v[MAP_SIZE >> 3];
  u32 i;
  
  if (dumb_mode || !score_changed) return;

  score_changed = 0;

  memset(temp_v, 255, MAP_SIZE >> 3);

  queued_favored  = 0;
  pending_favored = 0;

  q = queue;

  while (q) {
    q->favored = 0;
    q = q->next;
  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a top_rated[] contender, let's use it. */

  for (i = 0; i < MAP_SIZE; i++)
    if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = MAP_SIZE >> 3;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--) 
        if (top_rated[i]->trace_mini[j])
          temp_v[j] &= ~top_rated[i]->trace_mini[j];

      top_rated[i]->favored = 1;
      queued_favored++;

      if (!top_rated[i]->was_fuzzed) pending_favored++;

    }
    
  q = queue;

  while (q) {
    mark_as_redundant(q, !q->favored);
    q = q->next;
  }

}

/* Read all testcases from the input directory, then queue them for testing.
   Called at startup. */

static void read_testcases(void) {

  struct dirent **nl;
  s32 nl_cnt;
  u32 i;
  u8* fn;

  /* Auto-detect non-in-place resumption attempts. */

  fn = alloc_printf("%s/queue", in_dir);
  if (!access((char*)fn, F_OK)) in_dir = fn; else ck_free(fn);

  ACTF("Scanning '%s'...", in_dir);

  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering  of test cases would vary somewhat randomly and would be
     difficult to control. */

  nl_cnt = scandir((char*)in_dir, &nl, NULL, alphasort);

  if (nl_cnt < 0) {

    if (errno == ENOENT || errno == ENOTDIR)

      SAYF("\n" cLRD "[-] " cRST
           "The input directory does not seem to be valid - try again. The fuzzer needs\n"
           "    one or more test case to start with - ideally, a small file under 1 kB\n"
           "    or so. The cases must be stored as regular files directly in the input\n"
           "    directory.\n");

    PFATAL("Unable to open '%s'", in_dir);

  }

  if (shuffle_queue && nl_cnt > 1) {

    ACTF("Shuffling queue...");
    shuffle_ptrs((void**)nl, nl_cnt);

  }

  for (i = 0; i < nl_cnt; i++) {

    struct stat st;

    u8* fn = alloc_printf("%s/%s", in_dir, nl[i]->d_name);
    u8* dfn = alloc_printf("%s/.state/deterministic_done/%s", in_dir, nl[i]->d_name);

    u8  passed_det = 0;

    free(nl[i]); /* not tracked */
 
    if (lstat((char*)fn, &st) || access((char*)fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */

    if (!S_ISREG(st.st_mode) || !st.st_size || strstr((char*)fn, "/README.testcases")) {

      ck_free(fn);
      ck_free(dfn);
      continue;

    }

    //if (st.st_size > MAX_FILE) 
     // FATAL("Test case '%s' is too big (%s, limit is %s)", fn,
     //       DMS(st.st_size), DMS(MAX_FILE));

    /* Check for metadata that indicates that deterministic fuzzing
       is complete for this entry. We don't want to repeat deterministic
       fuzzing when resuming aborted scans, because it would be pointless
       and probably very time-consuming. */

    if (!access((char*)dfn, F_OK)) passed_det = 1;
    ck_free(dfn);

    add_to_queue(fn, st.st_size, passed_det);

  }

  free(nl); /* not tracked */

  if (!queued_paths) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like there are no valid test cases in the input directory! The fuzzer\n"
         "    needs one or more test case to start with - ideally, a small file under\n"
         "    1 kB or so. The cases must be stored as regular files directly in the\n"
         "    input directory.\n");

    FATAL("No usable test cases in '%s'", in_dir);

  }

  last_path_time = 0;
  queued_at_start = queued_paths;

}



/* Helper function for maybe_add_auto() */

static inline u8 memcmp_nocase(u8* m1, u8* m2, u32 len) {

  while (len--) if (tolower(*(m1++)) ^ tolower(*(m2++))) return 1;
  return 0;

}

/* Helper function for load_extras. */

static int compare_extras_len(const void* p1, const void* p2) {
  struct extra_data *e1 = (struct extra_data*)p1,
                    *e2 = (struct extra_data*)p2;

  return e1->len - e2->len;
}

static int compare_extras_use_d(const void* p1, const void* p2) {
  struct extra_data *e1 = (struct extra_data*)p1,
                    *e2 = (struct extra_data*)p2;

  return e2->hit_cnt - e1->hit_cnt;
}

/* Read extras from a file, sort by size. */

static void load_extras_file(u8* fname, u32* min_len, u32* max_len,
                             u32 dict_level) {

  FILE* f;
  u8  buf[MAX_LINE];
  char  *lptr;
  u32 cur_line = 0;

  f = fopen((char*)fname, "r");

  if (!f) PFATAL("Unable to open '%s'", fname);

  while ((lptr = fgets((char*)buf, MAX_LINE, f))) {

    char *rptr, *wptr;
    u32 klen = 0;

    cur_line++;

    /* Trim on left and right. */

    while (isspace(*lptr)) lptr++;

    rptr = lptr + strlen(lptr) - 1;
    while (rptr >= lptr && isspace(*rptr)) rptr--;
    rptr++;
    *rptr = 0;

    /* Skip empty lines and comments. */

    if (!*lptr || *lptr == '#') continue;

    /* All other lines must end with '"', which we can consume. */

    rptr--;

    if (rptr < lptr || *rptr != '"')
      FATAL("Malformed name=\"value\" pair in line %u.", cur_line);

    *rptr = 0;

    /* Skip alphanumerics and dashes (label). */

    while (isalnum(*lptr) || *lptr == '_') lptr++;

    /* If @number follows, parse that. */

    if (*lptr == '@') {

      lptr++;
      if (atoi(lptr) > dict_level) continue;
      while (isdigit(*lptr)) lptr++;

    }

    /* Skip whitespace and = signs. */

    while (isspace(*lptr) || *lptr == '=') lptr++;

    /* Consume opening '"'. */

    if (*lptr != '"')
      FATAL("Malformed name=\"keyword\" pair in line %u.", cur_line);

    lptr++;

    if (!*lptr) FATAL("Empty keyword in line %u.", cur_line);

    /* Okay, let's allocate memory and copy data between "...", handling
       \xNN escaping, \\, and \". */

    extras = ck_realloc_block(extras, (extras_cnt + 1) *
               sizeof(struct extra_data));

    extras[extras_cnt].data = ck_alloc(rptr - lptr);
    wptr = (char*)extras[extras_cnt].data;
    while (*lptr) {

      char* hexdigits = "0123456789abcdef";

      switch (*(unsigned char*)lptr) {

        case 1 ... 31:
        case 128 ... 255:
          FATAL("Non-printable characters in line %u.", cur_line);

        case '\\':

          lptr++;

          if (*lptr == '\\' || *lptr == '"') {
            *(wptr++) = *(lptr++);
            klen++;
            break;
          }

          if (*lptr != 'x' || !isxdigit(lptr[1]) || !isxdigit(lptr[2]))
            FATAL("Invalid escaping (not \\xNN) in line %u.", cur_line);

          *(wptr++) =
            ((strchr(hexdigits, tolower(lptr[1])) - hexdigits) << 4) |
            (strchr(hexdigits, tolower(lptr[2])) - hexdigits);

          lptr += 3;
          klen++;

          break;

        default:

          *(wptr++) = *(lptr++);
          klen++;

      }

    }

    extras[extras_cnt].len = klen;

    if (extras[extras_cnt].len > MAX_DICT_FILE)
      FATAL("Keyword too big in line %u (%s, limit is %s)", cur_line,
            DMS(klen), DMS(MAX_DICT_FILE));

    if (*min_len > klen) *min_len = klen;
    if (*max_len < klen) *max_len = klen;

    extras_cnt++;

  }

  fclose(f);

}


/* Read extras from the extras directory and sort them by size. */

static void load_extras(u8* dir) {

  DIR* d;
  struct dirent* de;
  u32 min_len = MAX_DICT_FILE, max_len = 0, dict_level = 0;
  char* x;

  /* If the name ends with @, extract level and continue. */

  if ((x = strchr((char*)dir, '@'))) {

    *x = 0;
    dict_level = atoi(x + 1);

  }

  ACTF("Loading extra dictionary from '%s' (level %u)...", dir, dict_level);

  d = opendir((char*)dir);

  if (!d) {

    if (errno == ENOTDIR) {
      load_extras_file(dir, &min_len, &max_len, dict_level);
      goto check_and_sort;
    }

    PFATAL("Unable to open '%s'", dir);

  }

  if (x) FATAL("Dictionary levels not supported for directories.");

  while ((de = readdir(d))) {

    struct stat st;
    u8* fn = alloc_printf("%s/%s", dir, de->d_name);
    s32 fd;

    if (lstat((char*)fn, &st) || access((char*)fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */
    if (!S_ISREG(st.st_mode) || !st.st_size) {

      ck_free(fn);
      continue;

    }

    if (st.st_size > MAX_DICT_FILE)
      FATAL("Extra '%s' is too big (%s, limit is %s)", fn,
            DMS(st.st_size), DMS(MAX_DICT_FILE));

    if (min_len > st.st_size) min_len = st.st_size;
    if (max_len < st.st_size) max_len = st.st_size;

    extras = ck_realloc_block(extras, (extras_cnt + 1) *
               sizeof(struct extra_data));

    extras[extras_cnt].data = ck_alloc(st.st_size);
    extras[extras_cnt].len  = st.st_size;

    fd = open((char*)fn, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", fn);

    ck_read(fd, extras[extras_cnt].data, st.st_size, fn);

    close(fd);
    ck_free(fn);

    extras_cnt++;

  }

  closedir(d);

check_and_sort:

  if (!extras_cnt) FATAL("No usable files in '%s'", dir);

  qsort(extras, extras_cnt, sizeof(struct extra_data), compare_extras_len);

  OKF("Loaded %u extra tokens, size range %s to %s.", extras_cnt,
      DMS(min_len), DMS(max_len));

  if (max_len > 32)
    WARNF("Some tokens are relatively large (%s) - consider trimming.",
          DMS(max_len));

  if (extras_cnt > MAX_DET_EXTRAS)
    WARNF("More than %u tokens - will use them probabilistically.",
          MAX_DET_EXTRAS);

}

/* Maybe add automatic extra. */

static void maybe_add_auto(u8* mem, u32 len) {

  u32 i;

  /* Allow users to specify that they don't want auto dictionaries. */

  if (!MAX_AUTO_EXTRAS || !USE_AUTO_EXTRAS) return;

  /* Skip runs of identical bytes. */

  for (i = 1; i < len; i++)
    if (mem[0] ^ mem[i]) break;

  if (i == len) return;

  /* Reject builtin interesting values. */

  if (len == 2) {

    i = sizeof(interesting_16) >> 1;

    while (i--) 
      if (*((u16*)mem) == interesting_16[i] ||
          *((u16*)mem) == SWAP16(interesting_16[i])) return;

  }

  if (len == 4) {

    i = sizeof(interesting_32) >> 2;

    while (i--) 
      if (*((u32*)mem) == interesting_32[i] ||
          *((u32*)mem) == SWAP32(interesting_32[i])) return;

  }

  /* Reject anything that matches existing extras. Do a case-insensitive
     match. We optimize by exploiting the fact that extras[] are sorted
     by size. */

  for (i = 0; i < extras_cnt; i++)
    if (extras[i].len >= len) break;

  for (; i < extras_cnt && extras[i].len == len; i++)
    if (!memcmp_nocase(extras[i].data, mem, len)) return;

  /* Last but not least, check a_extras[] for matches. There are no
     guarantees of a particular sort order. */

  auto_changed = 1;

  for (i = 0; i < a_extras_cnt; i++) {

    if (a_extras[i].len == len && !memcmp_nocase(a_extras[i].data, mem, len)) {

      a_extras[i].hit_cnt++;
      goto sort_a_extras;

    }

  }

  /* At this point, looks like we're dealing with a new entry. So, let's
     append it if we have room. Otherwise, let's randomly evict some other
     entry from the bottom half of the list. */

  if (a_extras_cnt < MAX_AUTO_EXTRAS) {

    a_extras = ck_realloc_block(a_extras, (a_extras_cnt + 1) *
                                sizeof(struct extra_data));

    a_extras[a_extras_cnt].data = ck_memdup(mem, len);
    a_extras[a_extras_cnt].len  = len;
    a_extras_cnt++;

  } else {

    i = MAX_AUTO_EXTRAS / 2 +
        UR((MAX_AUTO_EXTRAS + 1) / 2);

    ck_free(a_extras[i].data);

    a_extras[i].data    = ck_memdup(mem, len);
    a_extras[i].len     = len;
    a_extras[i].hit_cnt = 0;

  }

sort_a_extras:

  /* First, sort all auto extras by use count, descending order. */

  qsort(a_extras, a_extras_cnt, sizeof(struct extra_data),
        compare_extras_use_d);

  /* Then, sort the top USE_AUTO_EXTRAS entries by size. */

  qsort(a_extras, MIN(USE_AUTO_EXTRAS, a_extras_cnt),
        sizeof(struct extra_data), compare_extras_len);

}


/* Save automatically generated extras. */

static void save_auto(void) {

  u32 i;

  if (!auto_changed) return;
  auto_changed = 0;

  for (i = 0; i < MIN(USE_AUTO_EXTRAS, a_extras_cnt); i++) {

    u8* fn = alloc_printf("%s/queue/.state/auto_extras/auto_%06u", out_dir, i);
    s32 fd;

    fd = open((char*)fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", fn);

    ck_write(fd, a_extras[i].data, a_extras[i].len, fn);

    close(fd);
    ck_free(fn);

  }

}


/* Load automatically generated extras. */

static void load_auto(void) {

  u32 i;

  for (i = 0; i < USE_AUTO_EXTRAS; i++) {

    u8  tmp[MAX_AUTO_EXTRA + 1];
    u8* fn = alloc_printf("%s/.state/auto_extras/auto_%06u", in_dir, i);
    s32 fd, len;

    fd = open((char*)fn, O_RDONLY, 0600);

    if (fd < 0) {

      if (errno != ENOENT) PFATAL("Unable to open '%s'", fn);
      ck_free(fn);
      break;

    }

    /* We read one byte more to cheaply detect tokens that are too
       long (and skip them). */

    len = read(fd, tmp, MAX_AUTO_EXTRA + 1);

    if (len < 0) PFATAL("Unable to read from '%s'", fn);

    if (len >= MIN_AUTO_EXTRA && len <= MAX_AUTO_EXTRA)
      maybe_add_auto(tmp, len);

    close(fd);
    ck_free(fn);

  }

  if (i) OKF("Loaded %u auto-discovered dictionary tokens.", i);
  else OKF("No auto-generated dictionary tokens to reuse.");

}


/* Destroy extras. */

static void destroy_extras(void) {

  u32 i;

  for (i = 0; i < extras_cnt; i++) 
    ck_free(extras[i].data);

  ck_free(extras);

  for (i = 0; i < a_extras_cnt; i++) 
    ck_free(a_extras[i].data);

  ck_free(a_extras);

}





/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

static u8 run_target() {
  u64 start_us, stop_us;
  static u64 exec_ms = 0;

  //int status = 0;
  u32 tb4;
  
  /* After this memset, trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */
  uc_fuzzer_reset_cov(g_uc, 1);
  if (cmplog_mode) {
    uc_fuzzer_reset_cmplog(g_uc, 1);
  }
  memset(stream_map, 0, sizeof(struct stream_feedback));
  MEM_BARRIER();

  start_us = get_cur_time_us();
  restore_snapshot_initial(g_uc);
  kill_signal = run_single(g_uc);
  stop_us = get_cur_time_us();


  exec_ms = (stop_us - start_us) / 1000;

  if (exec_ms > exec_tmout) {
      child_timed_out = 1;
  }

  total_execs++;

  /* Any subsequent operations on trace_bits must not be moved by the
     compiler below this point. Past this location, trace_bits[] behave
     very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  tb4 = *(u32*)trace_bits;

#ifdef WORD_SIZE_64
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);
#endif /* ^WORD_SIZE_64 */

  /* Report outcome to caller. */

  if (kill_signal && !stop_soon) {

    

    if (child_timed_out && kill_signal == SIGKILL) return FAULT_TMOUT;

    return FAULT_CRASH;

  }


 

  /* It makes sense to account for the slowest units only if the testcase was run
  under the user defined timeout. */
  if (!(exec_ms > exec_tmout) && (slowest_exec_ms < exec_ms)) {
    slowest_exec_ms = exec_ms;
  }

  return FAULT_NONE;

}


static void show_stats(void);

/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

static u8 calibrate_case(struct queue_entry* q, u8* use_mem,
                         u32 handicap, u8 from_queue) {

  static u8 first_trace[MAP_SIZE];

  u8  fault = 0, new_bits = 0, var_detected = 0, hnb = 0,
      first_run = (q->exec_cksum == 0);

  u64 start_us, stop_us;

  s32 old_sc = stage_cur, old_sm = stage_max;
  u32 use_tmout = exec_tmout;
  u8* old_sn = (u8*)stage_name;

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */

  if (!from_queue || resuming_fuzz)
     use_tmout = MAX(exec_tmout + CAL_TMOUT_ADD,
                     exec_tmout * CAL_TMOUT_PERC / 100);

  q->cal_failed++;

  stage_name = "calibration";
  stage_max  = fast_cal ? 3 : CAL_CYCLES;
  
  

  if (q->exec_cksum) {

    memcpy(first_trace, trace_bits, MAP_SIZE);
    hnb = has_new_bits(virgin_bits);
    if (hnb > new_bits) new_bits = hnb;

  }
  
  if (from_queue)
    init_streams_input(&g_stream_input,use_mem, q->len, 0);
  start_us = get_cur_time_us();

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 cksum;

    if (!first_run && !(stage_cur % stats_update_freq)) show_stats();

    
    if(reset_streams_input(&g_stream_input, use_mem, q->len)){    
        q->num_mmios = get_num_mmio(&g_stream_input);
    }else{
        WARNF("Build streams failed with \"%s\", use empty file!",q->fname);           
        q->num_mmios = 0;
    }

    fault = run_target();

    /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (stop_soon || fault != crash_mode) goto abort_calibration;

    if (!dumb_mode && !stage_cur && !count_bytes(trace_bits)) {

      fault = FAULT_NOINST;
      goto abort_calibration;
    }

    cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    if (q->exec_cksum != cksum) {

      hnb = has_new_bits(virgin_bits);
      if (hnb > new_bits) new_bits = hnb;

      if (q->exec_cksum) {

        u32 i;

        for (i = 0; i < MAP_SIZE; i++) {

          if (!var_bytes[i] && first_trace[i] != trace_bits[i]) {

            var_bytes[i] = 1;
            stage_max    = CAL_CYCLES_LONG;

          }

        }

        var_detected = 1;

      } else {

        q->exec_cksum = cksum;
        memcpy(first_trace, trace_bits, MAP_SIZE);

      }

    }

  }

  stop_us = get_cur_time_us();

  total_cal_us     += stop_us - start_us;
  total_cal_cycles += stage_max;

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */

  q->exec_us     = (stop_us - start_us) / stage_max;
  q->bitmap_size = count_bytes(trace_bits);
  q->handicap    = handicap;
  q->cal_failed  = 0;

  total_bitmap_size += q->bitmap_size;
  total_bitmap_entries++;

  update_bitmap_score(q);

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

  if (!dumb_mode && first_run && !fault && !new_bits) fault = FAULT_NOBITS;

abort_calibration:

  if (new_bits == 2 && !q->has_new_cov) {
    q->has_new_cov = 1;
    queued_with_cov++;
  }

  /* Mark variable paths. */

  if (var_detected) {

    var_byte_count = count_bytes(var_bytes);

    if (!q->var_behavior) {
      mark_as_variable(q);
      queued_variable++;
    }

  }

  stage_name = (char*)old_sn;
  stage_cur  = old_sc;
  stage_max  = old_sm;

  if (!first_run) show_stats();

  return fault;

}


/* Examine map coverage. Called once, for first test case. */

static void check_map_coverage(void) {

  u32 i;

  if (count_bytes(trace_bits) < 100) return;

  for (i = (1 << (MAP_SIZE_POW2 - 1)); i < MAP_SIZE; i++)
    if (trace_bits[i]) return;

  WARNF("Recompile binary with newer version of afl to improve coverage!");

}


/* Perform dry run of all test cases to confirm that the app is working as
   expected. This is done only for the initial inputs, and only once. */

static void perform_dry_run() {

  struct queue_entry* q = queue;
  u32 cal_failures = 0;
  //u8* skip_crashes = (u8*)getenv("AFL_SKIP_CRASHES");
  bool skip_crashes = true;

  while (q) {

    u8* use_mem;
    u8  res;
    s32 fd;

    char* fn = strrchr(q->fname, '/') + 1;

    ACTF("Attempting dry run with '%s'...", fn);

    fd = open(q->fname, O_RDONLY);
    if (fd < 0) PFATAL("Unable to open '%s'", q->fname);

    use_mem = ck_alloc_nozero(q->len);

    if (read(fd, use_mem, q->len) != q->len)
      FATAL("Short read from '%s'", q->fname);

    close(fd);

    res = calibrate_case(q, use_mem, 0, 1);
    ck_free(use_mem);

    if (stop_soon) return;

    if (res == crash_mode || res == FAULT_NOBITS)
      SAYF(cGRA "    len = %u, map size = %u, exec speed = %llu us\n" cRST, 
           q->len, q->bitmap_size, q->exec_us);

    switch (res) {

      case FAULT_NONE:

        if (q == queue) check_map_coverage();

        if (crash_mode) FATAL("Test case '%s' does *NOT* crash", fn);

        break;

      case FAULT_TMOUT:

        if (timeout_given) {

          /* The -t nn+ syntax in the command line sets timeout_given to '2' and
             instructs afl-fuzz to tolerate but skip queue entries that time
             out. */

          if (timeout_given > 1) {
            WARNF("Test case results in a timeout (skipping)");
            q->cal_failed = CAL_CHANCES;
            cal_failures++;
            break;
          }

          SAYF("\n" cLRD "[-] " cRST
               "The program took more than %u ms to process one of the initial test cases.\n"
               "    Usually, the right thing to do is to relax the -t option - or to delete it\n"
               "    altogether and allow the fuzzer to auto-calibrate. That said, if you know\n"
               "    what you are doing and want to simply skip the unruly test cases, append\n"
               "    '+' at the end of the value passed to -t ('-t %u+').\n", exec_tmout,
               exec_tmout);

          FATAL("Test case '%s' results in a timeout", fn);

        } else {

          SAYF("\n" cLRD "[-] " cRST
               "The program took more than %u ms to process one of the initial test cases.\n"
               "    This is bad news; raising the limit with the -t option is possible, but\n"
               "    will probably make the fuzzing process extremely slow.\n\n"

               "    If this test case is just a fluke, the other option is to just avoid it\n"
               "    altogether, and find one that is less of a CPU hog.\n", exec_tmout);

          FATAL("Test case '%s' results in a timeout", fn);

        }

      case FAULT_CRASH:  

        if (crash_mode) break;

        if (skip_crashes) {
          WARNF("Test case results in a crash (skipping)");
          q->cal_failed = CAL_CHANCES;
          cal_failures++;
          break;
        }

        if (mem_limit) {


        } else {

          SAYF("\n" cLRD "[-] " cRST
               "Oops, the program crashed with one of the test cases provided. There are\n"
               "    several possible explanations:\n\n"

               "    - The test case causes known crashes under normal working conditions. If\n"
               "      so, please remove it. The fuzzer should be seeded with interesting\n"
               "      inputs - but not ones that cause an outright crash.\n\n"

#ifdef __APPLE__
  
               "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
               "      break afl-fuzz performance optimizations when running platform-specific\n"
               "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

               "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
               "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

        }

        FATAL("Test case '%s' results in a crash", fn);

      case FAULT_ERROR:

        FATAL("Unable to execute target application.");

      case FAULT_NOINST:

        FATAL("No instrumentation detected");

      case FAULT_NOBITS: 

        useless_at_start++;

        if (!in_bitmap && !shuffle_queue)
          WARNF("No new instrumentation output, test case may be useless.");

        break;

    }

    if (q->var_behavior) WARNF("Instrumentation output varies across runs.");

    q = q->next;

  }

  if (cal_failures) {

    if (cal_failures == queued_paths)
      FATAL("All test cases time out%s, giving up!",
            skip_crashes ? " or crash" : "");

    WARNF("Skipped %u test cases (%0.02f%%) due to timeouts%s.", cal_failures,
          ((double)cal_failures) * 100 / queued_paths,
          skip_crashes ? " or crashes" : "");

    if (cal_failures * 5 > queued_paths)
      WARNF(cLRD "High percentage of rejected test cases, check settings!");

  }

  OKF("All test cases processed.");

}


/* Helper function: link() if possible, copy otherwise. */

static void link_or_copy(u8* old_path, u8* new_path) {

  s32 i = link((char*)old_path, (char*)new_path);
  s32 sfd, dfd;
  u8* tmp;

  if (!i) return;

  sfd = open((char*)old_path, O_RDONLY);
  if (sfd < 0) PFATAL("Unable to open '%s'", old_path);

  dfd = open((char*)new_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (dfd < 0) PFATAL("Unable to create '%s'", new_path);

  tmp = ck_alloc(64 * 1024);

  while ((i = read(sfd, tmp, 64 * 1024)) > 0) 
    ck_write(dfd, tmp, i, new_path);

  if (i < 0) PFATAL("read() failed");

  ck_free(tmp);
  close(sfd);
  close(dfd);

}


static void nuke_resume_dir(void);

/* Create hard links for input test cases in the output directory, choosing
   good names and pivoting accordingly. */

static void pivot_inputs(void) {

  struct queue_entry* q = queue;
  u32 id = 0;

  ACTF("Creating hard links for all input files...");

  while (q) {

    char  *nfn, *rsl = strrchr(q->fname, '/');
    u32 orig_id;

    if (!rsl) rsl = q->fname; else rsl++;

    /* If the original file name conforms to the syntax and the recorded
       ID matches the one we'd assign, just use the original file name.
       This is valuable for resuming fuzzing runs. */

#ifndef SIMPLE_FILES
#  define CASE_PREFIX "id:"
#else
#  define CASE_PREFIX "id_"
#endif /* ^!SIMPLE_FILES */

    if (!strncmp(rsl, CASE_PREFIX, 3) &&
        sscanf(rsl + 3, "%06u", &orig_id) == 1 && orig_id == id) {

      char* src_str;
      u32 src_id;

      resuming_fuzz = 1;
      nfn = (char*)alloc_printf("%s/queue/%s", out_dir, rsl);

      /* Since we're at it, let's also try to find parent and figure out the
         appropriate depth for this entry. */

      src_str = strchr(rsl + 3, ':');

      if (src_str && sscanf(src_str + 1, "%06u", &src_id) == 1) {

        struct queue_entry* s = queue;
        while (src_id-- && s) s = s->next;
        if (s) q->depth = s->depth + 1;

        if (max_depth < q->depth) max_depth = q->depth;

      }

    } else {

      /* No dice - invent a new name, capturing the original one as a
         substring. */

#ifndef SIMPLE_FILES

      char* use_name = strstr(rsl, ",orig:");

      if (use_name) use_name += 6; else use_name = rsl;
      nfn = (char*)alloc_printf("%s/queue/id:%06u,orig:%s", out_dir, id, use_name);

#else

      nfn = (char*)alloc_printf("%s/queue/id_%06u", out_dir, id);

#endif /* ^!SIMPLE_FILES */

    }

    /* Pivot to the new queue entry. */

    link_or_copy((u8*)q->fname, (u8*)nfn);
    ck_free(q->fname);
    q->fname = nfn;

    /* Make sure that the passed_det value carries over, too. */

    if (q->passed_det) mark_as_det_done(q);

    q = q->next;
    id++;

  }

  if (in_place_resume) nuke_resume_dir();

}


#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Uses a static buffer. */

static u8* describe_op(u8 hnb) {

  static u8 ret[256];

  if (syncing_party) {

    sprintf((char*)ret, "sync:%s,src:%06u", syncing_party, syncing_case);

  } else {

    sprintf((char*)ret, "src:%06u", current_entry);

    if (splicing_with >= 0)
      sprintf((char*)ret + strlen((char*)ret), "+%06u", splicing_with);

    sprintf((char*)ret + strlen((char*)ret), ",op:%s", stage_short);

    if (stage_cur_byte >= 0) {

      sprintf((char*)ret + strlen((char*)ret), ",pos:%u", stage_cur_byte);

      if (stage_val_type != STAGE_VAL_NONE)
        sprintf((char*)ret + strlen((char*)ret), ",val:%s%+d", 
                (stage_val_type == STAGE_VAL_BE) ? "be:" : "",
                stage_cur_val);

    } else sprintf((char*)ret + strlen((char*)ret), ",rep:%u", stage_cur_val);

  }

  if (hnb == 2) strcat((char*)ret, ",+cov");

  return ret;

}

#endif /* !SIMPLE_FILES */


/* Write a message accompanying the crash directory :-) */

static void write_crash_readme(void) {

  u8* fn = alloc_printf("%s/crashes/README.txt", out_dir);
  s32 fd;
  FILE* f;

  fd = open((char*)fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  ck_free(fn);

  /* Do not die on errors here - that would be impolite. */

  if (fd < 0) return;

  f = fdopen(fd, "w");

  if (!f) {
    close(fd);
    return;
  }

  fprintf(f, "Command line used to find this crash:\n\n"

             "%s\n\n"

             "If you can't reproduce a bug outside of afl-fuzz, be sure to set the same\n"
             "memory limit. The limit used for this fuzzing session was %s.\n\n"

             "Need a tool to minimize test cases before investigating the crashes or sending\n"
             "them to a vendor? Check out the afl-tmin that comes with the fuzzer!\n\n"

             "Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop\n"
             "me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to\n"
             "add your finds to the gallery at:\n\n"

             "  http://lcamtuf.coredump.cx/afl/\n\n"

             "Thanks :-)\n",

             orig_cmdline, DMS(mem_limit << 20)); /* ignore errors */

  fclose(f);

}



static u8 compare_i2s(struct I2S_CK* i2sa, struct I2S_CK* i2sb) {
  while (i2sa && i2sb) {
    if (i2sa->key != i2sb->key) {
      return 1;
    }
    i2sa = i2sa->next;
    i2sb = i2sb->next;
  }
  if (i2sa==NULL && i2sb==NULL){
    return 0;
  }
  return 1;
}

#if 0
static u8 save_with_I2S(void* mem, u32 len, u64 addr, struct I2S_CK* i2s, u8 status, u32 cksum) {

  u8  *fn;
  s32 fd;
  if (!i2s) return 0;
  struct I2S_CK* cur = NULL;
  struct I2S_CK* new = NULL;
  struct queue_entry *q = queue;

  while (i2s->next) {
	  i2s = i2s->next;
  }
  
  
  while (i2s) {
	// copy from orig i2s
	  new = ck_alloc_nozero(sizeof(struct I2S_CK));
	  new->key = i2s->key;
	  new->idx = i2s->idx;
	  new->hits = i2s->hits;
	  new->is_v0 = i2s->is_v0;
	  new->t_op = i2s->t_op;
	
	// insert
	  new->prev = NULL;
    new->next = cur;
    if (cur) {
	    cur->prev = new;
    }
    cur = new;
	  i2s = i2s->prev;
  }
	
  if (status == 1) {

    if (unlikely(!queue_top->fti_info)) {
      queue_top->fti_info = kh_init(PTR);
    }
    
    struct mmio* mmio = get_mmio_by_addr(&g_stream_input, addr);
    struct fti_taint* taint = NULL;
    khiter_t iter = kh_get(PTR, queue_top->fti_info, mmio->stream_id);
    if( iter != kh_end(queue_top->fti_info)) {
      if(kh_exist(queue_top->fti_info, iter)) {
        taint = kh_value(queue_top->fti_info, iter);
      }
    }else{
      int kh_res;
      taint = ck_alloc(sizeof(struct fti_taint));
      iter = kh_put(PTR, queue_top->fti_info, mmio->stream_id, &kh_res);
      kh_value(queue_top->fti_info, iter) = taint;
    }
    fprintf(stderr,"save with i2s, addr:%016lx\n",addr);
    taint->I2S = cur;
    return 0;
  }

  while (cur) {
    i2s = cur;
    cur = cur->next;
    ck_free(i2s);
  }

  return 0;
}

#endif

/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. */

static u8 save_if_interesting(void* mem, u32 len, u8 fault) {

  char  *fn = "";
  u8  hnb;
  s32 fd;
  u8  keeping = 0, res;

  if (fault == crash_mode) {

    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */

    if (!(hnb = has_new_bits(virgin_bits))) {
      if (crash_mode) total_crashes++;
      return 0;
    }    

#ifndef SIMPLE_FILES

    fn = (char*)alloc_printf("%s/queue/id:%06u,%s", out_dir, queued_paths,
                      describe_op(hnb));

#else

    fn = (char*)alloc_printf("%s/queue/id_%06u", out_dir, queued_paths);

#endif /* ^!SIMPLE_FILES */

    add_to_queue((u8*)fn, len, 0);

    if (hnb == 2) {
      queue_top->has_new_cov = 1;
      queued_with_cov++;
    }

    //queue_top->exec_cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */

    res = calibrate_case(queue_top, mem, queue_cycle - 1, 0);
    
    
    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    ck_write(fd, mem, len, fn);
    close(fd);

    keeping = 1;

  }

  switch (fault) {

    case FAULT_TMOUT:

      /* Timeouts are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "dumb" mode, we
         just keep everything. */

      total_tmouts++;

      if (unique_hangs >= KEEP_UNIQUE_HANG) return keeping;

      if (!dumb_mode) {

#ifdef WORD_SIZE_64
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);
#endif /* ^WORD_SIZE_64 */

        if (!has_new_bits(virgin_tmout)) return keeping;

      }

      unique_tmouts++;

      /* Before saving, we make sure that it's a genuine hang by re-running
         the target with a more generous timeout (unless the default timeout
         is already generous). */

      //if (exec_tmout < hang_tmout) {

      //  u8 new_fault;
      //  new_fault = run_target();

        /* A corner case that one user reported bumping into: increasing the
           timeout actually uncovers a crash. Make sure we don't discard it if
           so. */

      //  if (!stop_soon && new_fault == FAULT_CRASH) goto keep_as_crash;

       // if (stop_soon || new_fault != FAULT_TMOUT) return keeping;

     // }

#ifndef SIMPLE_FILES

      fn = (char*)alloc_printf("%s/hangs/id:%06llu,%s", out_dir,
                        unique_hangs, describe_op(0));

#else

      fn = (char*)alloc_printf("%s/hangs/id_%06llu", out_dir,
                        unique_hangs);

#endif /* ^!SIMPLE_FILES */

      unique_hangs++;

      last_hang_time = get_cur_time();

      break;

    case FAULT_CRASH:

keep_as_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      total_crashes++;

      if (unique_crashes >= KEEP_UNIQUE_CRASH) return keeping;

      if (!dumb_mode) {

#ifdef WORD_SIZE_64
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);
#endif /* ^WORD_SIZE_64 */

        if (!has_new_bits(virgin_crash)) return keeping;

      }

      if (!unique_crashes) write_crash_readme();

#ifndef SIMPLE_FILES

      fn = (char*)alloc_printf("%s/crashes/id:%06llu,sig:%02u,%s", out_dir,
                        unique_crashes, kill_signal, describe_op(0));

#else

      fn = (char*)alloc_printf("%s/crashes/id_%06llu_%02u", out_dir, unique_crashes,
                        kill_signal);

#endif /* ^!SIMPLE_FILES */

      unique_crashes++;

      last_crash_time = get_cur_time();
      last_crash_execs = total_execs;

      break;

    case FAULT_ERROR: FATAL("Unable to execute target application");

    default: return keeping;

  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  ck_write(fd, mem, len, fn);
  close(fd);

  ck_free(fn);

  return keeping;

}


/* When resuming, try to find the queue position to start from. This makes sense
   only when resuming, and when we can find the original fuzzer_stats. */

static u32 find_start_position(void) {

  static u8 tmp[4096]; /* Ought to be enough for anybody. */

  u8  *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!resuming_fuzz) return 0;

  if (in_place_resume) fn = alloc_printf("%s/fuzzer_stats", out_dir);
  else fn = alloc_printf("%s/../fuzzer_stats", in_dir);

  fd = open((char*)fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0) return 0;

  i = read(fd, tmp, sizeof(tmp) - 1); (void)i; /* Ignore errors */
  close(fd);

  off = (u8*)strstr((char*)tmp, "cur_path          : ");
  if (!off) return 0;

  ret = atoi((char*)off + 20);
  if (ret >= queued_paths) ret = 0;
  return ret;

}





/* Update stats file for unattended monitoring. */

static void write_stats_file(double bitmap_cvg, double stability, double eps) {

  static double last_bcvg, last_stab, last_eps;
  static struct rusage usage;

  u8* fn = alloc_printf("%s/fuzzer_stats", out_dir);
  s32 fd;
  FILE* f;

  fd = open((char*)fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

  f = fdopen(fd, "w");

  if (!f) PFATAL("fdopen() failed");

  /* Keep last values in case we're called from another context
     where exec/sec stats and such are not readily available. */

  if (!bitmap_cvg && !stability && !eps) {
    bitmap_cvg = last_bcvg;
    stability  = last_stab;
    eps        = last_eps;
  } else {
    last_bcvg = bitmap_cvg;
    last_stab = stability;
    last_eps  = eps;
  }

  fprintf(f, "start_time        : %llu\n"
             "last_update       : %llu\n"
             "fuzzer_pid        : %u\n"
             "cycles_done       : %llu\n"
             "execs_done        : %llu\n"
             "execs_per_sec     : %0.02f\n"
             "paths_total       : %u\n"
             "paths_favored     : %u\n"
             "paths_found       : %u\n"
             "paths_imported    : %u\n"
             "max_depth         : %u\n"
             "cur_path          : %u\n" /* Must match find_start_position() */
             "pending_favs      : %u\n"
             "pending_total     : %u\n"
             "variable_paths    : %u\n"
             "stability         : %0.02f%%\n"
             "bitmap_cvg        : %0.02f%%\n"
             "unique_crashes    : %llu\n"
             "unique_hangs      : %llu\n"
             "last_path         : %llu\n"
             "last_crash        : %llu\n"
             "last_hang         : %llu\n"
             "execs_since_crash : %llu\n"
             "exec_timeout      : %u\n" /* Must match find_timeout() */
             "afl_banner        : %s\n"
             "afl_version       : " VERSION "\n"
             "target_mode       : %s%s%s%s%s%s%s\n"
             "command_line      : %s\n"
             "slowest_exec_ms   : %llu\n",
             start_time / 1000, get_cur_time() / 1000, getpid(),
             queue_cycle ? (queue_cycle - 1) : 0, total_execs, eps,
             queued_paths, queued_favored, queued_discovered, queued_imported,
             max_depth, current_entry, pending_favored, pending_not_fuzzed,
             queued_variable, stability, bitmap_cvg, unique_crashes,
             unique_hangs, last_path_time / 1000, last_crash_time / 1000,
             last_hang_time / 1000, total_execs - last_crash_execs,
             exec_tmout, use_banner,
             qemu_mode ? "qemu " : "", dumb_mode ? " dumb " : "",
             no_forkserver ? "no_forksrv " : "", crash_mode ? "crash " : "",
             persistent_mode ? "persistent " : "", deferred_mode ? "deferred " : "",
             (qemu_mode || dumb_mode || no_forkserver || crash_mode ||
              persistent_mode || deferred_mode) ? "" : "default",
             orig_cmdline, slowest_exec_ms);
             /* ignore errors */

  /* Get rss value from the children
     We must have killed the forkserver process and called waitpid
     before calling getrusage */
  if (getrusage(RUSAGE_CHILDREN, &usage)) {
      WARNF("getrusage failed");
  } else if (usage.ru_maxrss == 0) {
    fprintf(f, "peak_rss_mb       : not available while afl is running\n");
  } else {
#ifdef __APPLE__
    fprintf(f, "peak_rss_mb       : %zu\n", usage.ru_maxrss >> 20);
#else
    fprintf(f, "peak_rss_mb       : %zu\n", usage.ru_maxrss >> 10);
#endif /* ^__APPLE__ */
  }

  fclose(f);

}


/* Update the plot file if there is a reason to. */

static void maybe_update_plot_file(double bitmap_cvg, double eps) {

  static u32 prev_qp, prev_pf, prev_pnf, prev_ce, prev_md;
  static u64 prev_qc, prev_uc, prev_uh;

  if (prev_qp == queued_paths && prev_pf == pending_favored && 
      prev_pnf == pending_not_fuzzed && prev_ce == current_entry &&
      prev_qc == queue_cycle && prev_uc == unique_crashes &&
      prev_uh == unique_hangs && prev_md == max_depth) return;

  prev_qp  = queued_paths;
  prev_pf  = pending_favored;
  prev_pnf = pending_not_fuzzed;
  prev_ce  = current_entry;
  prev_qc  = queue_cycle;
  prev_uc  = unique_crashes;
  prev_uh  = unique_hangs;
  prev_md  = max_depth;

  /* Fields in the file:

     unix_time, cycles_done, cur_path, paths_total, paths_not_fuzzed,
     favored_not_fuzzed, unique_crashes, unique_hangs, max_depth,
     execs_per_sec */

  fprintf(plot_file, 
          "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f\n",
          get_cur_time() / 1000, queue_cycle - 1, current_entry, queued_paths,
          pending_not_fuzzed, pending_favored, bitmap_cvg, unique_crashes,
          unique_hangs, max_depth, eps); /* ignore errors */

  fflush(plot_file);

}



/* A helper function for maybe_delete_out_dir(), deleting all prefixed
   files in a directory. */

static u8 delete_files(u8* path, u8* prefix) {

  DIR* d;
  struct dirent* d_ent;

  d = opendir((char*)path);

  if (!d) return 0;

  while ((d_ent = readdir(d))) {

    if (d_ent->d_name[0] != '.' && (!prefix ||
        !strncmp(d_ent->d_name, (char*)prefix, strlen((char*)prefix)))) {

      u8* fname = alloc_printf("%s/%s", path, d_ent->d_name);
      if (unlink((char*)fname)) PFATAL("Unable to delete '%s'", fname);
      ck_free(fname);

    }

  }

  closedir(d);

  return !!rmdir((char*)path);

}


/* Get the number of runnable processes, with some simple smoothing. */

static double get_runnable_processes(void) {

  static double res;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

  /* I don't see any portable sysctl or so that would quickly give us the
     number of runnable processes; the 1-minute load average can be a
     semi-decent approximation, though. */

  if (getloadavg(&res, 1) != 1) return 0;

#else

  /* On Linux, /proc/stat is probably the best way; load averages are
     computed in funny ways and sometimes don't reflect extremely short-lived
     processes well. */

  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];
  u32 val = 0;

  if (!f) return 0;

  while (fgets((char*)tmp, sizeof(tmp), f)) {

    if (!strncmp((char*)tmp, "procs_running ", 14) ||
        !strncmp((char*)tmp, "procs_blocked ", 14)) val += atoi((char*)tmp + 14);

  }
 
  fclose(f);

  if (!res) {

    res = val;

  } else {

    res = res * (1.0 - 1.0 / AVG_SMOOTHING) +
          ((double)val) * (1.0 / AVG_SMOOTHING);

  }

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  return res;

}


/* Delete the temporary directory used for in-place session resume. */

static void nuke_resume_dir(void) {

  u8* fn;

  fn = alloc_printf("%s/_resume/.state/deterministic_done", out_dir);
  if (delete_files(fn, (u8*)CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/auto_extras", out_dir);
  if (delete_files(fn, (u8*)"auto_")) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/redundant_edges", out_dir);
  if (delete_files(fn, (u8*)CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/variable_behavior", out_dir);
  if (delete_files(fn, (u8*)CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state", out_dir);
  if (rmdir((char*)fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume", out_dir);
  if (delete_files(fn, (u8*)CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  return;

dir_cleanup_failed:

  FATAL("_resume directory cleanup failed");

}


/* Delete fuzzer output directory if we recognize it as ours, if the fuzzer
   is not currently running, and if the last run time isn't too great. */

static void maybe_delete_out_dir(void) {

  FILE* f;
  u8 *fn = alloc_printf("%s/fuzzer_stats", out_dir);

  /* See if the output directory is locked. If yes, bail out. If not,
     create a lock that will persist for the lifetime of the process
     (this requires leaving the descriptor open).*/

  out_dir_fd = open((char*)out_dir, O_RDONLY);
  if (out_dir_fd < 0) PFATAL("Unable to open '%s'", out_dir);

#ifndef __sun

  if (flock(out_dir_fd, LOCK_EX | LOCK_NB) && errno == EWOULDBLOCK) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like the job output directory is being actively used by another\n"
         "    instance of afl-fuzz. You will need to choose a different %s\n"
         "    or stop the other process first.\n",
         "output location");

    FATAL("Directory '%s' is in use", out_dir);

  }

#endif /* !__sun */

  f = fopen((char*)fn, "r");

  if (f) {

    u64 start_time, last_update;

    if (fscanf(f, "start_time     : %llu\n"
                  "last_update    : %llu\n", &start_time, &last_update) != 2)
      FATAL("Malformed data in '%s'", fn);

    fclose(f);

    /* Let's see how much work is at stake. */

    if (!in_place_resume && last_update - start_time > OUTPUT_GRACE * 60) {

      SAYF("\n" cLRD "[-] " cRST
           "The job output directory already exists and contains the results of more\n"
           "    than %u minutes worth of fuzzing. To avoid data loss, afl-fuzz will *NOT*\n"
           "    automatically delete this data for you.\n\n"

           "    If you wish to start a new session, remove or rename the directory manually,\n"
           "    or specify a different output location for this job. To resume the old\n"
           "    session, put '-' as the input directory in the command line ('-i -') and\n"
           "    try again.\n", OUTPUT_GRACE);

       FATAL("At-risk data found in '%s'", out_dir);

    }

  }

  ck_free(fn);

  /* The idea for in-place resume is pretty simple: we temporarily move the old
     queue/ to a new location that gets deleted once import to the new queue/
     is finished. If _resume/ already exists, the current queue/ may be
     incomplete due to an earlier abort, so we want to use the old _resume/
     dir instead, and we let rename() fail silently. */

  if (in_place_resume) {

    u8* orig_q = alloc_printf("%s/queue", out_dir);

    in_dir = alloc_printf("%s/_resume", out_dir);

    rename((char*)orig_q, (char*)in_dir); /* Ignore errors */

    OKF("Output directory exists, will attempt session resume.");

    ck_free(orig_q);

  } else {

    OKF("Output directory exists but deemed OK to reuse.");

  }

  ACTF("Deleting old session data...");

  /* Okay, let's get the ball rolling! First, we need to get rid of the entries
     in <out_dir>/.synced/.../id:*, if any are present. */

  if (!in_place_resume) {

    fn = alloc_printf("%s/.synced", out_dir);
    if (delete_files(fn, NULL)) goto dir_cleanup_failed;
    ck_free(fn);

  }

  /* Next, we need to clean up <out_dir>/queue/.state/ subdirectories: */

  fn = alloc_printf("%s/queue/.state/deterministic_done", out_dir);
  if (delete_files(fn, (u8*)CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/auto_extras", out_dir);
  if (delete_files(fn, (u8*)"auto_")) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/redundant_edges", out_dir);
  if (delete_files(fn, (u8*)CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/variable_behavior", out_dir);
  if (delete_files(fn, (u8*)CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* Then, get rid of the .state subdirectory itself (should be empty by now)
     and everything matching <out_dir>/queue/id:*. */

  fn = alloc_printf("%s/queue/.state", out_dir);
  if (rmdir((char*)fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue", out_dir);
  if (delete_files(fn, (u8*)CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);
  
  if (cmplog_mode) {
    fn = alloc_printf("%s/taint", out_dir);
    if (delete_files(fn, (u8*)CASE_PREFIX)) goto dir_cleanup_failed;
    ck_free(fn);
  }
  
  /* All right, let's do <out_dir>/crashes/id:* and <out_dir>/hangs/id:*. */

  if (!in_place_resume) {

    fn = alloc_printf("%s/crashes/README.txt", out_dir);
    unlink((char*)fn); /* Ignore errors */
    ck_free(fn);

  }

  fn = alloc_printf("%s/crashes", out_dir);

  /* Make backup of the crashes directory if it's not empty and if we're
     doing in-place resume. */

  if (in_place_resume && rmdir((char*)fn)) {

    time_t cur_t = time(0);
    struct tm* t = localtime(&cur_t);

#ifndef SIMPLE_FILES

    u8* nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#else

    u8* nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#endif /* ^!SIMPLE_FILES */

    rename((char*)fn, (char*)nfn); /* Ignore errors. */
    ck_free(nfn);

  }

  if (delete_files(fn, (u8*)CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/hangs", out_dir);

  /* Backup hangs, too. */

  if (in_place_resume && rmdir((char*)fn)) {

    time_t cur_t = time(0);
    struct tm* t = localtime(&cur_t);

#ifndef SIMPLE_FILES

    u8* nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#else

    u8* nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#endif /* ^!SIMPLE_FILES */

    rename((char*)fn, (char*)nfn); /* Ignore errors. */
    ck_free(nfn);

  }

  if (delete_files(fn, (u8*)CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* And now, for some finishing touches. */

  fn = alloc_printf("%s/.cur_input", out_dir);
  if (unlink((char*)fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/fuzz_bitmap", out_dir);
  if (unlink((char*)fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  if (!in_place_resume) {
    fn  = alloc_printf("%s/fuzzer_stats", out_dir);
    if (unlink((char*)fn) && errno != ENOENT) goto dir_cleanup_failed;
    ck_free(fn);
  }

  fn = alloc_printf("%s/plot_data", out_dir);
  if (unlink((char*)fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  OKF("Output dir cleanup successful.");

  /* Wow... is that all? If yes, celebrate! */

  return;

dir_cleanup_failed:

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, the fuzzer tried to reuse your output directory, but bumped into\n"
       "    some files that shouldn't be there or that couldn't be removed - so it\n"
       "    decided to abort! This happened while processing this path:\n\n"

       "    %s\n\n"
       "    Please examine and manually delete the files, or specify a different\n"
       "    output location for the tool.\n", fn);

  FATAL("Output directory cleanup failed");

}


static void check_term_size(void);


/* A spiffy retro stats screen! This is called every stats_update_freq
   execve() calls, plus in several other circumstances. */

static void show_stats(void) {

  static u64 last_stats_ms, last_plot_ms, last_ms, last_execs;
  static double avg_exec;
  double t_byte_ratio, stab_ratio;

  u64 cur_ms;
  u32 t_bytes, t_bits;

  u32 banner_len, banner_pad;
  u8  tmp[256];

  cur_ms = get_cur_time();

  /* If not enough time has passed since last UI update, bail out. */

  if (cur_ms - last_ms < 1000 / UI_TARGET_HZ) return;

  /* Check if we're past the 10 minute mark. */

  if (cur_ms - start_time > 10 * 60 * 1000) run_over10m = 1;

  /* Calculate smoothed exec speed stats. */

  if (!last_execs) {
  
    avg_exec = ((double)total_execs) * 1000 / (cur_ms - start_time);

  } else {

    double cur_avg = ((double)(total_execs - last_execs)) * 1000 /
                     (cur_ms - last_ms);

    /* If there is a dramatic (5x+) jump in speed, reset the indicator
       more quickly. */

    if (cur_avg * 5 < avg_exec || cur_avg / 5 > avg_exec)
      avg_exec = cur_avg;

    avg_exec = avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +
               cur_avg * (1.0 / AVG_SMOOTHING);

  }

  last_ms = cur_ms;
  last_execs = total_execs;

  /* Tell the callers when to contact us (as measured in execs). */

  stats_update_freq = avg_exec / (UI_TARGET_HZ * 10);
  if (!stats_update_freq) stats_update_freq = 1;

  /* Do some bitmap stats. */

  t_bytes = count_non_255_bytes(virgin_bits);
  t_byte_ratio = ((double)t_bytes * 100) / MAP_SIZE;

  if (t_bytes) 
    stab_ratio = 100 - ((double)var_byte_count) * 100 / t_bytes;
  else
    stab_ratio = 100;

  /* Roughly every minute, update fuzzer stats and save auto tokens. */

  if (cur_ms - last_stats_ms > STATS_UPDATE_SEC * 1000) {

    last_stats_ms = cur_ms;
    write_stats_file(t_byte_ratio, stab_ratio, avg_exec);
    save_auto();
    write_bitmap();

  }

  /* Every now and then, write plot data. */

  if (cur_ms - last_plot_ms > PLOT_UPDATE_SEC * 1000) {

    last_plot_ms = cur_ms;
    maybe_update_plot_file(t_byte_ratio, avg_exec);
 
  }

  /* Honor AFL_EXIT_WHEN_DONE and AFL_BENCH_UNTIL_CRASH. */

  if (!dumb_mode && cycles_wo_finds > 100 && !pending_not_fuzzed &&
      getenv("AFL_EXIT_WHEN_DONE")) stop_soon = 2;

  if (total_crashes && getenv("AFL_BENCH_UNTIL_CRASH")) stop_soon = 2;

  /* If we're not on TTY, bail out. */

  if (not_on_tty) return;

  /* Compute some mildly useful bitmap stats. */

  t_bits = (MAP_SIZE << 3) - count_bits(virgin_bits);

  /* Now, for the visuals... */

  if (clear_screen) {

    SAYF(TERM_CLEAR CURSOR_HIDE);
    clear_screen = 0;

    check_term_size();

  }

  SAYF(TERM_HOME);

  if (term_too_small) {

    SAYF(cBRI "Your terminal is too small to display the UI.\n"
         "Please resize terminal window to at least 80x25.\n" cRST);

    return;

  }

  /* Let's start by drawing a centered banner. */
  banner_len = (crash_mode ? 24 : 22) + strlen(VERSION) + strlen(use_banner);
  banner_pad = (80 - banner_len) / 2;
  memset(tmp, ' ', banner_pad);

  sprintf(tmp + banner_pad, "%s " cLCY VERSION cLGN
          " (%s)",  crash_mode ? cPIN "peruvian were-rabbit" : 
          cYEL "american fuzzy lop", use_banner);
  SAYF("\n%s\n\n", tmp);

  /* "Handy" shortcuts for drawing boxes... */

#define bSTG    bSTART cGRA
#define bH2     bH bH
#define bH5     bH2 bH2 bH
#define bH10    bH5 bH5
#define bH20    bH10 bH10
#define bH30    bH20 bH10
#define SP5     "     "
#define SP10    SP5 SP5
#define SP20    SP10 SP10

  /* Lord, forgive me this. */

  SAYF(SET_G1 bSTG bLT bH bSTOP cCYA " process timing " bSTG bH30 bH5 bH2 bHB
       bH bSTOP cCYA " overall results " bSTG bH5 bRT "\n");

  if (dumb_mode) {

    strcpy(tmp, cRST);

  } else {

    u64 min_wo_finds = (cur_ms - last_path_time) / 1000 / 60;

    /* First queue cycle: don't stop now! */
    if (queue_cycle == 1 || min_wo_finds < 15) strcpy(tmp, cMGN); else

    /* Subsequent cycles, but we're still making finds. */
    if (cycles_wo_finds < 25 || min_wo_finds < 30) strcpy(tmp, cYEL); else

    /* No finds for a long time and no test cases to try. */
    if (cycles_wo_finds > 100 && !pending_not_fuzzed && min_wo_finds > 120)
      strcpy(tmp, cLGN);

    /* Default: cautiously OK to stop? */
    else strcpy(tmp, cLBL);

  }

  SAYF(bV bSTOP "        run time : " cRST "%-34s " bSTG bV bSTOP
       "  cycles done : %s%-5s  " bSTG bV "\n",
       DTD(cur_ms, start_time), tmp, DI(queue_cycle - 1));

  /* We want to warn people about not seeing new paths after a full cycle,
     except when resuming fuzzing or running in non-instrumented mode. */

  if (!dumb_mode && (last_path_time || resuming_fuzz || queue_cycle == 1 ||
      in_bitmap || crash_mode)) {

    SAYF(bV bSTOP "   last new path : " cRST "%-34s ",
         DTD(cur_ms, last_path_time));

  } else {

    if (dumb_mode)

      SAYF(bV bSTOP "   last new path : " cPIN "n/a" cRST 
           " (non-instrumented mode)        ");

     else

      SAYF(bV bSTOP "   last new path : " cRST "none yet " cLRD
           "(odd, check syntax!)      ");

  }

  SAYF(bSTG bV bSTOP "  total paths : " cRST "%-5s  " bSTG bV "\n",
       DI(queued_paths));

  /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
     limit with a '+' appended to the count. */

  sprintf(tmp, "%s%s", DI(unique_crashes),
          (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  SAYF(bV bSTOP " last uniq crash : " cRST "%-34s " bSTG bV bSTOP
       " uniq crashes : %s%-6s " bSTG bV "\n",
       DTD(cur_ms, last_crash_time), unique_crashes ? cLRD : cRST,
       tmp);

  sprintf(tmp, "%s%s", DI(unique_hangs),
         (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bV bSTOP "  last uniq hang : " cRST "%-34s " bSTG bV bSTOP 
       "   uniq hangs : " cRST "%-6s " bSTG bV "\n",
       DTD(cur_ms, last_hang_time), tmp);

  SAYF(bVR bH bSTOP cCYA " cycle progress " bSTG bH20 bHB bH bSTOP cCYA
       " map coverage " bSTG bH bHT bH20 bH2 bH bVL "\n");

  /* This gets funny because we want to print several variable-length variables
     together, but then cram them into a fixed-width field - so we need to
     put them in a temporary buffer first. */

  sprintf(tmp, "%s%s (%0.02f%%)", DI(current_entry),
          queue_cur->favored ? "" : "*",
          ((double)current_entry * 100) / queued_paths);

  SAYF(bV bSTOP "  now processing : " cRST "%-17s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%0.02f%% / %0.02f%%", ((double)queue_cur->bitmap_size) * 
          100 / MAP_SIZE, t_byte_ratio);

  SAYF("    map density : %s%-21s " bSTG bV "\n", t_byte_ratio > 70 ? cLRD : 
       ((t_bytes < 200 && !dumb_mode) ? cPIN : cRST), tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(cur_skipped_paths),
          ((double)cur_skipped_paths * 100) / queued_paths);

  SAYF(bV bSTOP " paths timed out : " cRST "%-17s " bSTG bV, tmp);

  sprintf(tmp, "%0.02f bits/tuple",
          t_bytes ? (((double)t_bits) / t_bytes) : 0);

  SAYF(bSTOP " count coverage : " cRST "%-21s " bSTG bV "\n", tmp);

  SAYF(bVR bH bSTOP cCYA " stage progress " bSTG bH20 bX bH bSTOP cCYA
       " findings in depth " bSTG bH20 bVL "\n");

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_favored),
          ((double)queued_favored) * 100 / queued_paths);

  /* Yeah... it's still going on... halp? */

  SAYF(bV bSTOP "  now trying : " cRST "%-21s " bSTG bV bSTOP 
       " favored paths : " cRST "%-22s " bSTG bV "\n", stage_name, tmp);

  if (!stage_max) {

    sprintf(tmp, "%s/-", DI(stage_cur));

  } else {

    sprintf(tmp, "%s/%s (%0.02f%%)", DI(stage_cur), DI(stage_max),
            ((double)stage_cur) * 100 / stage_max);

  }

  SAYF(bV bSTOP " stage execs : " cRST "%-21s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_with_cov),
          ((double)queued_with_cov) * 100 / queued_paths);

  SAYF("  new edges on : " cRST "%-22s " bSTG bV "\n", tmp);

  sprintf(tmp, "%s (%s%s unique)", DI(total_crashes), DI(unique_crashes),
          (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  if (crash_mode) {

    SAYF(bV bSTOP " total execs : " cRST "%-21s " bSTG bV bSTOP
         "   new crashes : %s%-22s " bSTG bV "\n", DI(total_execs),
         unique_crashes ? cLRD : cRST, tmp);

  } else {

    SAYF(bV bSTOP " total execs : " cRST "%-21s " bSTG bV bSTOP
         " total crashes : %s%-22s " bSTG bV "\n", DI(total_execs),
         unique_crashes ? cLRD : cRST, tmp);

  }

  /* Show a warning about slow execution. */

  if (avg_exec < 100) {

    sprintf(tmp, "%s/sec (%s)", DF(avg_exec), avg_exec < 20 ?
            "zzzz..." : "slow!");

    SAYF(bV bSTOP "  exec speed : " cLRD "%-21s ", tmp);

  } else {

    sprintf(tmp, "%s/sec", DF(avg_exec));
    SAYF(bV bSTOP "  exec speed : " cRST "%-21s ", tmp);

  }

  sprintf(tmp, "%s (%s%s unique)", DI(total_tmouts), DI(unique_tmouts),
          (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF (bSTG bV bSTOP "  total tmouts : " cRST "%-22s " bSTG bV "\n", tmp);

  /* Aaaalmost there... hold on! */

  SAYF(bVR bH cCYA bSTOP " fuzzing strategy yields " bSTG bH10 bH bHT bH10
       bH5 bHB bH bSTOP cCYA " path geometry " bSTG bH5 bH2 bH bVL "\n");

  if (skip_deterministic) {

    strcpy(tmp, "n/a, n/a, n/a");

  } else {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_FLIP1]), DI(stage_cycles[STAGE_FLIP1]),
            DI(stage_finds[STAGE_FLIP2]), DI(stage_cycles[STAGE_FLIP2]),
            DI(stage_finds[STAGE_FLIP4]), DI(stage_cycles[STAGE_FLIP4]));

  }

  SAYF(bV bSTOP "   bit flips : " cRST "%-37s " bSTG bV bSTOP "    levels : "
       cRST "%-10s " bSTG bV "\n", tmp, DI(max_depth));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_FLIP8]), DI(stage_cycles[STAGE_FLIP8]),
            DI(stage_finds[STAGE_FLIP16]), DI(stage_cycles[STAGE_FLIP16]),
            DI(stage_finds[STAGE_FLIP32]), DI(stage_cycles[STAGE_FLIP32]));

  SAYF(bV bSTOP "  byte flips : " cRST "%-37s " bSTG bV bSTOP "   pending : "
       cRST "%-10s " bSTG bV "\n", tmp, DI(pending_not_fuzzed));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_ARITH8]), DI(stage_cycles[STAGE_ARITH8]),
            DI(stage_finds[STAGE_ARITH16]), DI(stage_cycles[STAGE_ARITH16]),
            DI(stage_finds[STAGE_ARITH32]), DI(stage_cycles[STAGE_ARITH32]));

  SAYF(bV bSTOP " arithmetics : " cRST "%-37s " bSTG bV bSTOP "  pend fav : "
       cRST "%-10s " bSTG bV "\n", tmp, DI(pending_favored));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_INTEREST8]), DI(stage_cycles[STAGE_INTEREST8]),
            DI(stage_finds[STAGE_INTEREST16]), DI(stage_cycles[STAGE_INTEREST16]),
            DI(stage_finds[STAGE_INTEREST32]), DI(stage_cycles[STAGE_INTEREST32]));

  SAYF(bV bSTOP "  known ints : " cRST "%-37s " bSTG bV bSTOP " own finds : "
       cRST "%-10s " bSTG bV "\n", tmp, DI(queued_discovered));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_EXTRAS_UO]), DI(stage_cycles[STAGE_EXTRAS_UO]),
            DI(stage_finds[STAGE_EXTRAS_UI]), DI(stage_cycles[STAGE_EXTRAS_UI]),
            DI(stage_finds[STAGE_EXTRAS_AO]), DI(stage_cycles[STAGE_EXTRAS_AO]));

  SAYF(bV bSTOP "  dictionary : " cRST "%-37s " bSTG bV bSTOP
       "  imported : " cRST "%-10s " bSTG bV "\n", tmp,
       (u8*)"n/a");

  sprintf(tmp, "%s/%s, %s/%s, %s/%s",
          DI(stage_finds[STAGE_HAVOC]), DI(stage_cycles[STAGE_HAVOC]),
          DI(stage_finds[STAGE_SPLICE]), DI(stage_cycles[STAGE_SPLICE]),
          DI(stage_finds[STAGE_EXTEND]), DI(stage_cycles[STAGE_EXTEND]));

  SAYF(bV bSTOP "  havoc(ext) : " cRST "%-37s " bSTG bV bSTOP, tmp);

  if (t_bytes) sprintf(tmp, "%0.02f%%", stab_ratio);
    else strcpy(tmp, "n/a");
  
  

  SAYF(" stability : %s%-10s " bSTG bV "\n", (stab_ratio < 85 && var_byte_count > 40) 
       ? cLRD : ((queued_variable && (!persistent_mode || var_byte_count > 20))
       ? cMGN : cRST), tmp);

    /* cmplog stats */
  if (!cmplog_mode) {
	sprintf(tmp, "n/a, n/a");
  }else {
	sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_FTI]), DI(stage_cycles[STAGE_FTI]),
            DI(stage_finds[STAGE_COLORIZATION]), DI(stage_cycles[STAGE_COLORIZATION]),
            DI(stage_finds[STAGE_ITS]), DI(stage_cycles[STAGE_ITS]));
  }
  
  SAYF(bV bSTOP "     fti+its : " cRST "%-37s " bSTG bV bSTOP, tmp);
  SAYF("                        " bSTG bV "\n", tmp);

  if (!bytes_trim_out) {

    sprintf(tmp, "n/a, ");

  } else {

    sprintf(tmp, "%0.02f%%/%s, ",
            ((double)(bytes_trim_in - bytes_trim_out)) * 100 / bytes_trim_in,
            DI(trim_execs));

  }

  if (!blocks_eff_total) {

    u8 tmp2[128];

    sprintf(tmp2, "n/a");
    strcat(tmp, tmp2);

  } else {

    u8 tmp2[128];

    sprintf(tmp2, "%0.02f%%",
            ((double)(blocks_eff_total - blocks_eff_select)) * 100 /
            blocks_eff_total);

    strcat(tmp, tmp2);

  }

  SAYF(bV bSTOP "        trim : " cRST "%-37s " bSTG bVR bH20 bH2 bH2 bRB "\n"
       bLB bH30 bH20 bH2 bH bRB bSTOP cRST RESET_G1, tmp);

  
  /* Provide some CPU utilization stats. */

  if (cpu_core_count) {

    double cur_runnable = get_runnable_processes();
    u32 cur_utilization = cur_runnable * 100 / cpu_core_count;

    u8* cpu_color = cCYA;

    /* If we could still run one or more processes, use green. */

    if (cpu_core_count > 1 && cur_runnable + 1 <= cpu_core_count)
      cpu_color = cLGN;

    /* If we're clearly oversubscribed, use red. */

    if (!no_cpu_meter_red && cur_utilization >= 150) cpu_color = cLRD;

#ifdef HAVE_AFFINITY

    if (cpu_aff >= 0) {

      SAYF(SP10 cGRA "[cpu%03u:%s%3u%%" cGRA "]\r" cRST, 
           MIN(cpu_aff, 999), cpu_color,
           MIN(cur_utilization, 999));

    } else {

      SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
           cpu_color, MIN(cur_utilization, 999));
 
   }

#else

    SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
         cpu_color, MIN(cur_utilization, 999));

#endif /* ^HAVE_AFFINITY */

  } else SAYF("\r");

  /* Hallelujah! */

  fflush(0);

}



/* Display quick statistics at the end of processing the input directory,
   plus a bunch of warnings. Some calibration stuff also ended up here,
   along with several hardcoded constants. Maybe clean up eventually. */

static void show_init_stats(void) {

  struct queue_entry* q = queue;
  u32 min_bits = 0, max_bits = 0;
  u64 min_us = 0, max_us = 0;
  u64 avg_us = 0;
  u32 max_len = 0;

  if (total_cal_cycles) avg_us = total_cal_us / total_cal_cycles;

  while (q) {

    if (!min_us || q->exec_us < min_us) min_us = q->exec_us;
    if (q->exec_us > max_us) max_us = q->exec_us;

    if (!min_bits || q->bitmap_size < min_bits) min_bits = q->bitmap_size;
    if (q->bitmap_size > max_bits) max_bits = q->bitmap_size;

    if (q->len > max_len) max_len = q->len;

    q = q->next;

  }

  SAYF("\n");

  if (avg_us > (qemu_mode ? 50000 : 10000)) 
    WARNF(cLRD "The target binary is pretty slow!");

  /* Let's keep things moving with slow binaries. */

  if (avg_us > 50000) havoc_div = 10;     /* 0-19 execs/sec   */
  else if (avg_us > 20000) havoc_div = 5; /* 20-49 execs/sec  */
  else if (avg_us > 10000) havoc_div = 2; /* 50-100 execs/sec */

  if (!resuming_fuzz) {

    if (max_len > 50 * 1024)
      WARNF(cLRD "Some test cases are huge (%s)",
            DMS(max_len));
    else if (max_len > 10 * 1024)
      WARNF("Some test cases are big (%s)",
            DMS(max_len));

    if (useless_at_start && !in_bitmap)
      WARNF(cLRD "Some test cases look useless. Consider using a smaller set.");

    if (queued_paths > 100)
      WARNF(cLRD "You probably have far too many input files! Consider trimming down.");
    else if (queued_paths > 20)
      WARNF("You have lots of input files; try starting small.");

  }

  OKF("Here are some useful stats:\n\n"

      cGRA "    Test case count : " cRST "%u favored, %u variable, %u total\n"
      cGRA "       Bitmap range : " cRST "%u to %u bits (average: %0.02f bits)\n"
      cGRA "        Exec timing : " cRST "%s to %s us (average: %s us)\n",
      queued_favored, queued_variable, queued_paths, min_bits, max_bits, 
      ((double)total_bitmap_size) / (total_bitmap_entries ? total_bitmap_entries : 1),
      DI(min_us), DI(max_us), DI(avg_us));

  if (!timeout_given) {

    /* Figure out the appropriate timeout. The basic idea is: 5x average or
       1x max, rounded up to EXEC_TM_ROUND ms and capped at 1 second.

       If the program is slow, the multiplier is lowered to 2x or 3x, because
       random scheduler jitter is less likely to have any impact, and because
       our patience is wearing thin =) */

    if (avg_us > 50000) exec_tmout = avg_us * 2 / 1000;
    else if (avg_us > 10000) exec_tmout = avg_us * 3 / 1000;
    else exec_tmout = avg_us * 5 / 1000;

    exec_tmout = MAX(exec_tmout, max_us / 1000);
    exec_tmout = (exec_tmout + EXEC_TM_ROUND) / EXEC_TM_ROUND * EXEC_TM_ROUND;

    if (exec_tmout > EXEC_TIMEOUT) exec_tmout = EXEC_TIMEOUT;

    ACTF("No -t option specified, so I'll use exec timeout of %u ms.", 
         exec_tmout);

    timeout_given = 1;

  } else if (timeout_given == 3) {

    ACTF("Applying timeout settings from resumed session (%u ms).", exec_tmout);

  }

  /* In dumb mode, re-running every timing out test case with a generous time
     limit is very expensive, so let's select a more conservative default. */

  if (dumb_mode && !getenv("AFL_HANG_TMOUT"))
    hang_tmout = MIN(EXEC_TIMEOUT, exec_tmout * 2 + 100);

  OKF("All set and ready to roll!");

}


/* Find first power of two greater or equal to val (assuming val under
   2^31). */

static u32 next_p2(u32 val) {

  u32 ret = 1;
  while (val > ret) ret <<= 1;
  return ret;

} 



/* Write a modified test case, run program, process results. Handle
   error conditions, returning 1 if it's time to bail out. This is
   a helper function for fuzz_one(). */

EXP_ST u8 common_fuzz_stuff(u8* out_buf, u32 len) {

  u8 fault = run_target();

  if (stop_soon) return 1;

  if (fault == FAULT_TMOUT) {

    if (subseq_tmouts++ > TMOUT_LIMIT) {
      cur_skipped_paths++;
      return 1;
    }

  } else subseq_tmouts = 0;

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (skip_requested) {

     skip_requested = 0;
     cur_skipped_paths++;
     return 1;

  }

  /* This handles FAULT_ERROR for us: */

  queued_discovered += save_if_interesting(out_buf, len, fault);

  if (!(stage_cur % stats_update_freq) || stage_cur + 1 == stage_max)
    show_stats();

  return 0;

}


/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */

static u32 choose_block_len(u32 limit) {

  u32 min_value, max_value;
  u32 rlim = MIN(queue_cycle, 3);

  if (!run_over10m) rlim = 1;

  switch (UR(rlim)) {

    case 0:  min_value = 1;
             max_value = HAVOC_BLK_SMALL;
             break;

    case 1:  min_value = HAVOC_BLK_SMALL;
             max_value = HAVOC_BLK_MEDIUM;
             break;

    default: 

             if (UR(10)) {

               min_value = HAVOC_BLK_MEDIUM;
               max_value = HAVOC_BLK_LARGE;

             } else {

               min_value = HAVOC_BLK_LARGE;
               max_value = HAVOC_BLK_XL;

             }

  }

  if (min_value >= limit) min_value = 1;

  return min_value + UR(MIN(max_value, limit) - min_value + 1);

}


/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. */

static u32 calculate_score(struct queue_entry* q) {

  u32 avg_exec_us = total_cal_us / total_cal_cycles;
  u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */

  if (q->exec_us * 0.1 > avg_exec_us) perf_score = 10;
  else if (q->exec_us * 0.25 > avg_exec_us) perf_score = 25;
  else if (q->exec_us * 0.5 > avg_exec_us) perf_score = 50;
  else if (q->exec_us * 0.75 > avg_exec_us) perf_score = 75;
  else if (q->exec_us * 4 < avg_exec_us) perf_score = 300;
  else if (q->exec_us * 3 < avg_exec_us) perf_score = 200;
  else if (q->exec_us * 2 < avg_exec_us) perf_score = 150;

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x. */

  if (q->bitmap_size * 0.3 > avg_bitmap_size) perf_score *= 3;
  else if (q->bitmap_size * 0.5 > avg_bitmap_size) perf_score *= 2;
  else if (q->bitmap_size * 0.75 > avg_bitmap_size) perf_score *= 1.5;
  else if (q->bitmap_size * 3 < avg_bitmap_size) perf_score *= 0.25;
  else if (q->bitmap_size * 2 < avg_bitmap_size) perf_score *= 0.5;
  else if (q->bitmap_size * 1.5 < avg_bitmap_size) perf_score *= 0.75;

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. */

  if (q->handicap >= 4) {

    perf_score *= 4;
    q->handicap -= 4;

  } else if (q->handicap) {

    perf_score *= 2;
    q->handicap--;

  }

  /* Final adjustment based on input depth, under the assumption that fuzzing
     deeper test cases is more likely to reveal stuff that can't be
     discovered with traditional fuzzers. */

  switch (q->depth) {

    case 0 ... 3:   break;
    case 4 ... 7:   perf_score *= 2; break;
    case 8 ... 13:  perf_score *= 3; break;
    case 14 ... 25: perf_score *= 4; break;
    default:        perf_score *= 5;

  }

  /* Make sure that we don't go over limit. */

  if (perf_score > HAVOC_MAX_MULT * 100) perf_score = HAVOC_MAX_MULT * 100;

  return perf_score;

}


/* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by afl-fuzz. This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. */

static u8 could_be_bitflip(u32 xor_val) {

  u32 sh = 0;

  if (!xor_val) return 1;

  /* Shift left until first bit set. */

  while (!(xor_val & 1)) { sh++; xor_val >>= 1; }

  /* 1-, 2-, and 4-bit patterns are OK anywhere. */

  if (xor_val == 1 || xor_val == 3 || xor_val == 15) return 1;

  /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */

  if (sh & 7) return 0;

  if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff)
    return 1;

  return 0;

}


/* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */

static u8 could_be_arith(u32 old_val, u32 new_val, u8 blen) {

  u32 i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val) return 1;

  /* See if one-byte adjustments to any byte could produce this result. */

  for (i = 0; i < blen; i++) {

    u8 a = old_val >> (8 * i),
       b = new_val >> (8 * i);

    if (a != b) { diffs++; ov = a; nv = b; }

  }

  /* If only one byte differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u8)(ov - nv) <= ARITH_MAX ||
        (u8)(nv - ov) <= ARITH_MAX) return 1;

  }

  if (blen == 1) return 0;

  /* See if two-byte adjustments to any byte would produce this result. */

  diffs = 0;

  for (i = 0; i < blen / 2; i++) {

    u16 a = old_val >> (16 * i),
        b = new_val >> (16 * i);

    if (a != b) { diffs++; ov = a; nv = b; }

  }

  /* If only one word differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u16)(ov - nv) <= ARITH_MAX ||
        (u16)(nv - ov) <= ARITH_MAX) return 1;

    ov = SWAP16(ov); nv = SWAP16(nv);

    if ((u16)(ov - nv) <= ARITH_MAX ||
        (u16)(nv - ov) <= ARITH_MAX) return 1;

  }

  /* Finally, let's do the same thing for dwords. */

  if (blen == 4) {

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) return 1;

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) return 1;

  }

  return 0;

}


/* Last but not least, a similar helper to see if insertion of an 
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique. */

static u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le) {

  u32 i, j;

  if (old_val == new_val) return 1;

  /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */

  for (i = 0; i < blen; i++) {

    for (j = 0; j < sizeof(interesting_8); j++) {

      u32 tval = (old_val & ~(0xff << (i * 8))) |
                 (((u8)interesting_8[j]) << (i * 8));

      if (new_val == tval) return 1;

    }

  }

  /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts. */

  if (blen == 2 && !check_le) return 0;

  /* See if two-byte insertions over old_val could give us new_val. */

  for (i = 0; i < blen - 1; i++) {

    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      u32 tval = (old_val & ~(0xffff << (i * 8))) |
                 (((u16)interesting_16[j]) << (i * 8));

      if (new_val == tval) return 1;

      /* Continue here only if blen > 2. */

      if (blen > 2) {

        tval = (old_val & ~(0xffff << (i * 8))) |
               (SWAP16(interesting_16[j]) << (i * 8));

        if (new_val == tval) return 1;

      }

    }

  }

  if (blen == 4 && check_le) {

    /* See if four-byte insertions could produce the same result
       (LE only). */

    for (j = 0; j < sizeof(interesting_32) / 4; j++)
      if (new_val == (u32)interesting_32[j]) return 1;

  }

  return 0;

}



static u32 calculate_score_stream(struct queue_entry* q, u32 avg_us) {

  u32 avg_exec_us = total_cal_us / total_cal_cycles;
  u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */

  if (avg_us * 0.1 > avg_exec_us) perf_score = 10;
  else if (avg_us * 0.25 > avg_exec_us) perf_score = 25;
  else if (avg_us * 0.5 > avg_exec_us) perf_score = 50;
  else if (avg_us * 0.75 > avg_exec_us) perf_score = 75;
  else if (avg_us * 4 < avg_exec_us) perf_score = 300;
  else if (avg_us * 3 < avg_exec_us) perf_score = 200;
  else if (avg_us * 2 < avg_exec_us) perf_score = 150;

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x. */

  if (q->bitmap_size * 0.3 > avg_bitmap_size) perf_score *= 3;
  else if (q->bitmap_size * 0.5 > avg_bitmap_size) perf_score *= 2;
  else if (q->bitmap_size * 0.75 > avg_bitmap_size) perf_score *= 1.5;
  else if (q->bitmap_size * 3 < avg_bitmap_size) perf_score *= 0.25;
  else if (q->bitmap_size * 2 < avg_bitmap_size) perf_score *= 0.5;
  else if (q->bitmap_size * 1.5 < avg_bitmap_size) perf_score *= 0.75;

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. */

  if (q->handicap >= 4) {

    perf_score *= 4;
    q->handicap -= 4;

  } else if (q->handicap) {

    perf_score *= 2;
    q->handicap--;

  }

  /* Final adjustment based on input depth, under the assumption that fuzzing
     deeper test cases is more likely to reveal stuff that can't be
     discovered with traditional fuzzers. */

  switch (q->depth) {

    case 0 ... 3:   break;
    case 4 ... 7:   perf_score *= 2; break;
    case 8 ... 13:  perf_score *= 3; break;
    case 14 ... 25: perf_score *= 4; break;
    default:        perf_score *= 5;

  }

  /* Make sure that we don't go over limit. */

  if (perf_score > EXTEND_MAX_MULT * 100) perf_score = EXTEND_MAX_MULT * 100;

  return perf_score;

}


/* replace everything with different values */
static void random_replace(u8 *buf, u32 len) {

  for (u32 i = 0; i < len; i++) {
    u8 c;
    do {
      c = UR(256);
    } while (c == buf[i]);
    buf[i] = c;
  }
}
/* Trim stream: auto trim and smart trim */
bool auto_trim() {
  bool needs_update = 0;
  khash_t(PTR) * kh_streams = get_streams(&g_stream_input);

  khiter_t k;
  for (k = kh_begin(kh_streams); k != kh_end(kh_streams); ++k){
    struct stream* stream = NULL;
    if (kh_exist(kh_streams, k)) {
      stream = kh_value(kh_streams, k);
    }
    if (!stream || stream->rc == 0){
      continue;
    }
     
    if (stream->len > stream_bits->cursors[stream->id]) {
      needs_update = 1;
      stream->len = stream_bits->cursors[stream->id];
    }    
  }
  return needs_update;     
}


static u8 trim_stream(struct queue_entry* q, u8* in_buf) {
  init_streams_input(&g_stream_input,in_buf, q->len, 0);
  static char tmp[64];
  static u8 clean_trace[MAP_SIZE];

  u8  needs_write = 0, fault = 0;
  u32 trim_exec = 0;
  u32 remove_len;
  u32 len_p2;
  u8* out_buf;
  u32 len = 0;
  
  u32 perf_score = 100;
  u32 orig_perf = 100;

  perf_score = calculate_score(queue_cur);

  
  u32 max_energy   = HAVOC_CYCLES * perf_score / havoc_div / 100;
   
  if (q->len < 8) return 0;

  stage_name = "auto trim";
  bytes_trim_in += q->len;

  /* auto trim */
  //get_streams_input_file(&g_stream_input, &out_buf, &len);
  //write_to_testcase(out_buf, len);

  fault = run_target();
  trim_execs++;

  if (stop_soon || fault == FAULT_ERROR) goto abort_trimming;

  /* Note that we don't keep track of crashes or hangs here; maybe TODO? */

  needs_write = auto_trim();

  stage_name = "smart trim";
  stage_short = "trim";
 
  
  khash_t(PTR) * kh_mmios = get_mmios(&g_stream_input);
  static u64 all_mmios[MAX_STREAM_SIZE];
  u64 num_all_mmios = 0;

  khiter_t k;
  for (k = kh_begin(kh_mmios); k != kh_end(kh_mmios); ++k){
    struct mmio* mmio = NULL;
    if (kh_exist(kh_mmios, k)) {
      mmio = kh_value(kh_mmios, k);
    }
    if (!mmio || mmio->valid == false){
      continue;
    }
    
    //u64 addr =  mmio->mmio_addr;
    //if (value_set_model_size > 0 && is_value_set_model(addr>>32, addr & 0xffffffff)) {
    //  continue;
    //}
    
    //struct bitextract_mmio_model_config* model_config = is_bitextract_model(addr>>32, addr & 0xffffffff);

    //if (model_config && model_config->mask_hamming_weight < 5){
    //  continue;
    //}

    all_mmios[num_all_mmios++] = mmio->mmio_addr;
  }

  orig_perf = perf_score = calculate_score(queue_cur);

  stage_max   = HAVOC_CYCLES * perf_score / havoc_div / 100 * num_all_mmios;

  if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;
  
#define TRIM_STREAM_CYCLES 1
  u32 trim_cycles = 0;

retriming:

  // shulle
  for(int i=num_all_mmios - 1; i > 0; i--){
    u64 tmp_addr = all_mmios[i];
    int j = random() % i;
    all_mmios[i] = all_mmios[j];
    all_mmios[j] = all_mmios[i];
  }

  
  for(int i=0; i < num_all_mmios; i++){
    u64 addr = all_mmios[i];
    //u16 size = m2s[i].size;
    u8* orig_buf;
    u32 orig_len;
    u8* tmp_buf;
    if (unlikely(!get_stream_input(&g_stream_input, addr,&orig_buf,&orig_len))) {
      continue;     
    }
    if (orig_len < 5) {
      continue;
    }
    tmp_buf = malloc(orig_len);
    if (!tmp_buf){
      continue;
    }
    len_p2 = next_p2(orig_len);

    u32 trim_min_bytes = TRIM_MIN_BYTES;
    
    remove_len = MAX(len_p2 / TRIM_START_STEPS, trim_min_bytes);
    /* Continue until the number of steps gets too high or the stepover
       gets too small. */
    
    u32 energy = max_energy;
    while (remove_len >= MAX(len_p2 / TRIM_END_STEPS, trim_min_bytes)) {
     
       u32 remove_pos = 0;

       sprintf(tmp, "trim %llx %s/%s", addr,DI(remove_len), DI(remove_len));
       stage_cur = 0;
       stage_max = orig_len / remove_len;
       memcpy(tmp_buf, orig_buf, orig_len);
       while (remove_pos < orig_len) {

         u32 trim_avail = MIN(remove_len, orig_len - remove_pos);
         u32 cksum;

         u32 move_tail = orig_len - remove_pos - trim_avail;
         memmove(tmp_buf + remove_pos, tmp_buf + remove_pos + trim_avail, 
                move_tail);
         //write_with_gap(in_buf, q->len, remove_pos, trim_avail);
         
         if(unlikely(!set_stream_input(&g_stream_input,addr, tmp_buf,orig_len-trim_avail))){
            break;
         }
         
         //get_streams_input_file(&g_stream_input, &out_buf, &len);
         //write_to_testcase(out_buf, len);
         fault = run_target();
         trim_execs++;
         if (energy>0)energy--;
         
         if (stop_soon || fault == FAULT_ERROR) goto abort_trimming;
         
         /* Note that we don't keep track of crashes or hangs here; maybe TODO? */

         cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

         /* If the deletion had no impact on the trace, make it permanent. This
            isn't perfect for variable-path inputs, but we're just making a
            best-effort pass, so it's not a big deal if we end up with false
            negatives every now and then. */

         if (cksum == q->exec_cksum) {
           orig_len -= trim_avail;
           len_p2  = next_p2(orig_len);

           memmove(orig_buf + remove_pos, orig_buf + remove_pos + trim_avail, 
                move_tail);

           /* Let's save a clean trace, which will be needed by
             update_bitmap_score once we're done with the trimming stuff. */

           if (!needs_write) {
             needs_write = 1;
             memcpy(clean_trace, trace_bits, MAP_SIZE);
           }
           energy = max_energy;
         } else {
           remove_pos += remove_len;
           get_streams_input_file(&g_stream_input, &out_buf, &len);
           queued_discovered += save_if_interesting(out_buf, len, fault);
         }

      /* Since this can be slow, update the screen every now and then. */
         if (!(trim_exec++ % stats_update_freq)) show_stats();
          
         stage_cur++;
        // if(stage_cur>stage_max) {
         //  goto end_triming;
         //  free(tmp_buf);
         //  set_stream_input(&g_stream_input,addr, orig_buf, orig_len);
         //}
       }

       remove_len >>= 1;

    }
    free(tmp_buf);
    set_stream_input(&g_stream_input,addr, orig_buf, orig_len);
  }

end_triming:
  trim_cycles++;
  if (trim_cycles < TRIM_STREAM_CYCLES) {
    goto retriming;
  }

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. */
  
  get_streams_input_file(&g_stream_input, &out_buf, &len);
  
  q->len = len;
  memcpy(in_buf, out_buf, q->len);
  if (needs_write) {

    s32 fd;

    unlink(q->fname); /* ignore errors */

    fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", q->fname);

    ck_write(fd, in_buf, q->len, q->fname);
    close(fd);

    memcpy(trace_bits, clean_trace, MAP_SIZE);
    update_bitmap_score(q);

  }



abort_trimming:

  bytes_trim_out += q->len;
  return fault;

}


static u8 mutate_stream(char** argv, struct queue_entry* q, u8* in_buf){
  u32 len, i, j;
  u8  *out_buf, *ex_tmp, *eff_map = 0;
  u8* file_buf;
  u32 file_len;
  u64 orig_hit_cnt, new_hit_cnt;
  u32 prev_cksum, eff_cnt = 1;

  u8  ret_val = 1;

  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;
  
  init_streams_input(&g_stream_input, in_buf, q->len, 0);

  khash_t(PTR) * kh_mmios = get_mmios(&g_stream_input);
  
  khiter_t k;
  for (k = kh_begin(kh_mmios); k != kh_end(kh_mmios); ++k){
    struct mmio* mmio = NULL;
    if (kh_exist(kh_mmios, k)) {
      mmio = kh_value(kh_mmios, k);
    }
    if (!mmio || mmio->valid == false){
      continue;
    }
    u64 addr = mmio->mmio_addr;
    // may skip base on addr?
    u16 size = mmio->size;

    a_len = 0;
    if (unlikely(!get_stream_input(&g_stream_input,addr,&out_buf,&len))) {
      continue;     
    }
    if (out_buf == NULL || len==0){
      continue;
    }


    /*********************************************
     * SIMPLE BITFLIP (+dictionary construction) *
     *********************************************/

    #define FLIP_BIT(_ar, _b) do { \
      u8* _arf = (u8*)(_ar); \
      u32 _bf = (_b); \
      _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
    } while (0)

    /* Single walking bit. */
goto tmpl;
    stage_short = "flip1";
    stage_max   = len << 3;
    stage_name  = "bitflip 1/1";

    stage_val_type = STAGE_VAL_NONE;

    orig_hit_cnt = queued_paths + unique_crashes;

    prev_cksum = queue_cur->exec_cksum;

    for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

      stage_cur_byte = stage_cur >> 3;

      FLIP_BIT(out_buf, stage_cur);
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
      if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;

      FLIP_BIT(out_buf, stage_cur);


      if (!dumb_mode && (stage_cur & 7) == 7) {

        u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

        if (stage_cur == stage_max - 1 && cksum == prev_cksum) {

          /* If at end of file and we are still collecting a string, grab the
             final character and force output. */

          if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];
          a_len++;

          if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
            maybe_add_auto(a_collect, a_len);

        } else if (cksum != prev_cksum) {

          /* Otherwise, if the checksum has changed, see if we have something
             worthwhile queued up, and collect that if the answer is yes. */

          if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
            maybe_add_auto(a_collect, a_len);

          a_len = 0;
          prev_cksum = cksum;

        }

        /* Continue collecting string, but only if the bit flip actually made
           any difference - we don't want no-op tokens. */

        if (cksum != queue_cur->exec_cksum) {

          if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];        
          a_len++;

        }

      }

    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP1]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP1] += stage_max;
    
tmpl:
goto skip_extras;
    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
    
    memcpy(&cmplog_backup, cmplog_ptr, sizeof(struct cmp_map));
    

    stage_name  = "test cmplog";
    stage_short = "cmplog";
    stage_cur   = 0;
    stage_max   = 0;

    orig_hit_cnt = queued_paths + unique_crashes;

    for(int w=0;w<CMP_MAP_W;w++){
        if(cmplog_backup.headers[w].hits&&cmplog_backup.headers[w].attribute == OP_AND) {
                
            //for(int h=0;h<cmplog_backup.headers[w].hits%CMP_MAP_H;h++){
                u32 v0 = cmplog_backup.log[w][0].v0;
                u32 v1 = cmplog_backup.log[w][0].v1;
                for (i = 0; i < len - 3; i++) {

                    u32 orig = *(u32*)(out_buf + i);
                    stage_cur_byte = i;

                    stage_val_type = STAGE_VAL_LE;
                    
                    *(u32*)(out_buf + i) = v0;

                    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
                    if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
                    stage_max++;
                    
                    *(u32*)(out_buf + i) = v0 ^ 0xFFFFFFFF;

                    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
                    if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
                    stage_max++;
                    
                    *(u32*)(out_buf + i) = (v0 ^ 0xFFFFFFFF) & orig;

                    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
                    if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
                    stage_max++;
                    
                    *(u32*)(out_buf + i) = ((v0 ^ 0xFFFFFFFF) & orig) | v0;

                    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
                    if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
                    stage_max++;
                    
                    *(u32*)(out_buf + i) = v1;

                    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
                    if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
                    stage_max++;
                    
                    *(u32*)(out_buf + i) = v1 ^ 0xFFFFFFFF;

                    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
                    if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
                    stage_max++;
                    
                    *(u32*)(out_buf + i) = (v1 ^ 0xFFFFFFFF) & orig;

                    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
                    if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
                    stage_max++;
                    
                    *(u32*)(out_buf + i) = ((v1 ^ 0xFFFFFFFF) & orig) | v1;

                    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
                    if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
                    stage_max++;
                    
                    /* Big endian next. */

                    stage_val_type = STAGE_VAL_BE;
                    
                    *(u32*)(out_buf + i) = SWAP32(v0);

                    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
                    if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
                    stage_max++;
                    
                    *(u32*)(out_buf + i) = SWAP32(v0) ^ 0xFFFFFFFF;

                    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
                    if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
                    stage_max++;
                    
                    *(u32*)(out_buf + i) = (SWAP32(v0) ^ 0xFFFFFFFF) & orig;

                    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
                    if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
                    stage_max++;
                    
                    *(u32*)(out_buf + i) =( (SWAP32(v0) ^ 0xFFFFFFFF) & orig )| SWAP32(v0);

                    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
                    if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
                    stage_max++;
                    
                    *(u32*)(out_buf + i) = SWAP32(v1);

                    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
                    if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
                    stage_max++;
                    
                    *(u32*)(out_buf + i) = SWAP32(v1) ^ 0xFFFFFFFF;

                    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
                    if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
                    stage_max++;
                    
                    *(u32*)(out_buf + i) = (SWAP32(v1) ^ 0xFFFFFFFF) & orig;

                    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
                    if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
                    stage_max++;

                    *(u32*)(out_buf + i) = ((SWAP32(v1) ^ 0xFFFFFFFF) & orig) | SWAP32(v1);

                    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
                    if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
                    stage_max++;
        

                    *(u32*)(out_buf + i) = orig;

               //  }
                
            }
              
        }    
          
    }

    

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_ARITH32]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_ARITH32] += stage_max;

    
goto skip_extras;

    stage_name  = "bitflip 2/1";
    stage_short = "flip2";
    stage_max   = (len << 3) - 1;

    orig_hit_cnt = new_hit_cnt;

    for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

      stage_cur_byte = stage_cur >> 3;

      FLIP_BIT(out_buf, stage_cur);
      FLIP_BIT(out_buf, stage_cur + 1);

      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
      if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;

      FLIP_BIT(out_buf, stage_cur);
      FLIP_BIT(out_buf, stage_cur + 1);

    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP2]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP2] += stage_max;

    /* Four walking bits. */

    stage_name  = "bitflip 4/1";
    stage_short = "flip4";
    stage_max   = (len << 3) - 3;

    orig_hit_cnt = new_hit_cnt;
 
    for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

      stage_cur_byte = stage_cur >> 3;

      FLIP_BIT(out_buf, stage_cur);
      FLIP_BIT(out_buf, stage_cur + 1);
      FLIP_BIT(out_buf, stage_cur + 2);
      FLIP_BIT(out_buf, stage_cur + 3);

      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
      if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;

      FLIP_BIT(out_buf, stage_cur);
      FLIP_BIT(out_buf, stage_cur + 1);
      FLIP_BIT(out_buf, stage_cur + 2);
      FLIP_BIT(out_buf, stage_cur + 3);

    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP4]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP4] += stage_max;


    /* Effector map setup. These macros calculate:

       EFF_APOS      - position of a particular file offset in the map.
       EFF_ALEN      - length of a map with a particular number of bytes.
       EFF_SPAN_ALEN - map span for a sequence of bytes.

     */

#define EFF_APOS(_p)          ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x)           ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l)          (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l) - 1) - EFF_APOS(_p) + 1)

    /* Initialize effector map for the next step (see comments below). Always
       flag first and last byte as doing something. */
 
    eff_map    = ck_alloc(EFF_ALEN(len));
    eff_map[0] = 1;

    if (EFF_APOS(len - 1) != 0) {
      eff_map[EFF_APOS(len - 1)] = 1;
      eff_cnt++;
    }

    /* Walking byte. */

    stage_name  = "bitflip 8/8";
    stage_short = "flip8";
    stage_max   = len;

    orig_hit_cnt = new_hit_cnt;

    for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

      stage_cur_byte = stage_cur;

      out_buf[stage_cur] ^= 0xFF;

      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
      if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;

      /* We also use this stage to pull off a simple trick: we identify
         bytes that seem to have no effect on the current execution path
         even when fully flipped - and we skip them during more expensive
         deterministic stages, such as arithmetics or known ints. */

      if (!eff_map[EFF_APOS(stage_cur)]) {

        u32 cksum;

        /* If in dumb mode or if the file is very short, just flag everything
           without wasting time on checksums. */

        if (!dumb_mode && len >= EFF_MIN_LEN)
          cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
        else
          cksum = ~queue_cur->exec_cksum;

        if (cksum != queue_cur->exec_cksum) {
          eff_map[EFF_APOS(stage_cur)] = 1;
          eff_cnt++;
        }

      }

      out_buf[stage_cur] ^= 0xFF;

    }

    /* If the effector map is more than EFF_MAX_PERC dense, just flag the
       whole thing as worth fuzzing, since we wouldn't be saving much time
       anyway. */

    if (eff_cnt != EFF_ALEN(len) &&
        eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {

      memset(eff_map, 1, EFF_ALEN(len));

      blocks_eff_select += EFF_ALEN(len);

    } else {

      blocks_eff_select += eff_cnt;

    }

    blocks_eff_total += EFF_ALEN(len);

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP8]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP8] += stage_max;


skip_bitflip:

    if (no_arith) goto skip_arith;

    /**********************
     * ARITHMETIC INC/DEC *
     **********************/

    /* 8-bit arithmetics. */

    stage_name  = "arith 8/8";
    stage_short = "arith8";
    stage_cur   = 0;
    stage_max   = 2 * len * ARITH_MAX;

    stage_val_type = STAGE_VAL_LE;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len; i++) {

      u8 orig = out_buf[i];
 
      /* Let's consult the effector map... */

      if (!eff_map[EFF_APOS(i)]) {
        stage_max -= 2 * ARITH_MAX;
        continue;
      }

      stage_cur_byte = i;

      for (j = 1; j <= ARITH_MAX; j++) {

        u8 r = orig ^ (orig + j);

        /* Do arithmetic operations only if the result couldn't be a product
           of a bitflip. */

        if (!could_be_bitflip(r)) {

          stage_cur_val = j;
          out_buf[i] = orig + j;

          get_streams_input_file(&g_stream_input, &file_buf, &file_len);
          if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
          stage_cur++;

        } else stage_max--;

        r =  orig ^ (orig - j);

        if (!could_be_bitflip(r)) {

          stage_cur_val = -j;
          out_buf[i] = orig - j;

          get_streams_input_file(&g_stream_input, &file_buf, &file_len);
          if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
          stage_cur++;

        } else stage_max--;

        out_buf[i] = orig;

      }

    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_ARITH8]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_ARITH8] += stage_max;

    /* 16-bit arithmetics, both endians. */

    if (len < 2) goto skip_arith;

    stage_name  = "arith 16/8";
    stage_short = "arith16";
    stage_cur   = 0;
    stage_max   = 4 * (len - 1) * ARITH_MAX;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len - 1; i++) {

      u16 orig = *(u16*)(out_buf + i);

      /* Let's consult the effector map... */

      if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
        stage_max -= 4 * ARITH_MAX;
        continue;
      }

      stage_cur_byte = i;

      for (j = 1; j <= ARITH_MAX; j++) {

        u16 r1 = orig ^ (orig + j),
            r2 = orig ^ (orig - j),
            r3 = orig ^ SWAP16(SWAP16(orig) + j),
            r4 = orig ^ SWAP16(SWAP16(orig) - j);

        /* Try little endian addition and subtraction first. Do it only
           if the operation would affect more than one byte (hence the 
           & 0xff overflow checks) and if it couldn't be a product of
           a bitflip. */

        stage_val_type = STAGE_VAL_LE; 

        if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {

          stage_cur_val = j;
          *(u16*)(out_buf + i) = orig + j;

          get_streams_input_file(&g_stream_input, &file_buf, &file_len);
          if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
          stage_cur++;
 
        } else stage_max--;

        if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

          stage_cur_val = -j;
          *(u16*)(out_buf + i) = orig - j;

          get_streams_input_file(&g_stream_input, &file_buf, &file_len);
          if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
          stage_cur++;

        } else stage_max--;

        /* Big endian comes next. Same deal. */

        stage_val_type = STAGE_VAL_BE;
 

        if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

          stage_cur_val = j;
          *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) + j);

          get_streams_input_file(&g_stream_input, &file_buf, &file_len);
          if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
          stage_cur++;

        } else stage_max--;

        if ((orig >> 8) < j && !could_be_bitflip(r4)) {

          stage_cur_val = -j;
          *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) - j);

          get_streams_input_file(&g_stream_input, &file_buf, &file_len);
          if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
          stage_cur++;

        } else stage_max--;

        *(u16*)(out_buf + i) = orig;

      }

    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_ARITH16]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_ARITH16] += stage_max;

    /* 32-bit arithmetics, both endians. */

    if (len < 4) goto skip_arith;

    stage_name  = "arith 32/8";
    stage_short = "arith32";
    stage_cur   = 0;
    stage_max   = 4 * (len - 3) * ARITH_MAX;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len - 3; i++) {

      u32 orig = *(u32*)(out_buf + i);

      /* Let's consult the effector map... */

      if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
          !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
        stage_max -= 4 * ARITH_MAX;
        continue;
      }

      stage_cur_byte = i;

      for (j = 1; j <= ARITH_MAX; j++) {

        u32 r1 = orig ^ (orig + j),
            r2 = orig ^ (orig - j),
            r3 = orig ^ SWAP32(SWAP32(orig) + j),
            r4 = orig ^ SWAP32(SWAP32(orig) - j);

        /* Little endian first. Same deal as with 16-bit: we only want to
           try if the operation would have effect on more than two bytes. */

        stage_val_type = STAGE_VAL_LE;

        if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {

          stage_cur_val = j;
          *(u32*)(out_buf + i) = orig + j;

          get_streams_input_file(&g_stream_input, &file_buf, &file_len);
          if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
          stage_cur++;

        } else stage_max--;

        if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {

          stage_cur_val = -j;
          *(u32*)(out_buf + i) = orig - j;

          get_streams_input_file(&g_stream_input, &file_buf, &file_len);
          if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
          stage_cur++;

        } else stage_max--;

        /* Big endian next. */

        stage_val_type = STAGE_VAL_BE;

        if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

          stage_cur_val = j;
          *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) + j);

          get_streams_input_file(&g_stream_input, &file_buf, &file_len);
          if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
          stage_cur++;

        } else stage_max--;

        if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {

          stage_cur_val = -j;
          *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) - j);

          get_streams_input_file(&g_stream_input, &file_buf, &file_len);
          if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
          stage_cur++;

        } else stage_max--;

        *(u32*)(out_buf + i) = orig;

      }

    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_ARITH32]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_ARITH32] += stage_max;


skip_arith:

    /**********************
     * INTERESTING VALUES *
     **********************/

    stage_name  = "interest 8/8";
    stage_short = "int8";
    stage_cur   = 0;
    stage_max   = len * sizeof(interesting_8);

    stage_val_type = STAGE_VAL_LE;

    orig_hit_cnt = new_hit_cnt;

    /* Setting 8-bit integers. */

    for (i = 0; i < len; i++) {

      u8 orig = out_buf[i];

      /* Let's consult the effector map... */

      if (!eff_map[EFF_APOS(i)]) {
        stage_max -= sizeof(interesting_8);
        continue;
      }

      stage_cur_byte = i;

      for (j = 0; j < sizeof(interesting_8); j++) {

        /* Skip if the value could be a product of bitflips or arithmetics. */

        if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
            could_be_arith(orig, (u8)interesting_8[j], 1)) {
          stage_max--;
          continue;
        }

        stage_cur_val = interesting_8[j];
        out_buf[i] = interesting_8[j];

        get_streams_input_file(&g_stream_input, &file_buf, &file_len);
        if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;

        out_buf[i] = orig;
        stage_cur++;

      }

    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_INTEREST8]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_INTEREST8] += stage_max;

    /* Setting 16-bit integers, both endians. */

    if (no_arith || len < 2) goto skip_interest;

    stage_name  = "interest 16/8";
    stage_short = "int16";
    stage_cur   = 0;
    stage_max   = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len - 1; i++) {

      u16 orig = *(u16*)(out_buf + i);

      /* Let's consult the effector map... */

      if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
        stage_max -= sizeof(interesting_16);
        continue;
      }

      stage_cur_byte = i;

      for (j = 0; j < sizeof(interesting_16) / 2; j++) {

        stage_cur_val = interesting_16[j];

        /* Skip if this could be a product of a bitflip, arithmetics,
           or single-byte interesting value insertion. */

        if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
            !could_be_arith(orig, (u16)interesting_16[j], 2) &&
            !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {

          stage_val_type = STAGE_VAL_LE;

          *(u16*)(out_buf + i) = interesting_16[j];

          get_streams_input_file(&g_stream_input, &file_buf, &file_len);
          if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
          stage_cur++;

        } else stage_max--;

        if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
            !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
            !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
            !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

          stage_val_type = STAGE_VAL_BE;

          *(u16*)(out_buf + i) = SWAP16(interesting_16[j]);
          get_streams_input_file(&g_stream_input, &file_buf, &file_len);
          if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
          stage_cur++;

        } else stage_max--;

      }

      *(u16*)(out_buf + i) = orig;

    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_INTEREST16]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_INTEREST16] += stage_max;

    if (len < 4) goto skip_interest;

    /* Setting 32-bit integers, both endians. */

    stage_name  = "interest 32/8";
    stage_short = "int32";
    stage_cur   = 0;
    stage_max   = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len - 3; i++) {

      u32 orig = *(u32*)(out_buf + i);

      /* Let's consult the effector map... */

      if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
          !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
        stage_max -= sizeof(interesting_32) >> 1;
        continue;
      }

      stage_cur_byte = i;

      for (j = 0; j < sizeof(interesting_32) / 4; j++) {

        stage_cur_val = interesting_32[j];

        /* Skip if this could be a product of a bitflip, arithmetics,
           or word interesting value insertion. */

        if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
            !could_be_arith(orig, interesting_32[j], 4) &&
            !could_be_interest(orig, interesting_32[j], 4, 0)) {

          stage_val_type = STAGE_VAL_LE;

          *(u32*)(out_buf + i) = interesting_32[j];

          get_streams_input_file(&g_stream_input, &file_buf, &file_len);
          if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
          stage_cur++;

        } else stage_max--;

        if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
            !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
            !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
            !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {

          stage_val_type = STAGE_VAL_BE;

          *(u32*)(out_buf + i) = SWAP32(interesting_32[j]);
          get_streams_input_file(&g_stream_input, &file_buf, &file_len);
          if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;
          stage_cur++;

        } else stage_max--;

      }

      *(u32*)(out_buf + i) = orig;

    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_INTEREST32]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_INTEREST32] += stage_max;

  skip_interest:

    /********************
     * DICTIONARY STUFF *
     ********************/

    if (!extras_cnt) goto skip_user_extras;

    /* Overwrite with user-supplied extras. */

    stage_name  = "user extras (over)";
    stage_short = "ext_UO";
    stage_cur   = 0;
    stage_max   = extras_cnt * len;

    stage_val_type = STAGE_VAL_NONE;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len; i++) {

      u32 last_len = 0;

      stage_cur_byte = i;

      /* Extras are sorted by size, from smallest to largest. This means
         that we don't have to worry about restoring the buffer in
         between writes at a particular offset determined by the outer
         loop. */

      for (j = 0; j < extras_cnt; j++) {

        /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
           skip them if there's no room to insert the payload, if the token
           is redundant, or if its entire span has no bytes set in the effector
           map. */

        if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
            extras[j].len > len - i ||
            !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
            !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {

          stage_max--;
          continue;

        }

        last_len = extras[j].len;
        memcpy(out_buf + i, extras[j].data, last_len);

        get_streams_input_file(&g_stream_input, &file_buf, &file_len);
        if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;

        stage_cur++;

      }

      /* Restore all the clobbered memory. */
      memcpy(out_buf + i, in_buf + i, last_len);

    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_EXTRAS_UO]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_EXTRAS_UO] += stage_max;

  skip_user_extras:

    if (!a_extras_cnt) goto skip_extras;

    stage_name  = "auto extras (over)";
    stage_short = "ext_AO";
    stage_cur   = 0;
    stage_max   = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len;

    stage_val_type = STAGE_VAL_NONE;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len; i++) {

      u32 last_len = 0;

      stage_cur_byte = i;

      for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++) {

        /* See the comment in the earlier code; extras are sorted by size. */

        if (a_extras[j].len > len - i ||
            !memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||
            !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, a_extras[j].len))) {

          stage_max--;
          continue;

        }

        last_len = a_extras[j].len;
        memcpy(out_buf + i, a_extras[j].data, last_len);

        get_streams_input_file(&g_stream_input, &file_buf, &file_len);
        if (common_fuzz_stuff(file_buf, file_len)) goto abandon_entry;

        stage_cur++;

      }

      /* Restore all the clobbered memory. */
      memcpy(out_buf + i, in_buf + i, last_len);

    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_EXTRAS_AO]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_EXTRAS_AO] += stage_max;

  skip_extras:

    /****************
     * RANDOM HAVOC *
     ****************/

  havoc_stage:
    return 0;

  }


    /* If we made this to here without jumping to havoc_stage or abandon_entry,
       we're properly done with deterministic steps and can mark it as such
       in the .state/ directory. */

  if (!queue_cur->passed_det) mark_as_det_done(queue_cur);
  ret_val = 0;
abandon_entry:
  return ret_val;

};


static struct range *add_range(struct range *ranges, u32 start, u32 end) {

  struct range *r = ck_alloc_nozero(sizeof(struct range));
  r->start = start;
  r->end = end;
  r->next = ranges;
  r->ok = 0;
  if (likely(ranges)) ranges->prev = r;
  return r;

}

static struct range *pop_biggest_range(struct range **ranges) {

  struct range *r = *ranges;
  struct range *rmax = NULL;
  u32           max_size = 0;

  while (r) {
    if (!r->ok) {
      u32 s = 1 + r->end - r->start;
      if (s >= max_size) {
        max_size = s;
        rmax = r;
      }
    }
    r = r->next;
  }

  return rmax;

}

/* helper function for redqueen */
static u8 common_fuzz_cmplog_stuff(u8 *out_buf, u32 len) {
  /* now just simple call common_fuzz_stuff */
  return common_fuzz_stuff(out_buf, len);
}

static u8 get_exec_checksum(u8 *buf, u32 len, u32 *cksum) {
  if (unlikely(common_fuzz_stuff(buf, len))) { return 1; }
  *cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
  return 0;
}




///// Input to State replacement

static u8 its_fuzz(u8 *buf, u32 len, u8 *status, u32 cksum) {

  u64 orig_hit_cnt, new_hit_cnt;
  u32 exec_cksum;
  orig_hit_cnt = queued_paths + unique_crashes;

#ifdef _DEBUG
  dump("DATA", buf, len);
#endif

  if (unlikely(get_exec_checksum(buf, len, &exec_cksum))) { return 1; }

  new_hit_cnt = queued_paths + unique_crashes;

  if (unlikely(new_hit_cnt != orig_hit_cnt)) {

#ifdef _DEBUG
    printf("NEW FIND\n");
#endif
    *status = 1;

  } else if (cksum != exec_cksum){
	// when taint success, it mean new find  
	  *status = 3;
  } else {
    // when taint failed, it mean new find
    *status = 2;
  }

  return 0;

}

static u8 compare_cmplog(struct cmp_map* cmplog_a, struct cmp_map* cmplog_b){
  for (int k = 0; k < CMP_MAP_W; ++k) {
      if (cmplog_a->headers[k].attribute != OP_ISUB ) {continue;};
      if (cmplog_a->headers[k].hits != cmplog_b->headers[k].hits) { return 1; }
      for (int j=0;j<cmplog_a->headers[k].hits;j++) {
        if(cmplog_a->log[k][j].v0 != cmplog_b->log[k][j].v0 || cmplog_a->log[k][j].v1 != cmplog_b->log[k][j].v1){
          return 1;
        }
      }
  }
  return 0;
}




static u8 get_encoding_buf(u8* buf, u32 len, u32 idx, u64 repl, u32 shape, u8* fti, struct transform_operands* t_op){
  u64 tmp_repl;
  u8* repl_buf = &tmp_repl;
  
  if (t_op->shape == 8 ) {
	  if (shape < 8) {
	    return 1;
	  }
	
    if (t_op->reverse) {
	    repl = SWAP64(repl);
	  }
    *(u64*)repl_buf = repl;
	  

  }else if (t_op->shape == 4){
    if (shape < 4){
	    return 1;
	  }
	
	  if (t_op->reverse) {
	    repl = SWAP32((u32)repl);
	  }else{
      repl = (u32)repl;
	  }
    *(u32*)repl_buf = repl;
  }else if (t_op->shape == 2){
	  if (shape < 2) {
	    return 1;
	  }
    if (t_op->reverse) {
	    repl = SWAP16((u16)repl);
	  }else{
      repl = (u16)repl;
	  }
    *(u16*)repl_buf = repl;
  }else if (t_op->shape == 1){
	  if (shape < 1) {
	    return 1;
	  }
	  *(u8*)repl_buf = (u8)repl;
  }else{
	  return 1;
  }
  
  int j=idx;
  for(int i=t_op->shape-1;i>=0;i--){
    while(j>=0&&fti[j]==0){
      j--;
    };
    if(j>=0){
      buf[j]=repl_buf[i];
    }
  }
  return 0;
}

static u8 get_encoding_buf2(u8* buf, u32 idx, u64 repl, u32 len, u32 taint_len, struct transform_operands* t_op){
  u64 *buf_64 = (u64 *)&buf[idx];
  u32 *buf_32 = (u32 *)&buf[idx];
  u16 *buf_16 = (u16 *)&buf[idx];
  u8 * buf_8 = &buf[idx];

  u32 its_len = MIN(len - idx, taint_len);
  
  if (t_op->shape == 8 ) {
	  if (its_len < 8) {
	    return 1;
	  }
	
    if (t_op->reverse) {
	    *buf_64 = SWAP64(repl);
	  }else{
      *buf_64 = repl;
	  }
	
  }else if (t_op->shape == 4){
    if (its_len < 4){
	    return 1;
	  }
	
	  if (t_op->reverse) {
	   *buf_32 = SWAP32((u32)repl);
	  }else{
      *buf_32 = (u32)repl;
	  }
  }else if (t_op->shape == 2){
	  if (its_len < 2) {
	    return 1;
	  }
    if (t_op->reverse) {
	    *buf_16 = SWAP16((u16)repl);
	  }else{
      *buf_16 = (u16)repl;
	  }	
  }else if (t_op->shape == 1){
	  if (its_len < 1) {
	    return 1;
	  }
	  *buf_8 = (u8)repl;
  }else{
	  return 1;
  }
  
  return 0;

}

// don't free the buffer
static bool compress_buf(u64 mask_num, u32 size, u8* mask_buf, u32 mask_buf_len, u8* orig_buf, u32 orig_buf_len, u8** compressed_buf, u32* compressed_buf_len) {
    static u8 buffer[MAX_STREAM_SIZE];

    if (mask_num == 0 || size == 0 || !orig_buf) {
      printf("mask_num:%016lx size:%d mask_buf:%016lx orig_buf:%016lx\n",mask_num, size, mask_buf, orig_buf);
      return false;
    }
    
    if (mask_buf && mask_buf_len != orig_buf_len) {
      printf("FTI taint info is not equal buffer len!!!\n");
      return false;
    }
    
    u32 buffer_len = 0;
    u8* mask_num_buf = &mask_num;

    for (int i=0;i<orig_buf_len;i++) {
      if (mask_buf) {
        if (mask_buf[i]) {
          buffer[buffer_len++] = orig_buf[i];
        }
      }else{
        if (mask_num_buf[i%size]) {
          buffer[buffer_len++] = orig_buf[i];
        }
      }

      if (buffer_len >= MAX_STREAM_SIZE) {
        break;
      }
    }
    
    *compressed_buf = &buffer;
    *compressed_buf_len = buffer_len;

#ifdef COMPRESS_DEBUG
    dump(" orig", orig_buf, orig_buf_len);
    dump(" mask", mask_buf, mask_buf_len);
    dump("after", buffer, buffer_len);
#endif

    return true;
};
static bool decompress_buf(u64 mask_num, u32 size, u8* mask_buf, u32 mask_buf_len, u8* orig_buf, u32 orig_buf_len, u8** decompressed_buf, u32* decompressed_buf_len){
    static u8 buffer[MAX_STREAM_SIZE];

    if (mask_num == 0 || size == 0 || !orig_buf) {
      printf("mask_num:%016lx size:%d mask_buf:%016lx orig_buf:%016lx\n",mask_num, size, mask_buf, orig_buf);
      return false;
    }
    
    u32 buffer_len = 0;
    u8* mask_num_buf = &mask_num;
    
    int i = 0;
    while(i < orig_buf_len && buffer_len < MAX_STREAM_SIZE) {
      if(mask_buf && buffer_len < mask_buf_len) {
        if (mask_buf[buffer_len]) {
          buffer[buffer_len] = orig_buf[i++];
        }
      }else{
        if (mask_num_buf[buffer_len%size]) {
          buffer[buffer_len] = orig_buf[i++];
        }
      }
      buffer_len++;
    }

    *decompressed_buf = &buffer;
    if (mask_buf_len > buffer_len) {
      buffer_len = mask_buf_len;
    }
    *decompressed_buf_len = buffer_len;
#ifdef DECOMPRESS_DEBUG
    dump(" orig", orig_buf, orig_buf_len);
    dump(" mask", mask_buf, mask_buf_len);
    dump("after", buffer, buffer_len);
#endif
    return true;
};


static void dump(char *txt, u8 *buf, u32 len) {

  u32 i;
  fprintf(stderr, "DUMP %s %016llx ", txt, hash32(buf, len, HASH_CONST));
  for (i = 0; i < len; i++)
    fprintf(stderr, "%02x", buf[i]);
  fprintf(stderr, "\n");

}

static void fix_checksum(struct queue_entry* q, u64 addr, u64 mask_num, u32 size, u8* mask_buf, u32 mask_buf_len, u8* masked_buf, u32 masked_buf_len, struct I2S_CK* I2S){
  if (!I2S) {
	  return;
  }
  
  u8* out_buf;
  u32 out_len;
  u8* file_buf;
  u32 file_len;
  
  if (unlikely(!get_stream_input(&g_stream_input, addr, &out_buf, &out_len))) {
    return;     
  }
  
  u32 tmp_out_buf_len;
  u8* tmp_out_buf;
  
  fix_checksum(q, addr, mask_num, size, mask_buf, mask_buf_len, masked_buf, masked_buf_len,I2S->next);


  
  u32 idx;
  u32 key;
  u64 repl;
  u32 is_v0;
  u32 hits;
  struct transform_operands* t_op;

	
  if (!decompress_buf(mask_num, size, mask_buf, mask_buf_len, masked_buf, masked_buf_len, &tmp_out_buf, &tmp_out_buf_len)) {
    return;
  }
  set_stream_input(&g_stream_input, addr, tmp_out_buf, tmp_out_buf_len);

  get_streams_input_file(&g_stream_input, &file_buf, &file_len);
  if (unlikely(common_fuzz_cmplog_stuff(file_buf, file_len))){
    return;
  };
  
	idx = I2S->idx;
	key = I2S->key;
	is_v0 = I2S->is_v0;
	t_op = &I2S->t_op;
	hits = I2S->hits;
	struct cmp_operands *o = &cmplog_ptr->log[key][hits];
	if (is_v0) {
	  repl = o->v0;
	}else{
	  repl = o->v1;
	}
#ifdef _DEBUG
	fprintf(stderr,"fix ck: idx:%d key:%d is_v0:%d hits:%d value:%llu\n",idx,key,is_v0,hits,repl);
#endif
        
	if (idx < masked_buf_len){
           get_encoding_buf2(masked_buf, idx, repl, masked_buf_len, masked_buf_len, t_op);
	}
  
  // fix_checksum next
  fix_checksum(q, addr, mask_num, size, mask_buf, mask_buf_len, masked_buf, masked_buf_len,I2S->next);
  set_stream_input(&g_stream_input, addr, out_buf, out_len);
}


static u8 input_to_state_stream(u64 addr, u32 size, u32 shape, u32 key, u32 h, u8* fti, u8 *buf, u32 len, u32 idx, u64 o_v0, u64 o_v1, u64 v0, u64 v1, u32 cksum) {
  

  u8* file_buf;
  u32 file_len;
  u32 newcksum;
  u64 orig_hit_cnt, new_hit_cnt;
  u64 orig_execs;
  u8 status;
  struct transform_operands t_op;  

  stage_max = 0;
  stage_cur = 0;
  stage_name = "input-to-state";
  stage_short = "its";
  
  orig_hit_cnt = queued_paths + unique_crashes;
  orig_execs = total_execs;

 
  
  if (shape==32){
    if((o_v0 & 0x00ffff00) !=  (v0 & 0x00ffff00)){
       return 0;
    }
    if((o_v1 & 0x00ffff00) !=  (v1 & 0x00ffff00)){
       return 0;
    }
  }else if(shape==64){
    if((o_v0 & 0x00ffffffffffff00) !=  (v0 & 0x00ffffffffffff00)){
      return 0;
    }
    if((o_v1 & 0x00ffffffffffff00) !=  (v1 & 0x00ffffffffffff00)){
      return 0;
    }
  }
  u8* orig_buf = ck_alloc_nozero(len);
  memcpy(orig_buf, buf, len);

  if ( o_v0 != v0  && o_v0 != o_v1) {
    
    status = 0;
    memcpy(buf, orig_buf, len);
    t_op.shape = 8;
	  t_op.reverse = 1;

    if (get_encoding_buf(buf, len, idx, o_v1, shape, fti, &t_op)==0){
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    
      if (unlikely(its_fuzz(file_buf, file_len, &status, cksum))){
        goto its_end;
      };
      if (status == 1 || status == 3){

	    }
    }
    
    status = 0;
    memcpy(buf, orig_buf, len);
    t_op.shape = 8;
	  t_op.reverse = 0;

    if (get_encoding_buf(buf, len, idx, o_v1, shape, fti, &t_op)==0){
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    
      if (unlikely(its_fuzz(file_buf, file_len, &status, cksum))){
        goto its_end;
      };
      if (status == 1 || status == 3){

	    }
    }

    status = 0;
    memcpy(buf, orig_buf, len);
    t_op.shape = 4;
	  t_op.reverse = 1;

    if (get_encoding_buf(buf, len, idx, o_v1, shape, fti, &t_op)==0){
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    
      if (unlikely(its_fuzz(file_buf, file_len, &status, cksum))){
        goto its_end;
      };
      if (status == 1 || status == 3){

	    }
    }

    status = 0;
    memcpy(buf, orig_buf, len);
    t_op.shape = 4;
	  t_op.reverse = 0;

    if (get_encoding_buf(buf, len, idx, o_v1, shape, fti, &t_op)==0){
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    
      if (unlikely(its_fuzz(file_buf, file_len, &status, cksum))){
        goto its_end;
      };
      if (status == 1 || status == 3){

	    }
    }

    status = 0;
    memcpy(buf, orig_buf, len);
    t_op.shape = 2;
	  t_op.reverse = 0;

    if (get_encoding_buf(buf, len, idx, o_v1, shape, fti, &t_op)==0){
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    
      if (unlikely(its_fuzz(file_buf, file_len, &status, cksum))){
        goto its_end;
      };
      if (status == 1 || status == 3){

	    }
    }

    status = 0;
    memcpy(buf, orig_buf, len);
    t_op.shape = 2;
	  t_op.reverse = 1;

    if (get_encoding_buf(buf, len, idx, o_v1, shape, fti, &t_op)==0){
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    
      if (unlikely(its_fuzz(file_buf, file_len, &status, cksum))){
        goto its_end;
      };
      if (status == 1 || status == 3){

	    }
    }

    status = 0;
    memcpy(buf, orig_buf, len);
    t_op.shape = 1;
	  t_op.reverse = 1;

    if (get_encoding_buf(buf, len, idx, o_v1, shape, fti, &t_op)==0){
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    
      if (unlikely(its_fuzz(file_buf, file_len, &status, cksum))){
        goto its_end;
      };
      if (status == 1 || status == 3){

	    }
    }
  }
  
  if ( o_v1 != v1  && o_v0 != o_v1) {
    status = 0;
    memcpy(buf, orig_buf, len);
    t_op.shape = 8;
	  t_op.reverse = 1;

    if (get_encoding_buf(buf, len, idx, o_v0, shape, fti, &t_op)==0){
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    
      if (unlikely(its_fuzz(file_buf, file_len, &status, cksum))){
        goto its_end;
      };
      if (status == 1 || status == 3){

	    }
    }
    
    status = 0;
    memcpy(buf, orig_buf, len);
    t_op.shape = 8;
	  t_op.reverse = 0;

    if (get_encoding_buf(buf, len, idx, o_v0, shape, fti, &t_op)==0){
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    
      if (unlikely(its_fuzz(file_buf, file_len, &status, cksum))){
        goto its_end;
      };
      if (status == 1 || status == 3){

	    }
    }

    status = 0;
    memcpy(buf, orig_buf, len);
    t_op.shape = 4;
	  t_op.reverse = 1;

    if (get_encoding_buf(buf, len, idx, o_v0, shape, fti, &t_op)==0){
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    
      if (unlikely(its_fuzz(file_buf, file_len, &status, cksum))){
        goto its_end;
      };
      if (status == 1 || status == 3){

	    }
    }

    status = 0;
    memcpy(buf, orig_buf, len);
    t_op.shape = 4;
	  t_op.reverse = 0;

    if (get_encoding_buf(buf, len, idx, o_v0, shape, fti, &t_op)==0){
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    
      if (unlikely(its_fuzz(file_buf, file_len, &status, cksum))){
        goto its_end;
      };
      if (status == 1 || status == 3){

	    }
    }

    status = 0;
    memcpy(buf, orig_buf, len);
    t_op.shape = 2;
	  t_op.reverse = 0;

    if (get_encoding_buf(buf, len, idx, o_v0, shape, fti, &t_op)==0){
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    
      if (unlikely(its_fuzz(file_buf, file_len, &status, cksum))){
        goto its_end;
      };
      if (status == 1 || status == 3){

	    }
    }

    status = 0;
    memcpy(buf, orig_buf, len);
    t_op.shape = 2;
	  t_op.reverse = 1;

    if (get_encoding_buf(buf, len, idx, o_v0, shape, fti, &t_op)==0){
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    
      if (unlikely(its_fuzz(file_buf, file_len, &status, cksum))){
        goto its_end;
      };
      if (status == 1 || status == 3){

	    }
    }

    status = 0;
    memcpy(buf, orig_buf, len);
    t_op.shape = 1;
	  t_op.reverse = 1;

    if (get_encoding_buf(buf, len, idx, o_v0, shape, fti, &t_op)==0){
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    
      if (unlikely(its_fuzz(file_buf, file_len, &status, cksum))){
        goto its_end;
      };
      if (status == 1 || status == 3){

	    }
    }
  }

    
its_end:
  memcpy(buf, orig_buf, len);
  free(orig_buf);
  new_hit_cnt = queued_paths + unique_crashes;
  stage_finds[STAGE_ITS] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ITS] += total_execs - orig_execs;

  
  if (new_hit_cnt - orig_hit_cnt==0 && pass_stats[key].faileds < 0xff) {

    pass_stats[key].faileds++;

  }

  if (pass_stats[key].total < 0xff) { pass_stats[key].total++; }
  return 0;
}



static bool is_visited(u32* visited_streams, u32 len_visited_streams, u32 stream_id) {
  for (int i=0;i<len_visited_streams;i++) {
    if (visited_streams[i] == stream_id) {
      return true;
    }
  }
  return false;
}

static bool direct_copy(u8 val, u64 cmp_val, u32 shape) {
  for(int i=0;i<shape;i++){
    if (val == (cmp_val & 0xff)) {
      return true;
    }
    cmp_val >>= 8;
  }
  return false;
}

static bool direct_copy_string(u8 val, u8* cmp_val, u32 shape) {
  if(val == 0) {
    return false;
  }
  for(int i=0;i<shape;i++){
    if (val == cmp_val[i]) {
      return true;
    }
  }
  return false;
}

static u8 fti_mutate_input_to_state_stream(u8* buf, u32 len, u32* valid_idx, u32 valid_idx_len, u64 pattern, u32 shape, u8* backup_buf) {
  u64 v_64;
  u32 v_32;
  u16 v_16;
  u8 v_8;
  u8* value_buf;
  
  u8* file_buf;
  u32 file_len;
  
  if (shape == 8) {
    v_64 = pattern;
    value_buf = &v_64;
  }else if (shape == 4) {
    v_32 = (u32)pattern;
    value_buf = &v_32;
  }else if (shape == 2) {
    v_16 = (u16)pattern;
    value_buf = &v_16;
  }else{
    v_8 = (u8)pattern;
    value_buf = &v_8;
  }
  
  
  
  for (int i=0;i<valid_idx_len;i++){
    for (int j=0;j<shape;j++) {
      if (i+j < valid_idx_len) {
        buf[valid_idx[i+j]] = value_buf[j];
      }
    }

    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    if (common_fuzz_stuff(file_buf, file_len)) return -1;
    memcpy(buf, backup_buf, len);
  }

  return 0;
}

static u8 fti_mutate_its_stream(struct queue_entry* q, u64 addr, u32 size, struct cmp_map* cmplog) {
  // only exec once
    
  u32 len;
  u8* buf;
  u8* file_buf;
  u32 file_len;
  u64 orig_hit_cnt, new_hit_cnt;
  
  static u32* valid_idx;
  static u32 valid_idx_len;
  
  static u32 valid_idx0[MAX_STREAM_LEN];
  static u32 valid_idx_len0;
  
  static u32 valid_idx1[MAX_STREAM_LEN];
  static u32 valid_idx_len1;
  
  static u8 pattern_buf[256];
  static u32 pattern_buf_len;
  
  if (unlikely(!get_stream_input(&g_stream_input, addr, &buf, &len))) {
    return 0;     
  }
  if (buf == NULL || len==0){
    return 0; 
  }
  
  u32 backup_buf_len = len;
  u8* backup_buf = ck_alloc_nozero(backup_buf_len);
    
  memcpy(backup_buf, buf, len);
    
  khash_t(PTR) *cmps_info = get_stream_cmps_info(&g_cmp_info, addr);
  if(cmps_info == NULL) {
    return 0;
  }
  
  stage_name  = "fti-mutate-its";
  stage_short = "fti-mutate-its";
  
  orig_hit_cnt = queued_paths + unique_crashes;
  u32 execs = 0;
  
  khiter_t k;
  for (k = kh_begin(cmps_info); k != kh_end(cmps_info); ++k){
    if (kh_exist(cmps_info, k) ) {
      u64 cmp_id = kh_value(cmps_info, k);
      
      struct stream_byte_cmps* cmps = get_direct_fti_info(q->fti_info, cmp_id, addr);
      if (cmps->count == 0) {
        continue;
      }
      
      if (cmplog_backup.headers[cmp_id].attribute == OP_AND || cmplog_backup.headers[cmp_id].attribute == OP_OR || cmplog_backup.headers[cmp_id].attribute == OP_XOR) {
        if(! ((get_touched(&g_cmp_info,cmp_id) && !(get_untouched(&g_cmp_info,cmp_id))) || (get_untouched(&g_cmp_info,cmp_id) && !(get_touched(&g_cmp_info,cmp_id))))  ){
          continue;
        }else{
          add_touched(&g_cmp_info,  cmp_id, 1, cmplog_backup.headers[cmp_id].attribute, cmplog_backup.headers[cmp_id].type, SHAPE_BYTES(cmplog_backup.headers[cmp_id].shape));
          add_untouched(&g_cmp_info, cmp_id, 1, cmplog_backup.headers[cmp_id].attribute, cmplog_backup.headers[cmp_id].type, SHAPE_BYTES(cmplog_backup.headers[cmp_id].shape));
        }      
      }
       
      #ifdef _DEBUG
      fprintf(stderr, "cmpid:%d\n",cmp_id);
      #endif
      
      u32 loggeds;
      if(cmplog_backup.headers[cmp_id].type == CMP_TYPE_RTN) {
        loggeds = MIN(CMP_MAP_RTN_H, cmplog_backup.headers[cmp_id].hits);
      }else{
        loggeds = MIN(CMP_MAP_H, cmplog_backup.headers[cmp_id].hits);
      }
      u32 shape = SHAPE_BYTES(cmplog_backup.headers[cmp_id].shape);
      
      bool is_const0, is_const1;
      bool is_counter0, is_counter1;

      
      bool direct0,direct1;
      for (int h=0;h<loggeds;h++) {
        direct0 = false;
        direct1 = false;
        valid_idx_len0 = 0;
        valid_idx_len1 = 0;
        for(int t=0;t<cmps->count;t++) {
          if (cmps->byte_cmp[t].h == h) {
            #ifdef _DEBUG
            fprintf(stderr, "        idx:%d h:%d v0d:%d v1d:%d\n",cmps->byte_cmp[t].idx, cmps->byte_cmp[t].h, cmps->byte_cmp[t].v0d, cmps->byte_cmp[t].v1d);
            #endif
            direct0 = direct0 || cmps->byte_cmp[t].v0d;
            direct1 = direct1 || cmps->byte_cmp[t].v1d;
            
            u32 idx = cmps->byte_cmp[t].idx;
            
            if (cmps->byte_cmp[t].v0d) {
              if (idx < len) {
                valid_idx0[valid_idx_len0++] = idx;
              }
            }
            
            if (cmps->byte_cmp[t].v1d) {
              if (idx < len) {
                valid_idx1[valid_idx_len1++] = idx;
              }
            }
          }
        }
        
        #ifdef _DEBUG
        fprintf(stderr,"is direct0:%d is direct1:%d\n",direct0,direct1);
        #endif
        
        
        if (direct0) {
          
          valid_idx = valid_idx0;
          valid_idx_len = valid_idx_len0;
          // string only be in v1
          
          if (cmplog_backup.headers[cmp_id].type == CMP_TYPE_RTN) {
            u32 stride = 1;
            u32 max_stride = size;
            
            while(stride <= max_stride) {
              u8* pattern = &(((struct cmpfn_operands*)(cmplog_backup.log[cmp_id]))[h].v1);
              
              #ifdef _DEBUG
              fprintf(stderr,"addr:%016lx string:%s shape:%d\n",addr, pattern, shape);
              
              fprintf(stderr, "idxs:");
              for(int i=0;i<valid_idx_len0;i++){
                fprintf(stderr, "%d ",valid_idx0[i]);
              }
              fprintf(stderr,"\n");
              dump("buf",buf, len);
              #endif
              
              u8* splits[] = {"\0"," ","\t","\r","\n","\r\n",","};
              
              for (int s=0;s<7;s++) {
                u8* split = splits[s];
              
                pattern_buf_len = 0;
              
                for(int i=0;i<shape;i++) {
                  for(int j=0;j<stride;j++){
                    pattern_buf[pattern_buf_len++] = pattern[i];
                  }
                }
                
                for(int i=0;i<strlen(split);i++) {
                  for(int j=0;j<stride;j++){
                    pattern_buf[pattern_buf_len++] = split[i];
                  }
                }
              
                stream_insert_region(&g_stream_input, addr, valid_idx0[0], pattern_buf_len, pattern_buf);
                get_streams_input_file(&g_stream_input, &file_buf, &file_len);
                if (common_fuzz_stuff(file_buf, file_len)) return -1;
                execs++;
              
            
                memcpy(buf, backup_buf, len);
                set_stream_input(&g_stream_input, addr, buf, len);
              }
              
              stride <<= 1;
            }
            
          }
          
       
          if (cmplog_backup.headers[cmp_id].type == CMP_TYPE_INS && valid_idx_len > 1 ) {
            
            u64 pattern = cmplog_backup.log[cmp_id][h].v1;
            
            #ifdef _DEBUG
            fprintf(stderr,"addr:%016lx string:%016lx shape:%d\n",addr, pattern, shape);
              
            fprintf(stderr, "idxs:");
            for(int i=0;i<valid_idx_len;i++){
              fprintf(stderr, "%d ",valid_idx[i]);
            }
            fprintf(stderr,"\n");
            dump("buf",buf, len);
            #endif
            
            if (shape > 4 && valid_idx_len > 4){
              u64 pattern_64 = pattern;
              u64 value = pattern_64;
              fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 8, backup_buf);
              execs++;
              
              if (cmplog_backup.headers[cmp_id].attribute == OP_AND || cmplog_backup.headers[cmp_id].attribute == OP_OR || cmplog_backup.headers[cmp_id].attribute == OP_XOR) {
                value = pattern_64 ^ 0xffffffffffffffff;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 8, backup_buf);
                execs++;
              }else{
                // little endian add one
                value = pattern_64 + 1;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 8, backup_buf);
                execs++;
                
                // little endian sub one
                value = pattern_64 - 1;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 8, backup_buf);
                execs++;
                
                // big endian
                value = SWAP64(pattern_64);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 8, backup_buf);
                execs++;
                                
                // big endian add one
                value = SWAP64(SWAP64(pattern_64) + 1);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 8, backup_buf);
                execs++;
                
                // big endian sub one
                value = SWAP64(SWAP64(pattern_64) - 1);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 8, backup_buf);
                execs++;
              }
              
            }
            
            if (shape > 2 && valid_idx_len > 2) {
              u32 pattern_32 = (u32)pattern;
              u32 value = pattern_32;
              fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 4, backup_buf);
              execs++;
              
              if (cmplog_backup.headers[cmp_id].attribute == OP_AND || cmplog_backup.headers[cmp_id].attribute == OP_OR || cmplog_backup.headers[cmp_id].attribute == OP_XOR) {
                value = pattern_32 ^ 0xffffffff;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 4, backup_buf);
                execs++;
              }else{
                // little endian add one
                value = pattern_32 + 1;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 4, backup_buf);
                execs++;
                
                // little endian sub one
                value = pattern_32 - 1;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 4, backup_buf);
                execs++;
                
                // big endian
                value = SWAP32(pattern_32);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 4, backup_buf);
                execs++;   
                
                // big endian add one
                value = SWAP32(SWAP32(pattern_32) + 1);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 4, backup_buf);
                execs++;
                
                // big endian sub one
                value = SWAP32(SWAP32(pattern_32) - 1);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 4, backup_buf);
                execs++;
              }  
            }
            if(shape > 1 && valid_idx_len > 1) {
              u16 pattern_16 = (u16)pattern;
              u16 value = pattern_16;
              fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 2, backup_buf);
              execs++;
              
              if (cmplog_backup.headers[cmp_id].attribute == OP_AND || cmplog_backup.headers[cmp_id].attribute == OP_OR || cmplog_backup.headers[cmp_id].attribute == OP_XOR) {
                value = pattern_16 ^ 0xffff;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 2, backup_buf);
                execs++;
              }else{
                // little endian add one
                value = pattern_16 + 1;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 2, backup_buf);
                execs++;
                
                // little endian sub one
                value = pattern_16 - 1;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 2, backup_buf);
                execs++;
                
                // big endian
                value = SWAP16(pattern_16);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 2, backup_buf);
                execs++;
                
                // big endian add one
                value = SWAP16(SWAP16(pattern_16) + 1);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 2, backup_buf);
                execs++;
                
                // big endian sub one
                value = SWAP16(SWAP16(pattern_16) - 1);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 2, backup_buf);
                execs++;
              }  
            }
            {
              u8 pattern_8 = (u8)pattern;
              u8 value = pattern_8;
              fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 1, backup_buf);
              execs++;
              
              if (cmplog_backup.headers[cmp_id].attribute == OP_AND || cmplog_backup.headers[cmp_id].attribute == OP_OR || cmplog_backup.headers[cmp_id].attribute == OP_XOR) {
                value = pattern_8 ^ 0xff;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 1, backup_buf);
                execs++;
              }else{
                // add one
                value = pattern_8 + 1;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 1, backup_buf);
                execs++;
                
                // sub one
                value = pattern_8 - 1;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 1, backup_buf);
                execs++;
                
              } 
            }
          } 
            
        }
        
        if (direct1 ) {
          valid_idx = valid_idx1;
          valid_idx_len = valid_idx_len1;
          if (cmplog_backup.headers[cmp_id].type == CMP_TYPE_INS && valid_idx_len > 1) {

            u64 pattern = cmplog_backup.log[cmp_id][h].v0;
            
            #ifdef _DEBUG
            fprintf(stderr,"addr:%016lx string:%016lx shape:%d\n",addr, pattern, shape);
              
            fprintf(stderr, "idxs:");
            for(int i=0;i<valid_idx_len;i++){
              fprintf(stderr, "%d ",valid_idx[i]);
            }
            fprintf(stderr,"\n");
            dump("buf",buf, len);
            #endif
            if (shape > 4 && valid_idx_len > 4){
              u64 pattern_64 = pattern;
              u64 value = pattern_64;
              fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 8, backup_buf);
              execs++;
              
              if (cmplog_backup.headers[cmp_id].attribute == OP_AND || cmplog_backup.headers[cmp_id].attribute == OP_OR || cmplog_backup.headers[cmp_id].attribute == OP_XOR) {
                value = pattern_64 ^ 0xffffffffffffffff;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 8, backup_buf);
                execs++;
              }else{
                // little endian add one
                value = pattern_64 + 1;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 8, backup_buf);
                execs++;
                
                // little endian sub one
                value = pattern_64 - 1;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 8, backup_buf);
                execs++;
                
                // big endian
                value = SWAP64(pattern_64);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 8, backup_buf);
                execs++;
                                
                // big endian add one
                value = SWAP64(SWAP64(pattern_64) + 1);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 8, backup_buf);
                execs++;
                
                // big endian sub one
                value = SWAP64(SWAP64(pattern_64) - 1);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 8, backup_buf);
                execs++;
              }
              
            }
            if (shape > 2 && valid_idx_len > 2) {
              u32 pattern_32 = (u32)pattern;
              u32 value = pattern_32;
              fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 4, backup_buf);
              execs++;
              
              if (cmplog_backup.headers[cmp_id].attribute == OP_AND || cmplog_backup.headers[cmp_id].attribute == OP_OR || cmplog_backup.headers[cmp_id].attribute == OP_XOR) {
                value = pattern_32 ^ 0xffffffff;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 4, backup_buf);
                execs++;
              }else{
                // little endian add one
                value = pattern_32 + 1;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 4, backup_buf);
                execs++;
                
                // little endian sub one
                value = pattern_32 - 1;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 4, backup_buf);
                execs++;
                
                // big endian
                value = SWAP32(pattern_32);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 4, backup_buf);
                execs++;   
                
                // big endian add one
                value = SWAP32(SWAP32(pattern_32) + 1);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 4, backup_buf);
                execs++;
                
                // big endian sub one
                value = SWAP32(SWAP32(pattern_32) - 1);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 4, backup_buf);
                execs++;
              }  
            }
            if(shape > 1 && valid_idx_len > 1) {
              u16 pattern_16 = (u16)pattern;
              u16 value = pattern_16;
              fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 2, backup_buf);
              execs++;
              
              if (cmplog_backup.headers[cmp_id].attribute == OP_AND || cmplog_backup.headers[cmp_id].attribute == OP_OR || cmplog_backup.headers[cmp_id].attribute == OP_XOR) {
                value = pattern_16 ^ 0xffff;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 2, backup_buf);
                execs++;
              }else{
                // little endian add one
                value = pattern_16 + 1;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 2, backup_buf);
                execs++;
                
                // little endian sub one
                value = pattern_16 - 1;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 2, backup_buf);
                execs++;
                
                // big endian
                value = SWAP16(pattern_16);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 2, backup_buf);
                execs++;
                
                // big endian add one
                value = SWAP16(SWAP16(pattern_16) + 1);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 2, backup_buf);
                execs++;
                
                // big endian sub one
                value = SWAP16(SWAP16(pattern_16) - 1);
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 2, backup_buf);
                execs++;
              }  
            }
            {
              u8 pattern_8 = (u8)pattern;
              u8 value = pattern_8;
              fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 1, backup_buf);
              execs++;
              
              if (cmplog_backup.headers[cmp_id].attribute == OP_AND || cmplog_backup.headers[cmp_id].attribute == OP_OR || cmplog_backup.headers[cmp_id].attribute == OP_XOR) {
                value = pattern_8 ^ 0xff;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 1, backup_buf);
                execs++;
              }else{
                // add one
                value = pattern_8 + 1;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 1, backup_buf);
                execs++;
                
                // sub one
                value = pattern_8 - 1;
                fti_mutate_input_to_state_stream(buf, len, valid_idx, valid_idx_len, value, 1, backup_buf);
                execs++;
                
              } 
            }
          } 
            
        }
        
      }
      
     }
  }

  new_hit_cnt = queued_paths + unique_crashes;
  stage_finds[STAGE_ITS]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ITS] += execs;
  add_schedule_info(addr, new_hit_cnt - orig_hit_cnt, execs);
  
  ck_free(backup_buf);
  return 0;

    
      
}



/* random everything with different values but stay in the same type */
static u8 type_random(u8 orig) {

  u8  c;

  do {

    switch (orig) {

      case 'A' ... 'F':
        c = 'A' + UR(1 + 'F' - 'A');
        break;
      case 'a' ... 'f':
        c = 'a' + UR(1 + 'f' - 'a');
        break;
      case '0':
        c = '1';
        break;
      case '1':
        c = '0';
        break;
      case '2' ... '9':
        c = '2' + UR(1 + '9' - '2');
        break;
      case 'G' ... 'Z':
        c = 'G' + UR(1 + 'Z' - 'G');
        break;
      case 'g' ... 'z':
        c = 'g' + UR(1 + 'z' - 'g');
        break;
      case '!' ... '*':
        c = '!' + UR(1 + '*' - '!');
        break;
      case ',' ... '.':
        c = ',' + UR(1 + '.' - ',');
        break;
      case ':' ... '@':
        c = ':' + UR(1 + '@' - ':');
        break;
      case '[' ... '`':
        c = '[' + UR(1 + '`' - '[');
        break;
      case '{' ... '~':
        c = '{' + UR(1 + '~' - '{');
        break;
      case '+':
        c = '/';
        break;
      case '/':
        c = '+';
        break;
      case ' ':
        c = '\t';
        break;
      case '\t':
        c = ' ';
        break;
      case '\r':
        c = '\n';
        break;
      case '\n':
        c = '\r';
        break;
      case 0:
        c = 1;
        break;
      case 1:
        c = 0;
        break;
      case 0xff:
        c = 0;
        break;
      default:
        if (orig < 32) {

          c = (orig ^ 0x1f);

        } else {

          c = (orig ^ 0x7f);  // we keep the highest bit

        }

    }

  } while (c == orig);

  
  return c;

}

static u8 fuzz_taint_inference_stream(struct queue_entry* q, u8* in_buf, u32 in_len) {
  u32 len, i, j;
  u8  *buf;
  u8* file_buf;
  u32 file_len;
  u32 cksum, newcksum;
  u64 orig_hit_cnt, new_hit_cnt;
  u64 orig_execs;
  u32 loggeds;

  u32 perf_score;

  perf_score = calculate_score(queue_cur);

  u32 max_energy   = HAVOC_CYCLES * perf_score / havoc_div / 100;
  
  static u64 all_mmios[MAX_STREAM_SIZE];
  u32 len_all_mmios = 0;

  stage_name = "fuzz-taint-inference";
  stage_short = "fti";

  u8* orig_buf = ck_alloc_nozero(MAX_STREAM_LEN);

  init_streams_input(&g_stream_input, in_buf, in_len, 0);
  
  get_streams_input_file(&g_stream_input, &file_buf, &file_len);
  if (get_exec_checksum(file_buf, file_len, &cksum)) return -1;

  memcpy(&cmplog_backup, cmplog_ptr, sizeof(struct cmp_map));

  if (unlikely(!q->fti_info)) {
    q->fti_info = ck_alloc(sizeof(struct fti_info));
    init_fti_info((struct fti_info*)q->fti_info);
  }

  // FIRST TAINT STAGE: TAINT STREAM ONE BY ONE
  khash_t(PTR) * kh_mmios = get_mmios(&g_stream_input);
  
  khiter_t k;
  for (k = kh_begin(kh_mmios); k != kh_end(kh_mmios); ++k){
    struct mmio* mmio = NULL;
    if (kh_exist(kh_mmios, k)) {
      mmio = kh_value(kh_mmios, k);
    }
    if (!mmio || mmio->valid == false){
      continue;
    }
    u64 addr = mmio->mmio_addr;
    // may skip base on addr?
    u16 size = mmio->size;
    u32 stream_id = mmio->stream_id;
    
    if (value_set_model_size > 0 && is_value_set_model(addr>>32, addr & 0xffffffff)) {
      continue;
    }

    if (passthrough_model_size > 0 && is_passthrough_model(addr>>32, addr & 0xffffffff)) {
      continue;
    }

    if (constant_model_size >0 && is_constant_model(addr>>32, addr & 0xffffffff)) {
      continue;
    }

    struct bitextract_mmio_model_config* model_config = is_bitextract_model(addr>>32, addr & 0xffffffff);
    if (model_config && model_config->mask_hamming_weight < 5){
      continue;
    }

    if (is_visited_fti_info(q->fti_info, addr)){
      continue;
    }
    

    if (unlikely(!get_stream_input(&g_stream_input, addr, &buf, &len))) {
      continue;
    }

    if (buf == NULL || len==0){
      continue;
    }

    orig_hit_cnt = queued_paths + unique_crashes;
    orig_execs = total_execs;

    // FIRST STAGE: GET THE MASK TAINT

    u64 tmpmask = 0;
    u8* tmpmask_buf = &tmpmask;
    memcpy(orig_buf, buf, len);

    for (int i=0;i<size;i++){
      memcpy(buf, orig_buf, len);
      for(int j=i;j<len;j+=size){  
        buf[j] ^= 0xff;
      }

      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
      if (unlikely(get_exec_checksum(file_buf, file_len, &newcksum))) {
        continue;
      }

      if(newcksum != cksum) {
        tmpmask_buf[i]=0xff;
      }else {
        for (int w = 0; w < CMP_MAP_W; ++w) {
          if (cmplog_backup.headers[w].hits != cmplog_ptr->headers[w].hits) { 
            tmpmask_buf[i]=0xff;
            break;
          }else{
            if(cmplog_backup.headers[w].type == CMP_TYPE_RTN) {
              loggeds = MIN(CMP_MAP_RTN_H,cmplog_backup.headers[w].hits);
            }else{
              loggeds = MIN(CMP_MAP_H,cmplog_backup.headers[w].hits);
            }

            u32 shape = SHAPE_BYTES(cmplog_backup.headers[w].shape);

            for(int h=0;h<loggeds;h++){
              if(cmplog_backup.headers[w].type == CMP_TYPE_RTN){
                u8* o_v0 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v0);
                u8* o_v1 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v1);
                u8* v0 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v0);
                u8* v1 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v1);

                if (strncmp(o_v0, v0, shape) || strncmp(o_v1, v1, shape)){
                  tmpmask_buf[i]=0xff;
                }
              }else{
                u64 o_v0 = cmplog_backup.log[w][h].v0;
                u64 o_v1 = cmplog_backup.log[w][h].v1;
                u64 v0 = cmplog_ptr->log[w][h].v0;
                u64 v1 = cmplog_ptr->log[w][h].v1;

                if(cmplog_backup.headers[w].attribute == OP_OR || cmplog_backup.headers[w].attribute == OP_AND || cmplog_backup.headers[w].attribute == OP_XOR) {

                }else if(o_v0 != v0 || o_v1 != v1) {
                  tmpmask_buf[i]=0xff;
                }

              }

              if (tmpmask_buf[i] == 0xff) {
                break;
              }       
            }

            if (tmpmask_buf[i] == 0xff) {
              break;
            }

          }
        }
      }
    }
    
    memcpy(buf, orig_buf, len);
    new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_FTI] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FTI] += total_execs - orig_execs;
      
    add_schedule_info(addr, new_hit_cnt - orig_hit_cnt, total_execs - orig_execs);
    if(tmpmask==0) {
      continue;
    }
    
    all_mmios[len_all_mmios++] = addr;

  }
    
  if (len_all_mmios==0){
    return 0;
  }
  u64 addr = schedule(all_mmios, len_all_mmios);
  
  add_visited_fti_info(q->fti_info, addr);
  struct mmio* mmio = get_mmio_by_addr(&g_stream_input, addr);
  if (mmio==NULL){
    return 0;
  }
  
  u16 size = mmio->size;
  u32 stream_id = mmio->stream_id;
  if (unlikely(!get_stream_input(&g_stream_input, addr, &buf, &len))) {
    return 0;     
  }
    
  if (buf == NULL || len == 0){
    return 0;
  }
  
  stage_max = 0;
  stage_cur = 0;
  orig_hit_cnt = queued_paths + unique_crashes;
  orig_execs = total_execs;

  // FIRST STAGE: GET THE MASK TAINT

  u64 tmpmask = 0;
  u8* tmpmask_buf = &tmpmask;
  memcpy(orig_buf, buf, len);

  for (int i=0;i<size;i++){
    memcpy(buf, orig_buf, len);
    for(int j=i;j<len;j+=size){  
      buf[j] ^= 0xff;
    }

    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    if (unlikely(get_exec_checksum(file_buf, file_len, &newcksum))) {
      continue;
    }

    if(newcksum != cksum) {
      tmpmask_buf[i]=0xff;
    }else {
      for (int w = 0; w < CMP_MAP_W; ++w) {
        if (cmplog_backup.headers[w].hits != cmplog_ptr->headers[w].hits) { 
          tmpmask_buf[i]=0xff;
          break;
        }else{
          if(cmplog_backup.headers[w].type == CMP_TYPE_RTN) {
            loggeds = MIN(CMP_MAP_RTN_H,cmplog_backup.headers[w].hits);
          }else{
            loggeds = MIN(CMP_MAP_H,cmplog_backup.headers[w].hits);
          }

          u32 shape = SHAPE_BYTES(cmplog_backup.headers[w].shape);

          for(int h=0;h<loggeds;h++){
            if(cmplog_backup.headers[w].type == CMP_TYPE_RTN){
              u8* o_v0 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v0);
              u8* o_v1 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v1);
              u8* v0 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v0);
              u8* v1 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v1);

              if (strncmp(o_v0, v0, shape) || strncmp(o_v1, v1, shape)){
                tmpmask_buf[i]=0xff;
              }
            }else{
              u64 o_v0 = cmplog_backup.log[w][h].v0;
              u64 o_v1 = cmplog_backup.log[w][h].v1;
              u64 v0 = cmplog_ptr->log[w][h].v0;
              u64 v1 = cmplog_ptr->log[w][h].v1;

              if(cmplog_backup.headers[w].attribute == OP_OR || cmplog_backup.headers[w].attribute == OP_AND || cmplog_backup.headers[w].attribute == OP_XOR) {

              }else if(o_v0 != v0 || o_v1 != v1) {
                tmpmask_buf[i]=0xff;
              }

            }

            if (tmpmask_buf[i] == 0xff) {
              break;
            }       
          }

          if (tmpmask_buf[i] == 0xff) {
            break;
          }

        }
      }
    }
  }
   
  if(tmpmask==0){
#ifdef TAINT_DEBUG
    fprintf(stderr, "addr:%016lx taint full\n",addr);
#endif
    goto taint_end;
  }

  stage_max = MIN(len, 5 * max_energy);
  stage_cur = 0;
  memcpy(buf, orig_buf, len);
  for (int j=0;j<stage_max;j++){
    stage_cur = j;
    
    if (tmpmask_buf[j%size]==0){
      continue;
    }
    u8 orig = buf[j];
    u8 changed;
    buf[j] = type_random(orig);
    //buf[j] ^= 0xff;
    //buf[j] = random() % 256;
    changed = buf[j];
    
    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    if (unlikely(get_exec_checksum(file_buf, file_len, &newcksum))) {
      continue;
    }

    buf[j] = orig;
     
    for (int w = 0; w < CMP_MAP_W; ++w) {
      if (cmplog_backup.headers[w].hits != cmplog_ptr->headers[w].hits) {
        add_indirect_fti_info(q->fti_info, w, addr, j, 0, 0, 0);
        add_stream_cmps_info(&g_cmp_info, addr, w);
        
        u32 max_loggeds;
        u32 orig_loggeds;
        if(cmplog_backup.headers[w].type == CMP_TYPE_RTN) {
          loggeds = MIN(CMP_MAP_RTN_H, cmplog_backup.headers[w].hits);
          max_loggeds = MIN(CMP_MAP_RTN_H, cmplog_ptr->headers[w].hits);
        }else{
          loggeds = MIN(CMP_MAP_H, cmplog_backup.headers[w].hits);
          max_loggeds = MIN(CMP_MAP_H, cmplog_ptr->headers[w].hits);
        }
        orig_loggeds = loggeds;
        loggeds = MIN(loggeds, cmplog_ptr->headers[w].hits);
        u32 shape = SHAPE_BYTES(cmplog_backup.headers[w].shape);
        
        for (int h=0; h<loggeds;h++){
          if(cmplog_backup.headers[w].type == CMP_TYPE_RTN){
            u8* o_v0 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v0);
            u8* o_v1 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v1);
            u8* v0 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v0);
            u8* v1 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v1);
            bool v0d = direct_copy_string(orig, o_v0, shape) && direct_copy_string(changed, v0, shape);
            bool v1d = direct_copy_string(orig, o_v1, shape) && direct_copy_string(changed, v1, shape);
            if (strncmp(o_v0,v0,shape) || strncmp(o_v1,v1,shape)){
              
              if (v0d && !strncmp(o_v1,v1,shape)) {
                maybe_add_auto(o_v1, shape);
              }
              if (strncmp(o_v0, o_v1,shape)){
                add_direct_fti_info(q->fti_info, w, addr, j, h, v0d, v1d);
              }
              
  
              bool first = false;
              if(strncmp(v0,v1,shape)){
                first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }else{
                first = !add_touched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }

              if (first) {
                stage_max *= 2;
                if (stage_max > len) {
                  stage_max = len;
                }
              }

            }
  
          }else{
            u64 o_v0 = cmplog_backup.log[w][h].v0;
            u64 o_v1 = cmplog_backup.log[w][h].v1;
            u64 v0 = cmplog_ptr->log[w][h].v0;
            u64 v1 = cmplog_ptr->log[w][h].v1;
            bool v0d = direct_copy(orig, o_v0, shape) && direct_copy(changed, v0, shape) ;
            bool v1d = direct_copy(orig, o_v1, shape) && direct_copy(changed, v1, shape) ;
            if(o_v0 != v0 || o_v1 != v1) {
              if(o_v0 != o_v1) {
                add_direct_fti_info(q->fti_info, w, addr, j, h, v0d, v1d);
              }
   
              bool first = false;
              if (cmplog_backup.headers[w].attribute == OP_ISUB || cmplog_backup.headers[w].attribute == OP_FCMP) {
                if (v0 == v1) {
                  first = !add_touched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }else{
                  first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }
              }else if(cmplog_backup.headers[w].attribute == OP_OR) {
                if (v0 | v1) {
                  first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }else{
                  first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }
              }else if(cmplog_backup.headers[w].attribute == OP_AND){
                if (v0 & v1) {
                  first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }else{
                  first = !add_untouched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }          
              }else if(cmplog_backup.headers[w].attribute == OP_XOR) {
                if (v0 ^ v1) {
                  first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }else{
                  first = !add_untouched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }         
              }
              if (first) {
                stage_max *= 2;
                if (stage_max > len) {
                  stage_max = len;
                }
              } 
            }
          }  
            
        }

        for (int h=loggeds; h<orig_loggeds;h++) {
          if(cmplog_backup.headers[w].type == CMP_TYPE_RTN){
            u8* v0 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v0);
            u8* v1 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v1);
            bool v0d = direct_copy_string(changed, v0, shape);
            bool v1d = direct_copy_string(changed, v1, shape);
            if (v0d) {
              maybe_add_auto(v1, shape);
            }

            bool first = false;
            if(strncmp(v0, v1,shape)){
              first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
            }else{
              first = !add_touched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
            }
            if (first) {
              stage_max *= 2;
              if (stage_max > len) {
                stage_max = len;
              }
            }
            
          }else{
            u64 v0 = cmplog_backup.log[w][h].v0;
            u64 v1 = cmplog_backup.log[w][h].v1;
            bool v0d = direct_copy(changed, v0, shape) ;
            bool v1d = direct_copy(changed, v1, shape) ;
            
            if(v0d){
              if(shape == 8) {
                u64 pattern = v1;
                maybe_add_auto(&pattern, shape);
              }
              if(shape == 4) {
                u32 pattern = v1;
                maybe_add_auto(&pattern, shape);
              }
            }
            if(v1d){
              if(shape == 8) {
                u64 pattern = v0;
                maybe_add_auto(&pattern, shape);
              }
              if(shape == 4) {
                u32 pattern = v0;
                maybe_add_auto(&pattern, shape);
              }
            }

            bool first = false;
            if (cmplog_backup.headers[w].attribute == OP_ISUB || cmplog_backup.headers[w].attribute == OP_FCMP) {
              if (v0 == v1) {
                first = !add_touched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }else{
                first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }
            }else if(cmplog_backup.headers[w].attribute == OP_OR) {
              if (v0 | v1) {
                first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }else{
                first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }
            }else if(cmplog_backup.headers[w].attribute == OP_AND){
              if (v0 & v1) {
                first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }else{
                first = !add_untouched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }          
            }else if(cmplog_backup.headers[w].attribute == OP_XOR) {
              if (v0 ^ v1) {
                first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }else{
                first = !add_untouched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }         
            }
            if (first) {
              stage_max *= 2;
              if (stage_max > len) {
                stage_max = len;
              }
            }

          }  
            
        }

        for (int h=loggeds; h<max_loggeds;h++){
          if(cmplog_ptr->headers[w].type == CMP_TYPE_RTN){
            u8* v0 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v0);
            u8* v1 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v1);
            bool v0d = direct_copy_string(changed, v0, shape);
            bool v1d = direct_copy_string(changed, v1, shape);

            bool first = false;
            if(strncmp(v0,v1,shape)){
              first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
            }else{
              first = !add_touched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
            }
            if (first) {
              stage_max *= 2;
              if (stage_max > len) {
                stage_max = len;
              }
            }
            
          }else{
            u64 v0 = cmplog_ptr->log[w][h].v0;
            u64 v1 = cmplog_ptr->log[w][h].v1;
            bool v0d = direct_copy(changed, v0, shape) ;
            bool v1d = direct_copy(changed, v1, shape) ;

            bool first = false;
            if (cmplog_backup.headers[w].attribute == OP_ISUB || cmplog_backup.headers[w].attribute == OP_FCMP) {
              if (v0 == v1) {
                first = !add_touched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }else{
                first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }
            }else if(cmplog_backup.headers[w].attribute == OP_OR) {
              if (v0 | v1) {
                first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }else{
                first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }
            }else if(cmplog_backup.headers[w].attribute == OP_AND){
              if (v0 & v1) {
                first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }else{
                first = !add_untouched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }          
            }else if(cmplog_backup.headers[w].attribute == OP_XOR) {
              if (v0 ^ v1) {
                first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }else{
                first = !add_untouched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }         
            }
            if (first) {
              stage_max *= 2;
              if (stage_max > len) {
                stage_max = len;
              }
            }
          }  
            
        }
    
      }else{
        
        if(cmplog_backup.headers[w].type == CMP_TYPE_RTN) {
          loggeds = MIN(CMP_MAP_RTN_H, cmplog_backup.headers[w].hits);
        }else{
          loggeds = MIN(CMP_MAP_H, cmplog_backup.headers[w].hits);
        }
        u32 shape = SHAPE_BYTES(cmplog_backup.headers[w].shape);
        
        
        for (int h=0; h<loggeds;h++){
          if(cmplog_backup.headers[w].type == CMP_TYPE_RTN){
            u8* o_v0 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v0);
            u8* o_v1 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v1);
            u8* v0 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v0);
            u8* v1 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v1);
            bool v0d = direct_copy_string(orig, o_v0, shape) && direct_copy_string(changed, v0, shape);
            bool v1d = direct_copy_string(orig, o_v1, shape) && direct_copy_string(changed, v1, shape);
            if (strncmp(o_v0,v0,shape) || strncmp(o_v1,v1,shape)){
            
              if (v0d && !strncmp(o_v1,v1,shape)) {
                maybe_add_auto(o_v1, shape);
              }
              if (strncmp(o_v0,o_v1,shape)) {
                add_direct_fti_info(q->fti_info, w, addr, j, h, v0d, v1d);
                add_stream_cmps_info(&g_cmp_info, addr, w);
              }
              
              bool first = false;
              if(strncmp(v0,v1,shape)){
                first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }else{
                first = !add_touched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }
              if (first) {
                stage_max *= 2;
                if (stage_max > len) {
                  stage_max = len;
                }
              }
            }

            
            
          }else{
            u64 o_v0 = cmplog_backup.log[w][h].v0;
            u64 o_v1 = cmplog_backup.log[w][h].v1;
            u64 v0 = cmplog_ptr->log[w][h].v0;
            u64 v1 = cmplog_ptr->log[w][h].v1;
            bool v0d = direct_copy(orig, o_v0, shape) && direct_copy(changed, v0, shape) ;
            bool v1d = direct_copy(orig, o_v1, shape) && direct_copy(changed, v1, shape) ;
            if(o_v0 != v0 || o_v1 != v1) {
              if (o_v0 != o_v1) {
                add_direct_fti_info(q->fti_info, w, addr, j, h, v0d, v1d);
                add_stream_cmps_info(&g_cmp_info, addr, w);
              }
              
              bool first = false;
              if (cmplog_backup.headers[w].attribute == OP_ISUB || cmplog_backup.headers[w].attribute == OP_FCMP) {
                if (v0 == v1) {
                  first = !add_touched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }else{
                  first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }
              }else if(cmplog_backup.headers[w].attribute == OP_OR) {
                if (v0 | v1) {
                  first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }else{
                  first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }
              }else if(cmplog_backup.headers[w].attribute == OP_AND){
                if (v0 & v1) {
                  first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }else{
                  first = !add_untouched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }          
              }else if(cmplog_backup.headers[w].attribute == OP_XOR) {
                if (v0 ^ v1) {
                  first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }else{
                  first = !add_untouched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }         
              }
              if (first) {
                stage_max *= 2;
                if (stage_max > len) {
                  stage_max = len;
                }
              }    
            }
          }             
        }      
      }       
    }
  }  

  fti_mutate_its_stream(q, addr, size, &cmplog_backup);
taint_end:
  memcpy(buf, orig_buf, len);
  new_hit_cnt = queued_paths + unique_crashes;
  stage_finds[STAGE_FTI] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FTI] += total_execs - orig_execs;
  add_schedule_info(addr, new_hit_cnt - orig_hit_cnt, total_execs - orig_execs);


  ck_free(orig_buf); 
  return 0;
}


static u8 fuzz_taint_inference_stream_test(struct queue_entry* q, u8* in_buf, u32 in_len) {
  u32 len, i, j;
  u8  *buf;
  u8* file_buf;
  u32 file_len;
  u32 cksum, newcksum;
  u64 orig_hit_cnt, new_hit_cnt;
  u64 orig_execs;
  u32 loggeds;
  u32 perf_score;

  perf_score = calculate_score(queue_cur);

  u32 max_energy   = HAVOC_CYCLES * perf_score / havoc_div / 100;

  static u32 visited_streams[MAX_STREAM_SIZE];
  u32 len_visited_streams = 0;

  stage_name = "fuzz-taint-inference";
  stage_short = "fti";
  
  u8* orig_buf = ck_alloc_nozero(MAX_STREAM_LEN);

  init_streams_input(&g_stream_input, in_buf, in_len, 0);
  
  get_streams_input_file(&g_stream_input, &file_buf, &file_len);
  if (get_exec_checksum(file_buf, file_len, &cksum)) return -1;

  memcpy(&cmplog_backup, cmplog_ptr, sizeof(struct cmp_map));

#ifdef TAINT_DEBUG
  s32 fd;
  static int tmp_id = 0;
  
  u8* fn = (char*)alloc_printf("%s/taint/id:%06d", out_dir, tmp_id);
  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  ck_free(fn);
  FILE *file = fdopen(fd,"w");
  if (file == NULL) PFATAL("Unable to create '%s'", fn);
  tmp_id++;
#endif

  if (unlikely(!q->fti_info)) {
    q->fti_info = ck_alloc(sizeof(struct fti_info));
    init_fti_info((struct fti_info*)q->fti_info);
  }
  
#ifdef TAINT_DEBUG
  fprintf(file,"b##########################\n");
#endif

  for (int w = 0; w < CMP_MAP_W; ++w) {
    if(cmplog_backup.headers[w].type == CMP_TYPE_RTN) {
      loggeds = MIN(CMP_MAP_RTN_H, cmplog_backup.headers[w].hits);
    }else{
      loggeds = MIN(CMP_MAP_H, cmplog_backup.headers[w].hits);
    }
    u32 shape = SHAPE_BYTES(cmplog_backup.headers[w].shape);
            
    for (int h=0; h<loggeds;h++){
      if(cmplog_backup.headers[w].type == CMP_TYPE_RTN){
        u8* o_v0 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v0);
        u8* o_v1 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v1);
        
        bool first = false;
        if(strncmp(o_v0,o_v1,shape)){
          first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
        }else{
          first = !add_touched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
        }
#ifdef TAINT_DEBUG       
        fprintf(file, "key:%5d h:%2d attr:%d type:%d first;%d",w, h, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type,first);
        fprintf(file,"o: ");
        for(int tt=0;tt<32;tt++){
          fprintf(file,"%02x",o_v0[tt]);
        }
        fprintf(file," ");
        for(int tt=0;tt<32;tt++){
          fprintf(file,"%02x",o_v1[tt]);
        }
            
        fprintf(file,"\n");
#endif             
      }else{
        u64 o_v0 = cmplog_backup.log[w][h].v0;
        u64 o_v1 = cmplog_backup.log[w][h].v1;
        
        
        bool first = false;
        if (cmplog_backup.headers[w].attribute == OP_ISUB || cmplog_backup.headers[w].attribute == OP_FCMP) {
          if (o_v0 == o_v1) {
            first = !add_touched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
          }else{
            first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
          }
        }else if(cmplog_backup.headers[w].attribute == OP_OR) {
          if (o_v0 | o_v1) {
            first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
          }else{
            first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
          }
        }else if(cmplog_backup.headers[w].attribute == OP_AND){
          if (o_v0 & o_v1) {
            first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
          }else{
            first = !add_untouched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
          }          
        }else if(cmplog_backup.headers[w].attribute == OP_XOR) {
          if (o_v0 ^ o_v1) {
            first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
          }else{
            first = !add_untouched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
          }         
        }
        
        if (first) {
          max_energy *= 2;
        }
#ifdef TAINT_DEBUG        
        fprintf(file, "key:%5d h:%2d o:%016lx %016lx attr:%d type:%d first:%d\n",w,h,o_v0, o_v1,
             cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, first);
#endif          
      }         
    }       
  }

#ifdef TAINT_DEBUG
  fprintf(file,"e##########################\n");
#endif

  khash_t(PTR) * kh_mmios = get_mmios(&g_stream_input);
  
  khiter_t k;
  for (k = kh_begin(kh_mmios); k != kh_end(kh_mmios); ++k){
    struct mmio* mmio = NULL;
    
    if (kh_exist(kh_mmios, k)) {
      mmio = kh_value(kh_mmios, k);
    }
    if (!mmio || mmio->valid == false){
      continue;
    }
    u64 addr = mmio->mmio_addr;
    // may skip base on addr?
    u16 size = mmio->size;
    u32 stream_id = mmio->stream_id;
    
    if (value_set_model_size > 0 && is_value_set_model(addr>>32, addr & 0xffffffff)) {
      continue;
    }
    
    if (passthrough_model_size > 0 && is_passthrough_model(addr>>32, addr & 0xffffffff)) {
      continue;
    }
    
    if (constant_model_size >0 && is_constant_model(addr>>32, addr & 0xffffffff)) {
      continue;
    }

    struct bitextract_mmio_model_config* model_config = is_bitextract_model(addr>>32, addr & 0xffffffff);
    
    
    if (model_config && model_config->mask_hamming_weight < 7){
      continue;
    }

    
    if (is_visited(visited_streams, len_visited_streams, stream_id)) {
      continue;
    }
    visited_streams[len_visited_streams++] = stream_id;
    
    add_visited_fti_info(q->fti_info, addr);

    if (unlikely(!get_stream_input(&g_stream_input, addr, &buf, &len))) {
      continue;     
    }
    
    if (buf == NULL || len==0){
      continue;
    }
    
    // taint stream one by one
#ifdef TAINT_DEBUG
    fprintf(file,"begin taint mmio:%016lx len:%d\n",addr,len);
#endif    

    orig_hit_cnt = queued_paths + unique_crashes;
    orig_execs = total_execs;
    
    
    // FIRST STAGE: GET THE MASK TAINT
    u64 tmpmask = 0;
    u8* tmpmask_buf = &tmpmask;
    memcpy(orig_buf, buf, len);
    for (int i=0;i<size;i++){
      memcpy(buf, orig_buf, len);
      for(int j=i;j<len;j+=size){  
        buf[j] ^= 0xff;
        //buf[j] = random() % 256;  
      }

      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
      if (unlikely(get_exec_checksum(file_buf, file_len, &newcksum))) {
        continue;
      }

      if(newcksum != cksum) {
        tmpmask_buf[i]=0xff;
      }else {
        for (int w = 0; w < CMP_MAP_W; ++w) {
          if (cmplog_backup.headers[w].hits != cmplog_ptr->headers[w].hits) { 
            tmpmask_buf[i]=0xff;
            break;
          }else{
            if(cmplog_backup.headers[w].type == CMP_TYPE_RTN) {
              loggeds = MIN(CMP_MAP_RTN_H,cmplog_backup.headers[w].hits);
            }else{
              loggeds = MIN(CMP_MAP_H,cmplog_backup.headers[w].hits);
            }
            u32 shape = SHAPE_BYTES(cmplog_backup.headers[w].shape);
            
            for(int h=0;h<loggeds;h++){
              if(cmplog_backup.headers[w].type == CMP_TYPE_RTN){
                u8* o_v0 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v0);
                u8* o_v1 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v1);
                u8* v0 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v0);
                u8* v1 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v1);
              
                if (strncmp(o_v0, v0, shape) || strncmp(o_v1, v1, shape)){
                  tmpmask_buf[i]=0xff;
                }
              }else{
                
                u64 o_v0 = cmplog_backup.log[w][h].v0;
                u64 o_v1 = cmplog_backup.log[w][h].v1;
                u64 v0 = cmplog_ptr->log[w][h].v0;
                u64 v1 = cmplog_ptr->log[w][h].v1;
                if(cmplog_backup.headers[w].attribute == OP_OR || cmplog_backup.headers[w].attribute == OP_AND || cmplog_backup.headers[w].attribute == OP_XOR) {
                  // v0 is direct and v1 is constant , v1 is direct and v0 is constant
                 /* tmpmask_buf[i]=0xff;
                  u64 tmp_v = o_v0 ^ v0;
                 
                  while(tmp_v) {
                    if (tmp_v == 0xff) {
                      tmpmask_buf[i]=0;
                      break;
                    }
                    tmp_v >>= 8;
                  }
                  
                  
                  tmp_v = o_v1 ^ v1;
                  while(tmp_v) {
                    if (tmp_v == 0xff) {
                      tmpmask_buf[i]=0;
                      break;
                    }
                    tmp_v >>= 8;
                  }*/
                  
                }else if(o_v0 != v0 || o_v1 != v1) {
                  tmpmask_buf[i]=0xff;
                }
              }
               
              if (tmpmask_buf[i] == 0xff) {
                break;
              }       
            }
          }
          
          
        }
        
      }
    }
    
    if(tmpmask==0) {
#ifdef TAINT_DEBUG
      fprintf(stderr, "addr:%016lx taint full\n",addr);
#endif
      goto taint_end;
    }
    
    new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_FTI] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FTI] += total_execs - orig_execs;
    
    add_schedule_info(addr, new_hit_cnt - orig_hit_cnt, total_execs - orig_execs);

    memcpy(buf, orig_buf, len);
    
    stage_max = MIN(len, max_energy);
    stage_max = MIN(1024, stage_max);
    stage_cur = 0;
    for (int j=0;j<stage_max;j++){
      stage_cur = j;
      stage_name = "fuzz-taint-inference";
      stage_short = "fti";
      orig_hit_cnt = queued_paths + unique_crashes;
      orig_execs = total_execs;
      
      if (tmpmask_buf[j%size]==0){
        stage_max++;
        continue;
      }
      u8 orig = buf[j];
      u8 changed;
      buf[j] = type_random(orig);
      //buf[j] ^= 0xff;
      //buf[j] = random() % 256;
      changed = buf[j];
      
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
      if (unlikely(get_exec_checksum(file_buf, file_len, &newcksum))) {
        continue;
      }

      buf[j] = orig;
      new_hit_cnt = queued_paths + unique_crashes;
      stage_finds[STAGE_FTI] += new_hit_cnt - orig_hit_cnt;
      stage_cycles[STAGE_FTI] += total_execs - orig_execs;
      add_schedule_info(addr, new_hit_cnt - orig_hit_cnt, total_execs - orig_execs);
#ifdef TAINT_DEBUG
      fprintf(file,"idx:%d\n",j);
#endif      
      for (int w = 0; w < CMP_MAP_W; ++w) {
        if (cmplog_backup.headers[w].hits != cmplog_ptr->headers[w].hits) {
          #ifdef TAINT_DEBUG
          fprintf(file, " addr:%016lx key:%d hits not eq: %d vs %d\n",addr, w, cmplog_backup.headers[w].hits, cmplog_ptr->headers[w].hits);
          #endif
          add_indirect_fti_info(q->fti_info, w, addr, j, 0, 0, 0);
          add_stream_cmps_info(&g_cmp_info, addr, w);
          
          u32 max_loggeds;
          u32 orig_loggeds;
          if(cmplog_backup.headers[w].type == CMP_TYPE_RTN) {
            loggeds = MIN(CMP_MAP_RTN_H, cmplog_backup.headers[w].hits);
            max_loggeds = MIN(CMP_MAP_RTN_H, cmplog_ptr->headers[w].hits);
          }else{
            loggeds = MIN(CMP_MAP_H, cmplog_backup.headers[w].hits);
            max_loggeds = MIN(CMP_MAP_H, cmplog_ptr->headers[w].hits);
          }
          orig_loggeds = loggeds;
          loggeds = MIN(loggeds, cmplog_ptr->headers[w].hits);
          u32 shape = SHAPE_BYTES(cmplog_backup.headers[w].shape);
          
          
          for (int h=0; h<loggeds;h++){
            if(cmplog_backup.headers[w].type == CMP_TYPE_RTN){
              u8* o_v0 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v0);
              u8* o_v1 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v1);
              u8* v0 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v0);
              u8* v1 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v1);
              bool v0d = direct_copy_string(orig, o_v0, shape) && direct_copy_string(changed, v0, shape);
              bool v1d = direct_copy_string(orig, o_v1, shape) && direct_copy_string(changed, v1, shape);
              if (strncmp(o_v0,v0,shape) || strncmp(o_v1,v1,shape)){
                
                if (v0d && !strncmp(o_v1,v1,shape)) {
                  maybe_add_auto(o_v1, shape);
                }
                if (strncmp(o_v0, o_v1, shape)) {
                  add_direct_fti_info(q->fti_info, w, addr, j, h, v0d, v1d);
                }
                #ifdef TAINT_DEBUG
                fprintf(file, "hit not eq addr:%016lx size:%d key:%5d h:%2d v0d:%d v1d:%d attr:%d type:%d",addr,size,w,h, v0d,v1d,
                    cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type);
                fprintf(file,"o:");
                for(int tt=0;tt<32;tt++){
                  fprintf(file,"%02x",o_v0[tt]);
                }
                fprintf(file," ");
                for(int tt=0;tt<32;tt++){
                  fprintf(file,"%02x",o_v1[tt]);
                }
                fprintf(file," ");
                
                fprintf(file,"c:");
                for(int tt=0;tt<32;tt++){
                  fprintf(file,"%02x",v0[tt]);
                }
                fprintf(file," ");
                for(int tt=0;tt<32;tt++){
                  fprintf(file,"%02x",v1[tt]);
                }
                fprintf(file," ");
                
                fprintf(file,"\n");
                #endif
                bool first = false;
                if(strncmp(v0,v1,shape)){
                  first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }else{
                  first = !add_touched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }
                
                if (first) {
                  stage_max *= 2;
                  if (stage_max > len) {
                    stage_max = len;
                  }
                }
              }
              

            }else{
              u64 o_v0 = cmplog_backup.log[w][h].v0;
              u64 o_v1 = cmplog_backup.log[w][h].v1;
              u64 v0 = cmplog_ptr->log[w][h].v0;
              u64 v1 = cmplog_ptr->log[w][h].v1;
              bool v0d = direct_copy(orig, o_v0, shape) && direct_copy(changed, v0, shape) ;
              bool v1d = direct_copy(orig, o_v1, shape) && direct_copy(changed, v1, shape) ;
              if(o_v0 != v0 || o_v1 != v1) {
                if (o_v0 != o_v1){
                  add_direct_fti_info(q->fti_info, w, addr, j, h, v0d, v1d);
                }

                #ifdef TAINT_DEBUG
                fprintf(file, "hit not eq addr:%016lx size:%d key:%5d h:%2d o:%016lx %016lx c:%016lx %016lx v0d:%d v1d:%d attr:%d type:%d\n",addr,size,w,h,o_v0, o_v1, v0, v1, v0d,v1d,
                    cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type);
                #endif    
                bool first = false;
                if (cmplog_backup.headers[w].attribute == OP_ISUB || cmplog_backup.headers[w].attribute == OP_FCMP) {
                  if (v0 == v1) {
                    first = !add_touched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                  }else{
                    first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                  }
                }else if(cmplog_backup.headers[w].attribute == OP_OR) {
                  if (v0 | v1) {
                    first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                  }else{
                    first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                  }
                }else if(cmplog_backup.headers[w].attribute == OP_AND){
                  if (v0 & v1) {
                    first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                  }else{
                    first = !add_untouched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                  }          
               }else if(cmplog_backup.headers[w].attribute == OP_XOR) {
                  if (v0 ^ v1) {
                    first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                  }else{
                    first = !add_untouched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                  }         
               }
               
               if (first) {
                  stage_max *= 2;
                  if (stage_max > len) {
                    stage_max = len;
                  }
               }
               
              }
            }  
              
          }

          for (int h=loggeds; h<orig_loggeds;h++) {
            if(cmplog_backup.headers[w].type == CMP_TYPE_RTN){
              u8* v0 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v0);
              u8* v1 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v1);
              bool v0d = direct_copy_string(changed, v0, shape);
              bool v1d = direct_copy_string(changed, v1, shape);
              if (v0d) {
                maybe_add_auto(v1, shape);
              }
              
            }else{
              u64 v0 = cmplog_backup.log[w][h].v0;
              u64 v1 = cmplog_backup.log[w][h].v1;
              bool v0d = direct_copy(changed, v0, shape) ;
              bool v1d = direct_copy(changed, v1, shape) ;
              
              if(v0d){
                if(shape == 8) {
                  u64 pattern = v1;
                  maybe_add_auto(&pattern, shape);
                }
                if(shape == 4) {
                  u32 pattern = v1;
                  maybe_add_auto(&pattern, shape);
                }
              }
              if(v1d){
                if(shape == 8) {
                  u64 pattern = v0;
                  maybe_add_auto(&pattern, shape);
                }
                if(shape == 4) {
                  u32 pattern = v0;
                  maybe_add_auto(&pattern, shape);
                }
              }
            }  
              
          }
          #ifdef TAINT_DEBUG
          fprintf(file, "diff------------------->\n");
          #endif
          for (int h=loggeds; h<max_loggeds;h++){
            if(cmplog_ptr->headers[w].type == CMP_TYPE_RTN){
              u8* v0 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v0);
              u8* v1 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v1);
              bool v0d = direct_copy_string(changed, v0, shape);
              bool v1d = direct_copy_string(changed, v1, shape);
              
              #ifdef TAINT_DEBUG
              fprintf(file, "hit not eq addr:%016lx size:%d key:%5d h:%2d v0d:%d v1d:%d attr:%d type:%d",addr,size, w, h, v0d,v1d,
                    cmplog_ptr->headers[w].attribute, cmplog_ptr->headers[w].type);

                
              fprintf(file,"c:");
              for(int tt=0;tt<32;tt++){
                fprintf(file,"%02x",v0[tt]);
              }
              fprintf(file," ");
              for(int tt=0;tt<32;tt++){
                fprintf(file,"%02x",v1[tt]);
              }
              
                
              fprintf(file,"\n");
              #endif

              bool first = false;
              if(strncmp(v0,v1,shape)){
                first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }else{
                first = !add_touched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
              }
              
              if (first) {
                stage_max *= 2;
                if (stage_max > len) {
                  stage_max = len;
                }
              }
              
            }else{
              u64 v0 = cmplog_ptr->log[w][h].v0;
              u64 v1 = cmplog_ptr->log[w][h].v1;
              bool v0d = direct_copy(changed, v0, shape) ;
              bool v1d = direct_copy(changed, v1, shape) ;
              #ifdef TAINT_DEBUG
              fprintf(file, "hit not eq addr:%016lx size:%d key:%5d h:%2d c:%016lx %016lx v0d:%d v1d:%d attr:%d type:%d\n",addr,size,w,h, v0, v1, v0d,v1d,
                  cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type);
              #endif
              bool first = false;
              if (cmplog_backup.headers[w].attribute == OP_ISUB || cmplog_backup.headers[w].attribute == OP_FCMP) {
                if (v0 == v1) {
                  first = !add_touched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }else{
                  first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }
              }else if(cmplog_backup.headers[w].attribute == OP_OR) {
                if (v0 | v1) {
                  first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }else{
                  first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }
              }else if(cmplog_backup.headers[w].attribute == OP_AND){
                if (v0 & v1) {
                  first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }else{
                  first = !add_untouched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }          
             }else if(cmplog_backup.headers[w].attribute == OP_XOR) {
                if (v0 ^ v1) {
                  first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }else{
                  first = !add_untouched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }         
             }
             
             if (first) {
               stage_max *= 2;
               if (stage_max > len) {
                 stage_max = len;
               }
             }
             
            }  
              
          }
          #ifdef TAINT_DEBUG
          fprintf(file, "diff-------------------<\n");
          #endif
          
          
         
            
        }else{
          
          if(cmplog_backup.headers[w].type == CMP_TYPE_RTN) {
            loggeds = MIN(CMP_MAP_RTN_H, cmplog_backup.headers[w].hits);
          }else{
            loggeds = MIN(CMP_MAP_H, cmplog_backup.headers[w].hits);
          }
          u32 shape = SHAPE_BYTES(cmplog_backup.headers[w].shape);
          
          
          for (int h=0; h<loggeds;h++){
            if(cmplog_backup.headers[w].type == CMP_TYPE_RTN){
              u8* o_v0 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v0);
              u8* o_v1 = &(((struct cmpfn_operands*)(cmplog_backup.log[w]))[h].v1);
              u8* v0 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v0);
              u8* v1 = &(((struct cmpfn_operands*)(cmplog_ptr->log[w]))[h].v1);
              bool v0d = direct_copy_string(orig, o_v0, shape) && direct_copy_string(changed, v0, shape);
              bool v1d = direct_copy_string(orig, o_v1, shape) && direct_copy_string(changed, v1, shape);
              if (strncmp(o_v0,v0,shape) || strncmp(o_v1,v1,shape)){
              
                if (v0d && !strncmp(o_v1,v1,shape)) {
                  maybe_add_auto(o_v1, shape);
                }
                if (strncmp(o_v0,o_v1,shape)){
                  add_direct_fti_info(q->fti_info, w, addr, j, h, v0d, v1d);
                  add_stream_cmps_info(&g_cmp_info, addr, w);
                }
                #ifdef TAINT_DEBUG
                fprintf(file, "hit eq addr:%016lx size:%d key:%5d h:%2d v0d:%d v1d:%d attr:%d type:%d",addr,size,w,h, v0d,v1d,
                    cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type);
                fprintf(file,"o:");
                for(int tt=0;tt<32;tt++){
                  fprintf(file,"%02x",o_v0[tt]);
                }
                fprintf(file," ");
                for(int tt=0;tt<32;tt++){
                  fprintf(file,"%02x",o_v1[tt]);
                }
                fprintf(file," ");
                
                fprintf(file,"c:");
                for(int tt=0;tt<32;tt++){
                  fprintf(file,"%02x",v0[tt]);
                }
                fprintf(file," ");
                for(int tt=0;tt<32;tt++){
                  fprintf(file,"%02x",v1[tt]);
                }
                fprintf(file," ");
                
                fprintf(file,"\n");
                #endif
                bool first = false;
                if(strncmp(v0,v1,shape)){
                  first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }else{
                  first = !add_touched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                }
                
                if (first) {
                  stage_max *= 2;
                  if (stage_max > len) {
                    stage_max = len;
                  }
                }
              }
              
              
            }else{
              u64 o_v0 = cmplog_backup.log[w][h].v0;
              u64 o_v1 = cmplog_backup.log[w][h].v1;
              u64 v0 = cmplog_ptr->log[w][h].v0;
              u64 v1 = cmplog_ptr->log[w][h].v1;
              bool v0d = direct_copy(orig, o_v0, shape) && direct_copy(changed, v0, shape) ;
              bool v1d = direct_copy(orig, o_v1, shape) && direct_copy(changed, v1, shape) ;
              if(o_v0 != v0 || o_v1 != v1) {
                if (o_v0 != o_v1) {
                  add_direct_fti_info(q->fti_info, w, addr, j, h, v0d, v1d);
                  add_stream_cmps_info(&g_cmp_info, addr, w);
                }
                #ifdef TAINT_DEBUG
                fprintf(file, "hit eq addr:%016lx size:%d key:%5d h:%2d o:%016lx %016lx c:%016lx %016lx v0d:%d v1d:%d attr:%d type:%d\n",addr,size,w,h,o_v0, o_v1, v0, v1, v0d,v1d,
                    cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type);
                #endif
                bool first = false;
                if (cmplog_backup.headers[w].attribute == OP_ISUB || cmplog_backup.headers[w].attribute == OP_FCMP) {
                  if (v0 == v1) {
                    first = !add_touched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                  }else{
                    first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                  }
                }else if(cmplog_backup.headers[w].attribute == OP_OR) {
                  if (v0 | v1) {
                    first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                  }else{
                    first = !add_untouched(&g_cmp_info, w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                  }
                }else if(cmplog_backup.headers[w].attribute == OP_AND){
                  if (v0 & v1) {
                    first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                  }else{
                    first = !add_untouched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                  }          
               }else if(cmplog_backup.headers[w].attribute == OP_XOR) {
                  if (v0 ^ v1) {
                    first = !add_touched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                  }else{
                    first = !add_untouched(&g_cmp_info,  w, 1, cmplog_backup.headers[w].attribute, cmplog_backup.headers[w].type, shape);
                  }         
               }
               
               if (first) {
                 stage_max *= 2;
                 if (stage_max > len) {
                   stage_max = len;
                 }
               }
               
              }
            }  
              
          }
        
        }
          

      }
    }  

    fti_mutate_its_stream(q, addr, size, &cmplog_backup);
taint_end:
    memcpy(buf, orig_buf, len);
    new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_FTI] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FTI] += total_execs - orig_execs;
    add_schedule_info(addr, new_hit_cnt - orig_hit_cnt, total_execs - orig_execs);

  }
  #ifdef TAINT_DEBUG
  //debug_fti_info(q->fti_info, file);
  fprintf(file,"b==========================\n");
  for (int w = 0; w < CMP_MAP_W; ++w) {
    if ((get_touched(&g_cmp_info,w) && !(get_untouched(&g_cmp_info,w))) || (get_untouched(&g_cmp_info,w) && !(get_touched(&g_cmp_info,w))))  {
      fprintf(file, "key:%5d \n",w);
    }       
  }    
  fprintf(file,"e==========================\n");
  
  fclose(file);
  #endif
  ck_free(orig_buf); 
  return 0;
}

#if 0
static u8 fuzz_taint_inference_stream_bak(struct queue_entry* q, u8* in_buf, u32 in_len) {
  u32 len, i, j;
  u8  *buf;
  u8* file_buf;
  u32 file_len;
  u32 cksum, newcksum;
  u64 orig_hit_cnt, new_hit_cnt;
  u64 orig_execs;
  u32 loggeds;

  static u32 visited_streams[MAX_STREAM_SIZE];
  u32 len_visited_streams = 0;


  stage_name = "fuzz-taint-inference";
  stage_short = "fti";

  if (unlikely(!pass_stats)) {

    pass_stats = ck_alloc(sizeof(struct afl_pass_stat) * CMP_MAP_W);

  }

  u8* orig_buf = ck_alloc_nozero(MAX_STREAM_LEN);

  u8 fti[MAX_STREAM_LEN];
  memset(&fti,0,MAX_STREAM_LEN);

  init_streams_input(&g_stream_input, in_buf, in_len, 0);
  
  get_streams_input_file(&g_stream_input, &file_buf, &file_len);
  if (get_exec_checksum(file_buf, file_len, &cksum)) return -1;

  memcpy(&cmplog_backup, cmplog_ptr, sizeof(struct cmp_map));

  khash_t(PTR) * kh_mmios = get_mmios(&g_stream_input);
  
  khiter_t k;
  for (k = kh_begin(kh_mmios); k != kh_end(kh_mmios); ++k){
    struct mmio* mmio = NULL;
    if (kh_exist(kh_mmios, k)) {
      mmio = kh_value(kh_mmios, k);
    }
    if (!mmio || mmio->valid == false){
      continue;
    }
    u64 addr = mmio->mmio_addr;
    // may skip base on addr?
    u16 size = mmio->size;
    u32 stream_id = mmio->stream_id;
    
    if (is_visited(visited_streams, len_visited_streams, stream_id)) {
      continue;
    }
    visited_streams[len_visited_streams++] = stream_id;

    if (unlikely(!get_stream_input(&g_stream_input, addr, &buf, &len))) {
      continue;     
    }
    if (buf == NULL || len==0){
      continue;
    }
    

    stage_max = 0;
    stage_cur = 0;
    orig_hit_cnt = queued_paths + unique_crashes;
    orig_execs = total_execs;

// chaged begin------------------------------   
    if (unlikely(!q->fti_info)) {
      q->fti_info = kh_init(PTR);
    }

    

    struct fti_taint* taint = NULL;
    khiter_t iter = kh_get(PTR, q->fti_info, stream_id);
    if( iter != kh_end(q->fti_info)) {
      if(kh_exist(q->fti_info, iter)) {
        taint = kh_value(q->fti_info, iter);
      }
    }else{
      int kh_res;
      taint = ck_alloc(sizeof(struct fti_taint));
      iter = kh_put(PTR, q->fti_info, stream_id, &kh_res);
      kh_value(q->fti_info, iter) = taint;
    }
    
    memset(&fti,0,len);
    
    if (taint) {
      // we don't care mask_num now
      
      if (taint->mask_buf) {
        taint->mask_buf = ck_realloc(taint->mask_buf, len);
        memcpy(&fti, taint->mask_buf, taint->mask_buf_len);
      }else{
        taint->mask_buf = ck_alloc(len);
      }
   
      taint->mask_buf_len = len;
      
    }
// changed end ------------------------------
    
    
    
    u64 tmpmask = 0;
    u8* tmpmask_buf = &tmpmask;
    memcpy(orig_buf, buf, len);
    for (int i=0;i<size;i++){
      memcpy(buf, orig_buf, len);
      for(int j=i;j<len;j+=size){  
        buf[j] ^= 0xff;
        //buf[j] = random() % 256;  
      }

      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
      if (unlikely(get_exec_checksum(file_buf, file_len, &newcksum))) {
        continue;
      }

      if(newcksum != cksum) {
        tmpmask_buf[i]=0xff;
      }else {
        for (int w = 0; w < CMP_MAP_W; ++w) {
          if (cmplog_backup.headers[w].hits != cmplog_ptr->headers[w].hits) { 
            tmpmask_buf[i]=0xff;
            break;
          }else{
            loggeds = MIN(cmplog_backup.headers[w].hits,CMP_MAP_H);
            u32 shape = SHAPE_BYTES(cmplog_backup.headers[w].shape);
            for(int h=0;h<loggeds;h++){
              u64 o_v0 = cmplog_backup.log[w][h].v0;
              u64 o_v1 = cmplog_backup.log[w][h].v1;
              u64 v0 = cmplog_ptr->log[w][h].v0;
              u64 v1 = cmplog_ptr->log[w][h].v1;

              if(o_v0 != v0 || o_v1 != v1){
                tmpmask_buf[i]=0xff;
              }
            }
            if (tmpmask_buf[i] == 0xff) {
              break;
            }       
          }
        }
      }
    }

    if(tmpmask==0){
#ifdef TAINT_DEBUG
      fprintf(stderr, "addr:%016lx taint full\n",addr);
#endif
      goto taint_end;
    }
    
    new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_FTI] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FTI] += total_execs - orig_execs;
    
    add_schedule_info(addr, new_hit_cnt - orig_hit_cnt, total_execs - orig_execs);

    memcpy(buf, orig_buf, len);
    
    for (int j=0;j<len;j++){
      stage_name = "fuzz-taint-inference";
      stage_short = "fti";
      orig_hit_cnt = queued_paths + unique_crashes;
      orig_execs = total_execs;
      if (tmpmask_buf[j%size]==0 || fti[j] == 1){
        continue;
      }
      u8 orig = buf[j];
      u8 changed;
      //buf[j] ^= 0xff;
      buf[j] = random() % 256;
      changed = buf[j];
      
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
      if (unlikely(get_exec_checksum(file_buf, file_len, &newcksum))) {
        continue;
      }

      buf[j] = orig;
      new_hit_cnt = queued_paths + unique_crashes;
      stage_finds[STAGE_FTI] += new_hit_cnt - orig_hit_cnt;
      stage_cycles[STAGE_FTI] += total_execs - orig_execs;
      add_schedule_info(addr, new_hit_cnt - orig_hit_cnt, total_execs - orig_execs);

      if(newcksum != cksum) {
        fti[j]=1;
        // hard? when block cov 
        continue;
      }
      
      for (int w = 0; w < CMP_MAP_W; ++w) {
        if (cmplog_backup.headers[w].hits != cmplog_ptr->headers[w].hits) { 
          fti[j]=1;
           
          if(cmplog_backup.headers[w].attribute == OP_ISUB) {
            loggeds = MIN(CMP_MAP_H,cmplog_backup.headers[w].hits);
            u32 shape = SHAPE_BYTES(cmplog_backup.headers[w].shape);
            for (int h=0; h<loggeds;h++){
            
              u64 o_v0 = cmplog_backup.log[w][h].v0;
              u64 o_v1 = cmplog_backup.log[w][h].v1;
              u64 v0 = cmplog_ptr->log[w][h].v0;
              u64 v1 = cmplog_ptr->log[w][h].v1;
              bool v0d = direct_copy(orig, o_v0, shape) && direct_copy(changed, v0, shape) ;
              bool v1d = direct_copy(orig, o_v1, shape) && direct_copy(changed, v1, shape) ;
              //(stderr,"hit not eq addr:%016lx size:%d key:%5d h:%2d o:%016lx %016lx c:%016lx %016lx v0d:%d v1d:%d\n",addr,size,w,h,o_v0, o_v1, v0, v1, v0d,v1d);
                
              //input_to_state_stream(addr, size, shape, w,  h, &fti, buf, len, j, o_v0, o_v1, v0, v1, cksum);
            }
          }
            
        }else{
          loggeds = MIN(cmplog_backup.headers[w].hits,CMP_MAP_H);
          u32 shape = SHAPE_BYTES(cmplog_backup.headers[w].shape);
          u64 s_v0, s_v1;
          u8  s_v0_fixed = loggeds, s_v1_fixed = loggeds;
          u8  s_v0_inc = loggeds, s_v1_inc = loggeds;
          u8  s_v0_dec = loggeds, s_v1_dec = loggeds;
          for(int h=0;h<loggeds;h++){
                u64 o_v0 = cmplog_backup.log[w][h].v0;
                u64 o_v1 = cmplog_backup.log[w][h].v1;
                u64 v0 = cmplog_ptr->log[w][h].v0;
                u64 v1 = cmplog_ptr->log[w][h].v1;
                
                /*if (h == 0) {

                  s_v0 = o_v0;
                  s_v1 = o_v1;

                } else {

                  if (s_v0 != o_v0) { s_v0_fixed -= 1; }
                  if (s_v1 != o_v1) { s_v1_fixed -= 1; }
                  if (s_v0 >= o_v0) { s_v0_inc -= 1; }
                  if (s_v1 >= o_v1) { s_v1_inc -= 1; }
                  if (s_v0 <= o_v0) { s_v0_dec -= 1; }
                  if (s_v1 <= o_v1) { s_v1_dec -= 1; }
                  s_v0 = o_v0;
                  s_v1 = o_v1;

                }*/
            if(cmplog_backup.log[w][h].v0 != cmplog_ptr->log[w][h].v0 || cmplog_backup.log[w][h].v1 != cmplog_ptr->log[w][h].v1){
              fti[j]=1;
              
              if (pass_stats[w].faileds >= CMPLOG_FAIL_MAX || pass_stats[w].total >= CMPLOG_FAIL_MAX) {
                continue;
              }
              bool v0d = direct_copy(orig, o_v0, shape) && direct_copy(changed, v0, shape) ;
              bool v1d = direct_copy(orig, o_v1, shape) && direct_copy(changed, v1, shape) ;


                
              if((cmplog_backup.headers[w].attribute & OP_TYPE_MASK) == OP_ISUB) {
                // input to state

            //fprintf(stderr,"addr:%016lx size:%d key:%5d h:%2d o:%016lx %016lx c:%016lx %016lx v0d:%d v1d:%d\n",addr,size,w,h,o_v0, o_v1, v0, v1, v0d,v1d);
                //input_to_state_stream(addr, size, shape, w,  h, &fti, buf, len, j, o_v0, o_v1, v0, v1, cksum);
              }
            }
          }
          /*if (loggeds/s_v0_fixed < 2) {s_v0_fixed = 1;}else{s_v0_fixed = 0;}
          if (loggeds/s_v1_fixed < 2) {s_v1_fixed = 1;}else{s_v1_fixed = 0;}
          if (loggeds/s_v0_inc < 2) {s_v0_inc = 1;}else{s_v0_inc = 0;}
          if (loggeds/s_v1_inc < 2) {s_v1_inc = 1;}else{s_v1_inc = 0;}
          if (loggeds/s_v0_dec < 2) {s_v0_dec = 1;}else{s_v0_dec = 0;}
          if (loggeds/s_v1_dec < 2) {s_v1_dec = 1;}else{s_v1_dec = 0;}
          if (loggeds>=5 && fti[j]) {
            fprintf(stderr,"s_v0_fixed:%d s_v1_fixed:%d s_v0_inc:%d s_v1_inc:%d s_v0_dec:%d s_v1_dec:%d \n",s_v0_fixed, s_v1_fixed, s_v0_inc, s_v1_inc, s_v0_dec, s_v1_dec);
          }*/
        
        }
          

      }
    }  
    



taint_end:

    if (unlikely(!q->fti_info)) {
      q->fti_info = kh_init(PTR);
    }

    //struct fti_taint* taint = NULL;
    //khiter_t iter = kh_get(PTR, q->fti_info, stream_id);
    iter = kh_get(PTR, q->fti_info, stream_id);
    if( iter != kh_end(q->fti_info)) {
      if(kh_exist(q->fti_info, iter)) {
        taint = kh_value(q->fti_info, iter);
      }
    }else{
      int kh_res;
      taint = ck_alloc(sizeof(struct fti_taint));
      iter = kh_put(PTR, q->fti_info, stream_id, &kh_res);
      kh_value(q->fti_info, iter) = taint;
    }
    
    if (taint) {
      taint->mask_num = tmpmask;
      /*if (tmpmask == 0) {
        if (taint->mask_buf) {
          free(taint->mask_buf);
          taint->mask_buf = NULL;
        }
        taint->mask_buf_len = 0;
      }else{
        if (taint->mask_buf) {
          taint->mask_buf = realloc(taint->mask_buf, len);
        }else{
          taint->mask_buf = malloc(len);
        }
        memcpy(taint->mask_buf, &fti, len);
        taint->mask_buf_len = len;
      }*/
      memcpy(taint->mask_buf, &fti, len);
      taint->mask_buf_len = len;
    }
    
#ifdef TAINT_DEBUG
    int s=-1;
    int e=0;
    for (;e<len;e++){
      if (fti[e]!=0){
        if(e-s-1)
          fprintf(stderr, "addr:%016lx idx:%d len:%d\n",addr,s+1,e-s-1);
        s=e;
      }
    }
    if(e-s-1)
      fprintf(stderr, "addr:%016lx idx:%d len:%d\n",addr,s+1,e-s-1);
#endif
    memcpy(buf, orig_buf, len);
    new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_FTI] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FTI] += total_execs - orig_execs;
    add_schedule_info(addr, new_hit_cnt - orig_hit_cnt, total_execs - orig_execs);

  }

  ck_free(orig_buf); 
  return 0;
}
#endif
// the taint show compressed buf.
#if 0
static u8 colorization(struct queue_entry* q, u64 addr, u64 mask_num, u32 size, u8* mask_buf, u32 mask_buf_len, struct tainted **taints, struct I2S_CK* cur_i2s) {

  u8* out_buf;
  u32 out_len;

  if (unlikely(!get_stream_input(&g_stream_input, addr, &out_buf, &out_len))) {
    return 1;     
  }
  
  u32 tmp_out_buf_len;
  u8* tmp_out_buf;

  u32 backup_len;
  u8* backup;
 
  if (!compress_buf(mask_num, size, mask_buf, mask_buf_len, out_buf, out_len, &backup, &backup_len)) {
    return 1;
  }
    
  if (backup_len == 0) {
    return 1;
  }
  
    
  u32 len = backup_len;
  u8* buf = ck_alloc_nozero(len);
  
  memcpy(buf, backup, len);
  
  struct I2S_CK* I2S = cur_i2s;

  u8* sort_map = ck_alloc_nozero(len);
  memset(sort_map, 0, len);
  
  u32 idx;
  u32 tlen;
  

  while (I2S) {
    idx = I2S->idx;
    tlen = I2S->t_op.shape;
//#ifdef _DEBUG
    fprintf(stderr,"color I2S: idx:%d len:%d ",idx,tlen);
//#endif

    for (int i=idx;i<idx+tlen;i++){
      if (fix_checksum_mode)
        sort_map[i] = 1;
    }
    I2S = I2S->next;
  }
  
  struct range *  ranges = NULL, *rng;
  
  u32 start = -1;
  for (int i=0; i<len; i++){
    if (sort_map[i] == 0) continue;

    if (start != i-1){
      ranges = add_range(ranges, start + 1, i-1);
//#ifdef _DEBUG
      fprintf(stderr,"range start:%d end:%d \n",start + 1,i-1);
//#endif
    }
    start = i;
  }

  if (start != len-1){
    ranges = add_range(ranges, start+1, len-1);
//#ifdef _DEBUG
    fprintf(stderr,"range start:%d end:%d \n",start + 1,len-1);
//#endif
  }
  
  ck_free(sort_map);

  //struct range *  ranges = add_range(NULL, 0, len - 1), *rng;
  struct tainted *taint = NULL;
  u8 *            changed = ck_alloc_nozero(len);
  u8* file_buf;
  u32 file_len;

  

  u64 orig_hit_cnt, new_hit_cnt;
  orig_hit_cnt = queued_paths + unique_crashes;
  u32 exec_cksum, cksum;


  stage_name = "colorization";
  stage_short = "colorization";
  stage_max = (len << 1);
  stage_cur = 0;

  // in colorization we do not classify counts, hence we have to calculate
  // the original checksum.
  if (fix_checksum_mode)
      fix_checksum(q, addr, mask_num, size, mask_buf, mask_buf_len, buf, len, cur_i2s);
  
  if (!decompress_buf(mask_num, size, mask_buf, mask_buf_len, buf, len, &tmp_out_buf, &tmp_out_buf_len)) {
      goto checksum_fail;
  }
  set_stream_input(&g_stream_input, addr, tmp_out_buf, tmp_out_buf_len);

  get_streams_input_file(&g_stream_input, &file_buf, &file_len);
  if (unlikely(get_exec_checksum(file_buf, file_len, &exec_cksum))) {
    goto checksum_fail;
  }


  memcpy(changed, buf, len);
  random_replace(changed, len);

  while ((rng = pop_biggest_range(&ranges)) != NULL &&
         stage_cur < stage_max) {

    u32 s = 1 + rng->end - rng->start;
    memcpy(buf + rng->start, changed + rng->start, s);

    u64 start_us = get_cur_time_us();
    
    if (fix_checksum_mode)
      fix_checksum(q, addr, mask_num, size, mask_buf, mask_buf_len, buf, len, cur_i2s);

    if (!decompress_buf(mask_num, size, mask_buf, mask_buf_len, buf, len, &tmp_out_buf, &tmp_out_buf_len)) {
      goto checksum_fail;
    }
    set_stream_input(&g_stream_input, addr, tmp_out_buf, tmp_out_buf_len);

    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    if (unlikely(get_exec_checksum(file_buf, file_len,  &cksum))) {
      goto checksum_fail;
    }

    u64 stop_us = get_cur_time_us();

    /* Discard if the mutations change the path or if it is too decremental
      in speed - how could the same path have a much different speed
      though ...*/

    if (cksum != exec_cksum ||
        (unlikely(stop_us - start_us > 15 * queue_cur->exec_us))) {

      memcpy(buf + rng->start, backup + rng->start, s);

      if (s > 1) {  // to not add 0 size ranges

        ranges = add_range(ranges, rng->start, rng->start - 1 + s / 2);
        ranges = add_range(ranges, rng->start + s / 2, rng->end);

      }

      if (ranges == rng) {

        ranges = rng->next;
        if (ranges) { ranges->prev = NULL; }

      } else if (rng->next) {

        rng->prev->next = rng->next;
        rng->next->prev = rng->prev;

      } else {

        if (rng->prev) { rng->prev->next = NULL; }

      }

      ck_free(rng);

    } else {      
      rng->ok = 1;
    }

    if (++stage_cur % stats_update_freq == 0) { show_stats(); };

  }

  rng = ranges;
  while (rng) {

    rng = rng->next;

  }

  u32 i = 1;
  u32 positions = 0;
  while (i) {

  restart:
    i = 0;
    struct range *r = NULL;
    u32           pos = (u32)-1;
    rng = ranges;

    while (rng) {

      if (rng->ok == 1 && rng->start < pos) {

        if (taint && taint->pos + taint->len == rng->start) {

          taint->len += (1 + rng->end - rng->start);
          positions += (1 + rng->end - rng->start);
          rng->ok = 2;
          goto restart;

        } else {

          r = rng;
          pos = rng->start;

        }

      }

      rng = rng->next;

    }

    if (r) {

      struct tainted *t = ck_alloc_nozero(sizeof(struct tainted));
      t->pos = r->start;
      t->len = 1 + r->end - r->start;
      positions += (1 + r->end - r->start);
      if (likely(taint)) { taint->prev = t; }
      t->next = taint;
      t->prev = NULL;
      taint = t;
      r->ok = 2;
      i = 1;

    }

  }

  /* temporary: clean ranges */
  while (ranges) {

    rng = ranges;
    ranges = rng->next;
    ck_free(rng);
    rng = NULL;

  }

  new_hit_cnt = queued_paths + unique_crashes;



  if (taint) {

      *taints = taint;
      ++colorize_success;

  }

  stage_finds[STAGE_COLORIZATION] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_COLORIZATION] += stage_cur;

  ck_free(buf);
  ck_free(changed);
  set_stream_input(&g_stream_input, addr, out_buf, out_len);

  return 0;

checksum_fail:
  while (ranges) {

    rng = ranges;
    ranges = rng->next;
    ck_free(rng);
    rng = NULL;

  }
  
  ck_free(buf);
  ck_free(changed);
  set_stream_input(&g_stream_input, addr, out_buf, out_len);

  return 1;

}

static u8 insert_I2S(struct queue_entry* q, u64 addr, struct I2S_CK* new){
  // may overwrite by new


  struct fti_taint* ftaint = NULL;
  struct mmio* mmio = get_mmio_by_addr(&g_stream_input, addr);
  if (q->fti_info){
    khiter_t iter = kh_get(PTR, q->fti_info, mmio->stream_id);
    if( iter != kh_end(q->fti_info)) {
      if(kh_exist(q->fti_info, iter)) {
        ftaint = kh_value(q->fti_info, iter);
      }
    }
  }
    
  if (!ftaint) {
    return 1;
  }

  struct I2S_CK* tmp = ftaint->I2S;
  while (tmp) {
	  if (tmp->idx == new->idx) {
	    tmp->key = new->key;
	    tmp->hits = new->hits;
	    tmp->is_v0 = new->is_v0;
	    tmp->t_op = new->t_op;
	    ck_free(new);
	    return 1;
	  }
	  if(tmp->key == new->key){
      ck_free(new);
	    return 2;
	  }
	  tmp = tmp->next;
  }
  
  new->prev = NULL;
  new->next = ftaint->I2S;
  if (ftaint->I2S) {
	  ftaint->I2S->prev = new;
  }
  ftaint->I2S = new;

  return 0;
}


static u8 cmp_fuzz_stuff(struct queue_entry* q, u64 addr, u64 mask_num, u32 size, u8* mask_buf, u32 mask_buf_len, u8* color_buf, u32 buf_len,
       u32 taint_len, u32 key, u32 idx, u32 hits, u32 is_v0, u64 value, u32 cksum, struct transform_operands t_op, struct I2S_CK* old_i2s, u8* ret_status){
  
  u8* file_buf;
  u32 file_len;
  u8* out_buf;
  u32 out_len;
  u32 tmp_out_buf_len;
  u8* tmp_out_buf;

  
  if (unlikely(!get_stream_input(&g_stream_input, addr, &out_buf, &out_len))) {
    return 1;     
  }


  struct I2S_CK* I2S;
  u8 status = 0;

  if (get_encoding_buf2(color_buf, idx, value, buf_len, taint_len, &t_op) == 0) {
    if (fix_checksum_mode)
      fix_checksum(q, addr, mask_num, size, mask_buf, mask_buf_len, color_buf, buf_len, old_i2s);
    
    
    if (!decompress_buf(mask_num, size, mask_buf, mask_buf_len, color_buf, buf_len, &tmp_out_buf, &tmp_out_buf_len)) {
      return 1;
    }
    set_stream_input(&g_stream_input, addr, tmp_out_buf, tmp_out_buf_len);
    
    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    if (unlikely(its_fuzz(file_buf, file_len, &status, cksum))){
      *ret_status = status;
      set_stream_input(&g_stream_input, addr, out_buf, out_len);
     
      return 1;
	  };
#ifdef _DEBUG
	  fprintf(stderr,"status:%d idx:%d value %d\n",status, idx, value);
#endif
   
	  if (status == 1 || status == 3){
			u64 o_v0 = cmplog_backup.log[key][hits%CMP_MAP_H].v0;
      u64 o_v1 = cmplog_backup.log[key][hits%CMP_MAP_H].v1;
      u64 v0 = cmplog_backup2.log[key][hits%CMP_MAP_H].v0;
      u64 v1 = cmplog_backup2.log[key][hits%CMP_MAP_H].v1;
	    if (o_v0 != v0 && o_v1 != v1) {
	  	  I2S = ck_alloc_nozero(sizeof(struct I2S_CK));
	  	  I2S->key = key;
	    	I2S->idx = idx;
	    	I2S->hits = hits;
        I2S->is_v0 = is_v0;
	    	I2S->t_op = t_op;
#ifdef _DEBUG
        fprintf(stderr,"addr:%016lx status:%d idx:%d value %d\n",addr, status, idx, value);
#endif
	      insert_I2S(q, addr, I2S);
	    }
		// save with same I2S with modified buf
      struct fti_taint* ftaint = NULL;
      struct mmio* mmio = get_mmio_by_addr(&g_stream_input, addr);
      if (q->fti_info){
        khiter_t iter = kh_get(PTR, q->fti_info, mmio->stream_id);
        if( iter != kh_end(q->fti_info)) {
          if(kh_exist(q->fti_info, iter)) {
            ftaint = kh_value(q->fti_info, iter);
          }
        }
      }
    
      if (ftaint) {
        save_with_I2S(file_buf, file_len, addr, ftaint->I2S, status, cksum);
      }

	  	
	  
	  //break;
	  }
  }
  *ret_status = status;
  set_stream_input(&g_stream_input, addr, out_buf, out_len);
  return 0;
}

#endif

static u8 cmp_fuzz(struct queue_entry* q, u64 addr, u64 mask_num, u32 size, u8* mask_buf, u32 mask_buf_len, 
        u32 key, u8* orig_buf, u8* color_buf, u32 buf_len, struct tainted *taint, u32 cksum, struct I2S_CK* old_I2S) {

  u32 tmp_out_buf_len;
  u8* tmp_out_buf;

  u32 backup_len = buf_len;
  u8* backup = ck_alloc_nozero(backup_len);
  memcpy(backup, color_buf, buf_len);

  struct transform_operands t_op;
  struct tainted *   t;
  u32                i, j, idx, taint_len, loggeds;
  u32                have_taint = 1;
  u8                 status = 0, found_one = 0, is_vaild = 0;
  struct I2S_CK* I2S = old_I2S;
  
  
  loggeds = MIN(cmplog_backup.headers[key].hits, cmplog_backup2.headers[key].hits);
  loggeds = MIN(loggeds, CMP_MAP_H);

  u32 shape = SHAPE_BYTES(cmplog_backup.headers[key].shape);  

  u64 s_v0, s_v1;
  u8  s_v0_fixed = 1, s_v1_fixed = 1;
  u8  s_v0_inc = 1, s_v1_inc = 1;
  u8  s_v0_dec = 1, s_v1_dec = 1;

  stage_max += loggeds;
  for (i = 0; i < loggeds; ++i) {

    u64 o_v0 = cmplog_backup.log[key][i].v0;
    u64 o_v1 = cmplog_backup.log[key][i].v1;
    u64 v0 = cmplog_backup2.log[key][i].v0;
    u64 v1 = cmplog_backup2.log[key][i].v1;

    // loop detection code
    if (i == 0) {

      s_v0 = o_v0;
      s_v1 = o_v1;

    } else {

      if (s_v0 != o_v0) { s_v0_fixed = 0; }
      if (s_v1 != o_v1) { s_v1_fixed = 0; }
      if (s_v0 >= o_v0) { s_v0_inc = 0; }
      if (s_v1 >= o_v1) { s_v1_inc = 0; }
      if (s_v0 <= o_v0) { s_v0_dec = 0; }
      if (s_v1 <= o_v1) { s_v1_dec = 0; }
      s_v0 = o_v0;
      s_v1 = o_v1;

    }

   
    // opt not in the paper
    for (j = 0; j < i; ++j) {

      if (cmplog_backup.log[key][j].v0 == o_v0 &&
          cmplog_backup.log[key][j].v1 == o_v1) {

        goto cmp_fuzz_next_iter;

      }

    }

    t = taint;
    while (t->next) {

      t = t->next;

    }

    for (idx = 0; idx < buf_len; ++idx) {

      if (have_taint) {

        if (!t || idx < t->pos) {

          continue;

        } else {

          taint_len = t->pos + t->len - idx;

          if (idx == t->pos + t->len - 1) { t = t->prev; }

        }

      } else {

        taint_len = buf_len - idx;

      }

      status = 0;
      
      bool v0d = direct_copy(orig_buf[idx], o_v0, shape) && direct_copy(color_buf[idx], v0, shape);
      bool v1d = direct_copy(orig_buf[idx], o_v1, shape) && direct_copy(color_buf[idx], v1, shape);

#ifdef _DEBUG
            fprintf(stderr, "Handling: key:%d hits:%d %llx->%llx vs %llx->%llx idx=%u shape=%u %02x %02x\n",
            key, i, o_v0, v0, o_v1, v1, idx, shape,orig_buf[idx], color_buf[idx]);
#endif
      
      if ((o_v0 != v0 ) &&  v0d && v0 != v1) {
        is_vaild = 1;

        t_op.shape = 1;
        t_op.reverse = 1;
		    memcpy(color_buf, backup, buf_len);

		    if (cmp_fuzz_stuff(q, addr, mask_num, size, mask_buf, mask_buf_len, color_buf, buf_len, taint_len, key, idx, i, 0, v1, cksum, t_op, I2S, &status)){
          goto exec_faild;
		    }
      
        if (status == 1) {
          found_one = 1;
          break;
        }
        
        if (shape >=2) {
          t_op.shape = 2;
          t_op.reverse = 1;
		      memcpy(color_buf, backup, buf_len);
		
		      if (unlikely(cmp_fuzz_stuff(q, addr, mask_num, size, mask_buf, mask_buf_len, color_buf, buf_len, taint_len, key, idx, i, 0, v1, cksum, t_op, I2S, &status))){
		        goto exec_faild;
		      }
          if (status == 1 ) {
            found_one = 1;
            break;
          }

          t_op.shape = 2;
          t_op.reverse = 0;
		      memcpy(color_buf, backup, buf_len);
		
		      if (unlikely(cmp_fuzz_stuff(q, addr, mask_num, size, mask_buf, mask_buf_len, color_buf, buf_len, taint_len, key, idx, i, 0, v1, cksum, t_op, I2S, &status))){
		        goto exec_faild;
		      }
          if (status == 1) {
            found_one = 1;
            break;
          }
        }

        if (shape >=4) {
          t_op.shape = 4;
          t_op.reverse = 1;
		      memcpy(color_buf, backup, buf_len);
		
		      if (unlikely(cmp_fuzz_stuff(q, addr, mask_num, size, mask_buf, mask_buf_len, color_buf, buf_len, taint_len, key, idx, i, 0, v1, cksum, t_op, I2S, &status))){
		        goto exec_faild;
		      }
          if (status == 1 ) {
            found_one = 1;
            break;
          }

          t_op.shape = 4;
          t_op.reverse = 0;
		      memcpy(color_buf, backup, buf_len);
		
		      if (unlikely(cmp_fuzz_stuff(q, addr, mask_num, size, mask_buf, mask_buf_len, color_buf, buf_len, taint_len, key, idx, i, 0, v1, cksum, t_op, I2S, &status))){
		        goto exec_faild;
		      }
          if (status == 1 ) {
            found_one = 1;
            break;
          }
        }

        if (shape >=8) {
          t_op.shape = 8;
          t_op.reverse = 1;
		      memcpy(color_buf, backup, buf_len);
		
		      if (unlikely(cmp_fuzz_stuff(q, addr, mask_num, size, mask_buf, mask_buf_len, color_buf, buf_len, taint_len, key, idx, i, 0, v1, cksum, t_op, I2S, &status))){
		        goto exec_faild;
		      }
          if (status == 1 ) {
            found_one = 1;
            break;
          }

          t_op.shape = 8;
          t_op.reverse = 0;
		      memcpy(color_buf, backup, buf_len);
		
		      if (unlikely(cmp_fuzz_stuff(q, addr, mask_num, size, mask_buf, mask_buf_len, color_buf, buf_len, taint_len, key, idx, i, 0, v1, cksum, t_op, I2S, &status))){
		        goto exec_faild;
		      }
          if (status == 1 ) {
            found_one = 1;
            break;
          }
        }
#ifdef _DEBUG        
        fprintf(stderr,"addr:%016lx idx:%d\n",addr,idx);
#endif
      };

      if ((o_v1 != v1 ) &&  v1d && v0 != v1) {
        is_vaild = 1;

        t_op.shape = 1;
        t_op.reverse = 1;
		    memcpy(color_buf, backup, buf_len);
		
		    if (unlikely(cmp_fuzz_stuff(q, addr, mask_num, size, mask_buf, mask_buf_len, color_buf, buf_len, taint_len, key, idx, i, 1, v0, cksum, t_op, I2S, &status))){
		      goto exec_faild;
		    }
        if (status == 1 ) {
          found_one = 1;
          break;
        }
        
        if (shape >=2) {
          
          t_op.shape = 2;
          t_op.reverse = 1;
		      memcpy(color_buf, backup, buf_len);
		
		      if (unlikely(cmp_fuzz_stuff(q, addr, mask_num, size, mask_buf, mask_buf_len, color_buf, buf_len, taint_len, key, idx, i, 1, v0, cksum, t_op, I2S, &status))){
		        goto exec_faild;
		      }
          if (status == 1 ) {
            found_one = 1;
            break;
          }

          t_op.shape = 2;
          t_op.reverse = 0;
		      memcpy(color_buf, backup, buf_len);
		
		      if (unlikely(cmp_fuzz_stuff(q, addr, mask_num, size, mask_buf, mask_buf_len, color_buf, buf_len, taint_len, key, idx, i, 1, v0, cksum, t_op, I2S, &status))){
		        goto exec_faild;
		      }
          if (status == 1 ) {
            found_one = 1;
            break;
          }
        }

        if (shape >=4) {
          t_op.shape = 4;
          t_op.reverse = 1;
		      memcpy(color_buf, backup, buf_len);
		
		      if (unlikely(cmp_fuzz_stuff(q, addr, mask_num, size, mask_buf, mask_buf_len, color_buf, buf_len, taint_len, key, idx, i, 1, v0, cksum, t_op, I2S, &status))){
		        goto exec_faild;
		      }
          if (status == 1 ) {
            found_one = 1;
            break;
          }

          t_op.shape = 4;
          t_op.reverse = 0;
		      memcpy(color_buf, backup, buf_len);
		
		      if (unlikely(cmp_fuzz_stuff(q, addr, mask_num, size, mask_buf, mask_buf_len, color_buf, buf_len, taint_len, key, idx, i, 1, v0, cksum, t_op, I2S, &status))){
		        goto exec_faild;
		      }
          if (status == 1 ) {
            found_one = 1;
            break;
          }
        }

        if (shape >=8) {
          t_op.shape = 8;
          t_op.reverse = 1;
		      memcpy(color_buf, backup, buf_len);
		
		      if (unlikely(cmp_fuzz_stuff(q, addr, mask_num, size, mask_buf, mask_buf_len, color_buf, buf_len, taint_len, key, idx, i, 1, v0, cksum, t_op, I2S, &status))){
		        goto exec_faild;
		      }
          if (status == 1 ) {
            found_one = 1;
            break;
          }

          t_op.shape = 8;
          t_op.reverse = 0;
		      memcpy(color_buf, backup, buf_len);
		
		      if (unlikely(cmp_fuzz_stuff(q, addr, mask_num, size, mask_buf, mask_buf_len, color_buf, buf_len, taint_len, key, idx, i, 1, v0, cksum, t_op, I2S, &status))){
		        goto exec_faild;
		      }
          if (status == 1 ) {
            found_one = 1;
            break;
          }
        }
#ifdef _DEBUG
        fprintf(stderr,"addr:%016lx idx:%d\n",addr,idx);
#endif
      };


    }
cmp_fuzz_next_iter:
    stage_cur++;
  }
  if (is_vaild) {
    if (!found_one && pass_stats[key].faileds < 0xff) {

      pass_stats[key].faileds++;

    }

    if (pass_stats[key].total < 0xff) { pass_stats[key].total++; }
  }

  ck_free(backup);
  return 0;

exec_faild:
  ck_free(backup);
	return 1; 

}
#if 0
static u8 input_to_state_stage_stream(struct queue_entry* q, u8* in_buf, u32 in_len) {

  u32 len, i, j;
  u8* file_buf;
  u32 file_len;
  u8  *out_buf = 0;
  u32 cksum, newcksum;

  static u32 visited_streams[MAX_STREAM_SIZE];
  u32 len_visited_streams = 0;


  init_streams_input(&g_stream_input, in_buf, q->len, 0);


  khash_t(PTR) * kh_mmios = get_mmios(&g_stream_input);
  
  khiter_t k;
  for (k = kh_begin(kh_mmios); k != kh_end(kh_mmios); ++k) {
    struct mmio* mmio = NULL;
    if (kh_exist(kh_mmios, k)) {
      mmio = kh_value(kh_mmios, k);
    }
    if (!mmio || mmio->valid == false){
      continue;
    }
    u64 addr = mmio->mmio_addr;
    u16 size = mmio->size;
    u32 stream_id = mmio->stream_id;

    if (is_visited(visited_streams, len_visited_streams, stream_id)) {
      continue;
    }
    visited_streams[len_visited_streams++] = stream_id;

    if (unlikely(!get_stream_input(&g_stream_input, addr, &out_buf, &len))) {
      continue;     
    }
    if (out_buf == NULL || len==0){
      continue;
    }

    u64 mask_num = 0xffffffffffffffff;
    u32 mask_buf_len = 0;
    u8* mask_buf = NULL;
    u8* mask_num_buf = &mask_num;
    struct fti_taint* ftaint = NULL;
    if (q->fti_info){
      khiter_t iter = kh_get(PTR, q->fti_info, stream_id);
      if( iter != kh_end(q->fti_info)) {
        if(kh_exist(q->fti_info, iter)) {
          ftaint = kh_value(q->fti_info, iter);
          if (ftaint) {
            mask_num = ftaint->mask_num;
            mask_buf = ftaint->mask_buf;
            mask_buf_len = ftaint->mask_buf_len;
          }
        }
      }
      if (mask_num == 0) {
        continue;
      }
    }else{
      continue;
    }
    
    if (!ftaint) {
      continue;
    }


    
    struct tainted *taint = NULL;

    if (ftaint->colorized >= CMPLOG_LVL_MAX) {
      continue;
    }

	  if (ftaint->I2S || !ftaint->taint) {
#ifdef _DEBUG
      if (ftaint->I2S) {
        fprintf(stderr, "oooolk:%016lx\n find i2s\n",addr);
      }
#endif

      if (unlikely(colorization(q, addr, mask_num, size, mask_buf, mask_buf_len, &taint, ftaint->I2S))) { continue; }

      // no taint? still try, create a dummy to prevent again colorization
      if (!taint) {
#ifdef _DEBUG
        fprintf(stderr, "ADDR: %016lx TAINT FAILED\n",addr);
#endif
        ftaint->colorized++;
	      //ck_free(fix_orig_buf);
        continue;

      }
#ifdef _DEBUG
      else if (taint->pos == 0 && taint->len == len) {
        fprintf(stderr, "TAINT FULL\n");
      }
#endif
    } else {

      taint = ftaint->taint;

    }

    u32 tmp_out_buf_len;
    u8* tmp_out_buf;

    u32 backup_masked_buf_len;
    u8* backup_masked_buf;
 
    if (!compress_buf(mask_num, size, mask_buf, mask_buf_len, out_buf, len, &backup_masked_buf, &backup_masked_buf_len)) {
      continue;
    }
    
    if (backup_masked_buf_len == 0) {
      continue;
    }
    
    u32 masked_buf_len = backup_masked_buf_len;
    u8* masked_buf = ck_alloc_nozero(masked_buf_len);

    memcpy(masked_buf, backup_masked_buf, masked_buf_len);
    
    struct tainted *t = taint;
    while (t) {
      u32 idx = t->pos;
      u32 t_len = t->len;
      
//#ifdef _DEBUG
      fprintf(stderr, "ADDR: %016lx T: idx=%u len=%u\n", addr, t->pos, t->len);
//#endif
      if (idx + t_len <= masked_buf_len)
        random_replace(masked_buf + idx, t_len);
      t = t->next;

    }
    
#ifdef _DEBUG
    fprintf(stderr,"\n");
    dump("origb",backup_masked_buf, backup_masked_buf_len);
    fprintf(stderr,"\n");
    dump("color",masked_buf, masked_buf_len);
#endif

    u64 orig_hit_cnt, new_hit_cnt;
    u64 orig_execs = total_execs;
    orig_hit_cnt = queued_paths + unique_crashes;

    stage_name = "input-to-state";
    stage_short = "its";
    stage_max = 0;
    stage_cur = 0;

    if (fix_checksum_mode)
      fix_checksum(q, addr, mask_num, size, mask_buf, mask_buf_len, backup_masked_buf, backup_masked_buf_len, ftaint->I2S);

    if (!decompress_buf(mask_num, size, mask_buf, mask_buf_len, backup_masked_buf, backup_masked_buf_len, &tmp_out_buf, &tmp_out_buf_len)) {
      goto exit_its;
    }

    set_stream_input(&g_stream_input, addr, tmp_out_buf, tmp_out_buf_len);
    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    if (get_exec_checksum(file_buf, file_len, &cksum)) return -1;

    memcpy(&cmplog_backup, cmplog_ptr, sizeof(struct cmp_map));
    
    if (fix_checksum_mode)
      fix_checksum(q, addr, mask_num, size, mask_buf, mask_buf_len, masked_buf, masked_buf_len, ftaint->I2S);
    if (!decompress_buf(mask_num, size, mask_buf, mask_buf_len, masked_buf, masked_buf_len, &tmp_out_buf, &tmp_out_buf_len)) {
      goto exit_its;
    }

    set_stream_input(&g_stream_input, addr, tmp_out_buf, tmp_out_buf_len);

    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    if (unlikely(get_exec_checksum(file_buf, file_len,  &newcksum))) {
      goto exit_its;
    }
    
    orig_execs = total_execs;
    orig_hit_cnt = queued_paths + unique_crashes;


    memcpy(&cmplog_backup2, cmplog_ptr, sizeof(struct cmp_map));
    
    if (newcksum != cksum) {
      fprintf(stderr,"cknum not eq!\n");
      goto exit_its;
    }

    
    for (int w = 0; w < CMP_MAP_W; ++w) {

      if (pass_stats[w].faileds >= CMPLOG_FAIL_MAX || pass_stats[w].total >= CMPLOG_FAIL_MAX) {
        continue;
      }
      


      if (!cmplog_backup.headers[w].hits || !cmplog_backup2.headers[w].hits) { 
        continue;
      } 

      if((cmplog_backup.headers[w].attribute & OP_TYPE_MASK) == OP_ISUB) {
        if(unlikely(cmp_fuzz(q, addr, mask_num, size, mask_buf, mask_buf_len, w, backup_masked_buf, masked_buf, backup_masked_buf_len, taint, cksum, ftaint->I2S))){
          goto exit_its;
        }
      }
    }

 

exit_its:

  


    if (!ftaint->taint) { 
      ftaint->taint = taint; 
    }else if(ftaint->I2S){
      while (taint) {

        t = taint->next;
        ck_free(taint);
        taint = t;

      }
    }

  



    new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_ITS] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_ITS] += total_execs - orig_execs;
  
    ck_free(masked_buf);
    set_stream_input(&g_stream_input, addr, out_buf, len);
  }
  
  return 0;
}
#endif

static u8 havoc_stream(struct queue_entry* q, u8* in_buf, u32 in_len){
  u32 len, i, j;
  u8* file_buf;
  u32 file_len;
  u64 orig_hit_cnt, new_hit_cnt;
  u8  *out_buf = 0;

  u32 perf_score = 100;
  u32 orig_perf = 100;

  static u64 all_mmios[MAX_STREAM_SIZE];
  u32 len_all_mmios = 0;

  init_streams_input(&g_stream_input, in_buf, q->len, 0);
  
  khash_t(PTR) * kh_mmios = get_mmios(&g_stream_input);
  
  khiter_t k;
  for (k = kh_begin(kh_mmios); k != kh_end(kh_mmios); ++k){
    struct mmio* mmio = NULL;
    if (kh_exist(kh_mmios, k)) {
      mmio = kh_value(kh_mmios, k);
    }
    if (!mmio || mmio->valid == false){
      continue;
    }
    u64 addr = mmio->mmio_addr;
    // may skip base on addr?
    u16 size = mmio->size;
    u32 stream_id = mmio->stream_id;

    //if (value_set_model_size > 0 && is_value_set_model(addr>>32, addr & 0xffffffff)) {
    //  continue;
    //}
    
    if (passthrough_model_size > 0 && is_passthrough_model(addr>>32, addr & 0xffffffff)) {
      continue;
    }
    
    if (constant_model_size >0 && is_constant_model(addr>>32, addr & 0xffffffff)) {
      continue;
    }

    //struct bitextract_mmio_model_config* model_config = is_bitextract_model(addr>>32, addr & 0xffffffff);
    
    
    //if (model_config && model_config->mask_hamming_weight < 5){
    //  continue;
    //}
    

    if (unlikely(!get_stream_input(&g_stream_input, addr, &out_buf, &len))) {
      continue;     
    }
    if (out_buf == NULL || len==0){
      continue;
    }
    
    all_mmios[len_all_mmios++] = addr;
  }
    
  if (len_all_mmios==0){
    return 0;
  }
  u64 addr = schedule(all_mmios, len_all_mmios);
    
  struct mmio* mmio = get_mmio_by_addr(&g_stream_input,addr);
  if (mmio==NULL){
    return 0;
  }
  
  u16 size = mmio->size;
  u32 stream_id = mmio->stream_id;
  if (unlikely(!get_stream_input(&g_stream_input, addr, &out_buf, &len))) {
    return 0;     
  }
    
  if (out_buf == NULL || len==0){
    return 0;
  }

    
  stage_cur_byte = -1;

  orig_perf = perf_score = calculate_score(queue_cur);

  u64 havoc_queued;
    
  stage_name  = "havoc";
  stage_short = "havoc";
  stage_max   = HAVOC_CYCLES * perf_score / havoc_div / 100;


  if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;


  u32 tmp_out_buf_len;
  u8* tmp_out_buf;

    
  u32 masked_buf_len = len;
  u8* masked_buf = ck_alloc_nozero(masked_buf_len);
    
  memcpy(masked_buf, out_buf, masked_buf_len);

    
  orig_hit_cnt = queued_paths + unique_crashes;
  havoc_queued = queued_paths;

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */

    
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

    stage_cur_val = use_stacking;
 
    for (i = 0; i < use_stacking; i++) {

      switch (UR(16 + ((extras_cnt + a_extras_cnt) ? 2 : 0))) {

        case 0:

          /* Flip a single bit somewhere. Spooky! */
        
          FLIP_BIT(masked_buf, UR(masked_buf_len << 3));
          break;

        case 1: 

          /* Set byte to interesting value. */

          masked_buf[UR(masked_buf_len)] = interesting_8[UR(sizeof(interesting_8))];
          break;

        case 2:

          /* Set word to interesting value, randomly choosing endian. */
          
          if (masked_buf_len < 2) break;

          if (UR(2)) {

            *(u16*)(masked_buf + UR(masked_buf_len - 1)) =
              interesting_16[UR(sizeof(interesting_16) >> 1)];

          } else {

            *(u16*)(masked_buf + UR(masked_buf_len - 1)) = SWAP16(
              interesting_16[UR(sizeof(interesting_16) >> 1)]);

          }

          break;

        case 3:
            
          /* Set dword to interesting value, randomly choosing endian. */

          if (masked_buf_len < 4) break;

          if (UR(2)) {
  
            *(u32*)(masked_buf + UR(masked_buf_len - 3)) =
              interesting_32[UR(sizeof(interesting_32) >> 2)];

          } else {

            *(u32*)(masked_buf + UR(masked_buf_len - 3)) = SWAP32(
              interesting_32[UR(sizeof(interesting_32) >> 2)]);

          }

          break;

        case 4:

          /* Randomly subtract from byte. */

          masked_buf[UR(masked_buf_len)] -= 1 + UR(ARITH_MAX);
          break;

        case 5:

          /* Randomly add to byte. */

          masked_buf[UR(masked_buf_len)] += 1 + UR(ARITH_MAX);
          break;

        case 6:

          /* Randomly subtract from word, random endian. */

          if (masked_buf_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(masked_buf_len - 1);

            *(u16*)(masked_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(masked_buf_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(masked_buf + pos) =
              SWAP16(SWAP16(*(u16*)(masked_buf + pos)) - num);

          }

          break;

        case 7:

          /* Randomly add to word, random endian. */

          if (masked_buf_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(masked_buf_len - 1);

            *(u16*)(masked_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(masked_buf_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(masked_buf + pos) =
              SWAP16(SWAP16(*(u16*)(masked_buf + pos)) + num);
 
          }

          break;

        case 8:

          /* Randomly subtract from dword, random endian. */

          if (masked_buf_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(masked_buf_len - 3);

            *(u32*)(masked_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(masked_buf_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(masked_buf + pos) =
              SWAP32(SWAP32(*(u32*)(masked_buf + pos)) - num);

          }

          break;

        case 9:
 
          /* Randomly add to dword, random endian. */
          if (masked_buf_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(masked_buf_len - 3);

            *(u32*)(masked_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(masked_buf_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(masked_buf + pos) =
              SWAP32(SWAP32(*(u32*)(masked_buf + pos)) + num);

          }

          break;

        case 10:

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          masked_buf[UR(masked_buf_len)] ^= 1 + UR(255);
          break;

        case 11 ... 12: {

           /* Delete bytes. We're making this a bit more likely
              than insertion (the next option) in hopes of keeping
              files reasonably small. */
              
          u32 del_from, del_len;

          if (masked_buf_len < 2) break;

          /* Don't delete too much. */

          del_len = choose_block_len(masked_buf_len - 1);

          del_from = UR(masked_buf_len - del_len + 1);

          memmove(masked_buf + del_from, masked_buf + del_from + del_len,
                  masked_buf_len - del_from - del_len);

          masked_buf_len -= del_len;
              
          break;

        }

        case 13:
            
          if (masked_buf_len + HAVOC_BLK_XL < MAX_FILE) {

            /* Clone bytes (75%) or insert a block of constant bytes (25%). */

            u8  actually_clone = UR(4);
            u32 clone_from, clone_to, clone_len;
            u8* new_buf;

            if (actually_clone) {

              clone_len  = choose_block_len(masked_buf_len);
              clone_from = UR(masked_buf_len - clone_len + 1);

            } else {
 
              clone_len = choose_block_len(HAVOC_BLK_XL);
              clone_from = 0;

            }

            clone_to   = UR(masked_buf_len);

            new_buf = ck_alloc_nozero(masked_buf_len + clone_len);

            /* Head */

            memcpy(new_buf, masked_buf, clone_to);

            /* Inserted part */

            if (actually_clone)
              memcpy(new_buf + clone_to, masked_buf + clone_from, clone_len);
            else
              memset(new_buf + clone_to,
                     UR(2) ? UR(256) : masked_buf[UR(masked_buf_len)], clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, masked_buf + clone_to,
                   masked_buf_len - clone_to);

            ck_free(masked_buf);
            masked_buf = new_buf;
            masked_buf_len += clone_len;

          }
            
          break;

        case 14: {

            /* Overwrite bytes with a randomly selected chunk (75%) or fixed
               bytes (25%). */

            u32 copy_from, copy_to, copy_len;

            if (masked_buf_len < 2) break;

            copy_len  = choose_block_len(masked_buf_len - 1);

            copy_from = UR(masked_buf_len - copy_len + 1);
            copy_to   = UR(masked_buf_len - copy_len + 1);

            if (UR(4)) {

              if (copy_from != copy_to)
                memmove(masked_buf + copy_to, masked_buf + copy_from, copy_len);
 
            } else memset(masked_buf + copy_to,
                          UR(2) ? UR(256) : masked_buf[UR(masked_buf_len)], copy_len);
             

            break;

          }

        case 15: {
            
          /*  u32 repeat_size = (1<<UR(4));
            if(repeat_size > size) repeat_size = size;
            u32 offset = UR(masked_buf_len);
            u32 repeat_len = UR(masked_buf_len-offset);
            
            for(int t=repeat_size;t<repeat_len;t+=repeat_size){
               if (offset+t+repeat_size < masked_buf_len) {
                 memcpy(masked_buf+offset+t, masked_buf+offset, repeat_size);
               }
            }
          */  
            break;
        }
        

          /* Values 16 and 17 can be selected only if there are any extras
             present in the dictionaries. */

        case 16: {

            /* Overwrite bytes with an extra. */

            if (!extras_cnt || (a_extras_cnt && UR(2))) {

              /* No user-specified extras or odds in our favor. Let's use an
                 auto-detected one. */

              u32 use_extra = UR(a_extras_cnt);
              u32 extra_len = a_extras[use_extra].len;
              u32 insert_at;

              if (extra_len > masked_buf_len) break;

              insert_at = UR(masked_buf_len - extra_len + 1);
              memcpy(masked_buf + insert_at, a_extras[use_extra].data, extra_len);

            } else {

              /* No auto extras or odds in our favor. Use the dictionary. */

              u32 use_extra = UR(extras_cnt);
              u32 extra_len = extras[use_extra].len;
              u32 insert_at;

              if (extra_len > masked_buf_len) break;

              insert_at = UR(masked_buf_len - extra_len + 1);
              memcpy(masked_buf + insert_at, extras[use_extra].data, extra_len);

            }

            break;

        }

        case 17: {

            u32 use_extra, extra_len, insert_at = UR(masked_buf_len + 1);
            u8* new_buf;

            /* Insert an extra. Do the same dice-rolling stuff as for the
               previous case. */

            if (!extras_cnt || (a_extras_cnt && UR(2))) {

              use_extra = UR(a_extras_cnt);
              extra_len = a_extras[use_extra].len;

              if (masked_buf_len + extra_len >= MAX_FILE) break;

              new_buf = ck_alloc_nozero(masked_buf_len + extra_len);

              /* Head */
              memcpy(new_buf, masked_buf, insert_at);

              /* Inserted part */
              memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);

            } else {

              use_extra = UR(extras_cnt);
              extra_len = extras[use_extra].len;

              if (masked_buf_len + extra_len >= MAX_FILE) break;

              new_buf = ck_alloc_nozero(masked_buf_len + extra_len);

              /* Head */
              memcpy(new_buf, masked_buf, insert_at);

              /* Inserted part */
              memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);

            }

            /* Tail */
            memcpy(new_buf + insert_at + extra_len, masked_buf + insert_at,
                   masked_buf_len - insert_at);

            ck_free(masked_buf);
            masked_buf   = new_buf;
            masked_buf_len += extra_len;

            break;

          }

      }

    }



    set_stream_input(&g_stream_input, addr, masked_buf, masked_buf_len);
      
    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    if (common_fuzz_stuff(file_buf, file_len)) return -1;
    

    /* If we're finding new stuff, let's run for a bit longer, limits
         permitting. */

    if (queued_paths != havoc_queued) {

      if (perf_score <= HAVOC_MAX_MULT * 100) {
        stage_max  *= 2;
        perf_score *= 2;
      }

      havoc_queued = queued_paths;
      
      u8* backup_buf = ck_alloc_nozero(len);
      
      memcpy(backup_buf, out_buf, len);
      memcpy(out_buf, masked_buf, masked_buf_len);
      set_stream_input(&g_stream_input, addr, out_buf, masked_buf_len);
      
      extend_stream_single(q);
      
      memcpy(out_buf, backup_buf, len);
      set_stream_input(&g_stream_input, addr, out_buf, len);
      
      ck_free(backup_buf);
    }
    
    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

      

    if (masked_buf_len < len) masked_buf = ck_realloc(masked_buf, len);
    masked_buf_len = len;
    memcpy(masked_buf, out_buf, len);
  }

  ck_free(masked_buf);

  set_stream_input(&g_stream_input, addr, out_buf, len);
  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_HAVOC]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_HAVOC] += stage_max;
     
  add_schedule_info(addr, new_hit_cnt - orig_hit_cnt, stage_max);
  
  return 0;
}


static u8 fti_mutate_havoc_stream(u8* masked_buf, u32 masked_buf_len, u32* valid_idx, u32 valid_idx_len) {

    u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));
    u32 idx_position;
    u16 v_16;
    u32 v_32;
 
    for (int i = 0; i < use_stacking; i++) {
      
      switch (UR(11 + ((extras_cnt + a_extras_cnt) ? 1 : 0))) {

        case 0:

          /* Flip a single bit somewhere. Spooky! */
          
          idx_position = UR(valid_idx_len);
          FLIP_BIT(masked_buf, (valid_idx[idx_position] << 3) + UR(8));
          break;

        case 1: 

          /* Set byte to interesting value. */
          idx_position = UR(valid_idx_len);
          masked_buf[valid_idx[idx_position]] = interesting_8[UR(sizeof(interesting_8))];
          break;

        case 2:

          /* Set word to interesting value, randomly choosing endian. */
          
          if (valid_idx_len < 2) break;
          
          idx_position = UR(valid_idx_len-1);
          v_16 =  interesting_16[UR(sizeof(interesting_16) >> 1)];

          if (UR(2)) {
            v_16 = SWAP16(v_16);
          }
          
          masked_buf[valid_idx[idx_position]] = v_16 & 0xff;
          v_16 >>= 8;
          masked_buf[valid_idx[idx_position+1]] = v_16 & 0xff; 

          break;

        case 3:
            
          /* Set dword to interesting value, randomly choosing endian. */

          if (valid_idx_len < 4) break;

          idx_position = UR(valid_idx_len-3);
          v_32 = interesting_32[UR(sizeof(interesting_32) >> 2)];

          if (UR(2)) {
            v_32 = SWAP32(v_32);
          }
          
          for(int j=0;j<4;j++) {
            masked_buf[valid_idx[idx_position+j]] = v_32 & 0xff;
            v_32 >>= 8;
          }

          break;

        case 4:

          /* Randomly subtract from byte. */
          idx_position = UR(valid_idx_len);
          
          masked_buf[valid_idx[idx_position]] -= 1 + UR(ARITH_MAX);
          break;

        case 5:

          /* Randomly add to byte. */
          idx_position = UR(valid_idx_len);
          
          masked_buf[valid_idx[idx_position]] += 1 + UR(ARITH_MAX);
          break;

        case 6:

          /* Randomly subtract from word, random endian. */

          if (valid_idx_len < 2) break;
          
          idx_position = UR(valid_idx_len-1);
          v_16 = 0;

          if (UR(2)) {

            v_16 = masked_buf[valid_idx[idx_position]];
            v_16 <<= 8;
            v_16 |= masked_buf[valid_idx[idx_position+1]];

            v_16 -= 1 + UR(ARITH_MAX);
            
            masked_buf[valid_idx[idx_position+1]] = v_16 & 0xff;
            v_16 >>=8;
            masked_buf[valid_idx[idx_position]] = v_16 & 0xff;
            

          } else {

            v_16 = masked_buf[valid_idx[idx_position+1]];
            v_16 <<= 8;
            v_16 |= masked_buf[valid_idx[idx_position]];

            v_16 -= 1 + UR(ARITH_MAX);
            
            masked_buf[valid_idx[idx_position]] = v_16 & 0xff;
            v_16 >>=8;
            masked_buf[valid_idx[idx_position+1]] = v_16 & 0xff;

          }

          break;

        case 7:

          /* Randomly add to word, random endian. */

          if (valid_idx_len < 2) break;
          
          idx_position = UR(valid_idx_len-1);
          v_16 = 0;

          if (UR(2)) {

            v_16 = masked_buf[valid_idx[idx_position]];
            v_16 <<= 8;
            v_16 |= masked_buf[valid_idx[idx_position+1]];

            v_16 += 1 + UR(ARITH_MAX);
            
            masked_buf[valid_idx[idx_position+1]] = v_16 & 0xff;
            v_16 >>=8;
            masked_buf[valid_idx[idx_position]] = v_16 & 0xff;
            

          } else {

            v_16 = masked_buf[valid_idx[idx_position+1]];
            v_16 <<= 8;
            v_16 |= masked_buf[valid_idx[idx_position]];

            v_16 += 1 + UR(ARITH_MAX);
            
            masked_buf[valid_idx[idx_position]] = v_16 & 0xff;
            v_16 >>=8;
            masked_buf[valid_idx[idx_position+1]] = v_16 & 0xff;

          }

          break;


        case 8:

          /* Randomly subtract from dword, random endian. */

          if (valid_idx_len < 4) break;
          
          idx_position = UR(valid_idx_len-3);
          v_32 = 0;

          for(int j=0;j<4;j++){
            v_32 |= masked_buf[valid_idx[idx_position+j]];
            v_32 <<= 8;
          }
          
          if (UR(2)) {

            v_32 -= 1 + UR(ARITH_MAX);
            
            v_32 = SWAP32(v_32);
            
            for(int j=0;j<4;j++){
              masked_buf[valid_idx[idx_position+j]] = v_32 & 0xff;
              v_32 >>= 8;
            }

          } else {

            v_32 = SWAP32(v_32);
            v_32 -= 1 + UR(ARITH_MAX); 

            for(int j=0;j<4;j++){
              masked_buf[valid_idx[idx_position+j]] = v_32 & 0xff;
              v_32 >>= 8;
            }

          }

          break;

        case 9:
 
          /* Randomly add to dword, random endian. */
          if (valid_idx_len < 4) break;
          
          idx_position = UR(valid_idx_len-3);
          v_32 = 0;

          for(int j=0;j<4;j++){
            v_32 |= masked_buf[valid_idx[idx_position+j]];
            v_32 <<= 8;
          }
          
          if (UR(2)) {

            v_32 += 1 + UR(ARITH_MAX);
            
            v_32 = SWAP32(v_32);
            
            for(int j=0;j<4;j++){
              masked_buf[valid_idx[idx_position+j]] = v_32 & 0xff;
              v_32 >>= 8;
            }

          } else {

            v_32 = SWAP32(v_32);
            v_32 += 1 + UR(ARITH_MAX); 

            for(int j=0;j<4;j++){
              masked_buf[valid_idx[idx_position+j]] = v_32 & 0xff;
              v_32 >>= 8;
            }

          }

          break;

        case 10:

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          idx_position = UR(valid_idx_len);
          
          masked_buf[valid_idx[idx_position]] ^= 1 + UR(255);
          break;


        case 11: {

            /* Overwrite bytes with an extra. */

            if (!extras_cnt || (a_extras_cnt && UR(2))) {

              /* No user-specified extras or odds in our favor. Let's use an
                 auto-detected one. */

              u32 use_extra = UR(a_extras_cnt);
              u32 extra_len = a_extras[use_extra].len;
              u32 insert_at;

              if (extra_len > valid_idx_len) break;

              idx_position = UR(valid_idx_len - extra_len + 1);
              
              for(int j=0;j<extra_len;j++){
                masked_buf[valid_idx[idx_position+j]] = a_extras[use_extra].data[j];
              }
              

            } else {

              /* No auto extras or odds in our favor. Use the dictionary. */

              u32 use_extra = UR(extras_cnt);
              u32 extra_len = extras[use_extra].len;
              u32 insert_at;

              if (extra_len > valid_idx_len) break;

              idx_position = UR(valid_idx_len - extra_len + 1);
              
              for(int j=0;j<extra_len;j++){
                masked_buf[valid_idx[idx_position+j]] = extras[use_extra].data[j];
              }

            }
            
            break;

        }
      }
    }
      
}

static u8 fti_mutate_stream(struct queue_entry* q, u8* in_buf, u32 in_len){
  u32 len, i, j;
  u8* file_buf;
  u32 file_len;
  u64 orig_hit_cnt, new_hit_cnt;
  u8  *out_buf = 0;
  u32 cksum;

  u32 perf_score = 100;
  u32 orig_perf = 100;

  static u64 all_mmios[MAX_STREAM_SIZE];
  u32 len_all_mmios = 0;
  
  u32 valid_idx[MAX_STREAM_LEN];
  u32 valid_idx_len;

  init_streams_input(&g_stream_input, in_buf, in_len, 0);
  
  get_streams_input_file(&g_stream_input, &file_buf, &file_len);
  if (get_exec_checksum(file_buf, file_len, &cksum)) return -1;

  memcpy(&cmplog_backup, cmplog_ptr, sizeof(struct cmp_map));
  
  khash_t(PTR) * kh_mmios = get_mmios(&g_stream_input);
  
  khiter_t k;
  for (k = kh_begin(kh_mmios); k != kh_end(kh_mmios); ++k){
    struct mmio* mmio = NULL;
    if (kh_exist(kh_mmios, k)) {
      mmio = kh_value(kh_mmios, k);
    }
    if (!mmio || mmio->valid == false){
      continue;
    }
    u64 addr = mmio->mmio_addr;
    // may skip base on addr?
    u16 size = mmio->size;
    u32 stream_id = mmio->stream_id;
    
    if(!is_visited_fti_info(q->fti_info, addr)){
      continue;
    }
    
    if(!get_stream_cmps_info(&g_cmp_info, addr)){
      continue;
    }

    if (unlikely(!get_stream_input(&g_stream_input, addr, &out_buf, &len))) {
      continue;     
    }
    if (out_buf == NULL || len==0){
      continue;
    }
    
    all_mmios[len_all_mmios++] = addr;
  }
    
  if (len_all_mmios==0){
    return 0;
  }
  u64 addr = schedule(all_mmios, len_all_mmios);
    
  struct mmio* mmio = get_mmio_by_addr(&g_stream_input, addr);
  if (mmio==NULL){
    return 0;
  }
  
  u16 size = mmio->size;
  u32 stream_id = mmio->stream_id;
  if (unlikely(!get_stream_input(&g_stream_input, addr, &out_buf, &len))) {
    return 0;     
  }
    
  if (out_buf == NULL || len==0){
    return 0;
  }

  
  khash_t(PTR) *cmps_info = get_stream_cmps_info(&g_cmp_info, addr);
  if(cmps_info == NULL) {
    
    havoc_stream(queue_cur, in_buf, len);
    return 0;
  }
  
  stage_cur_byte = -1;

  orig_perf = perf_score = calculate_score(queue_cur);

  u64 havoc_queued;
    
  stage_name  = "fti-mutate";
  stage_short = "fti-mutate";
  stage_max   = HAVOC_CYCLES * perf_score / havoc_div / 100;


  if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;
  
  u32 valid_br = 0;
  u32 stage_max_per = 0;
  u32 stage_cur_per = 0;
  u32 cur_stage_max_per = 0;
  stage_cur = 0;
  
  for (k = kh_begin(cmps_info); k != kh_end(cmps_info); ++k){
    if (kh_exist(cmps_info, k) ) {
      u64 cmp_id = kh_value(cmps_info, k);
      
      //if(! ((get_touched(&g_cmp_info,cmp_id) && !(get_untouched(&g_cmp_info,cmp_id))) || (get_untouched(&g_cmp_info,cmp_id) && !(get_touched(&g_cmp_info,cmp_id))))  ){
       // continue;
      //}
      struct stream_byte_cmps* cmps = get_direct_fti_info(q->fti_info, cmp_id, addr);
      
      if(cmps->count > 0) {
         valid_br++;
      }
       
      cmps = get_indirect_fti_info(q->fti_info, cmp_id, addr);
      
      if(cmps->count > 0) {
         valid_br++;
      }
    }
  }
  
  if (valid_br == 0) {
    havoc_stream(queue_cur, in_buf, len);
    return 0;
  }
  
  stage_max_per = MAX(10, stage_max/valid_br);
  stage_cur_per = 0;
  stage_cur = 0;

  bool skip = false;

  if (stage_max_per * valid_br > 5 * stage_max){
    skip = true;
    stage_max = stage_max_per * valid_br;
  }
  
  u32 masked_buf_len = len;
  u8* masked_buf = ck_alloc_nozero(masked_buf_len);
  
  for (k = kh_begin(cmps_info); k != kh_end(cmps_info); ++k){
    if (kh_exist(cmps_info, k) ) {
      u64 cmp_id = kh_value(cmps_info, k);
      
      //fprintf(stderr,"   direct cmp_id:%llu\n",cmp_id);
      struct stream_byte_cmps* cmps = get_direct_fti_info(q->fti_info, cmp_id, addr);
      
      valid_idx_len = 0;
      for(int t=0;t<cmps->count;t++) {
        //fprintf(stderr, "        idx:%d v0d:%d v1d:%d\n",cmps->byte_cmp[t].idx, cmps->byte_cmp[t].v0d, cmps->byte_cmp[t].v1d);
        u32 idx = cmps->byte_cmp[t].idx;
        if (idx < len) {
          valid_idx[valid_idx_len++] = idx;
        }
      }
      
      if(valid_idx_len==0){
        continue;
      }

      if (skip) {
        if(! ((get_touched(&g_cmp_info,cmp_id) && !(get_untouched(&g_cmp_info,cmp_id))) || (get_untouched(&g_cmp_info,cmp_id) && !(get_touched(&g_cmp_info,cmp_id))))  ){
          continue;
        }
        stage_max -= stage_max_per;
      }   

      cur_stage_max_per = stage_max_per;
      
      orig_hit_cnt = queued_paths + unique_crashes;
      havoc_queued = queued_paths;
      
      perf_score = orig_perf;
      for (stage_cur_per = 0; stage_cur_per < cur_stage_max_per; stage_cur_per++) {
        memcpy(masked_buf, out_buf, len);
        fti_mutate_havoc_stream(masked_buf, masked_buf_len, valid_idx, valid_idx_len);
        
        set_stream_input(&g_stream_input, addr, masked_buf, masked_buf_len);
        get_streams_input_file(&g_stream_input, &file_buf, &file_len);
      
        if (common_fuzz_stuff(file_buf, file_len)) return -1;

        if (queued_paths != havoc_queued) {

          if (perf_score <= HAVOC_MAX_MULT * 100) {
            stage_max += cur_stage_max_per;
            cur_stage_max_per  *= 2;
            perf_score *= 2;
          }

          havoc_queued = queued_paths;
          
          u8* backup_buf = ck_alloc_nozero(len);
      
          memcpy(backup_buf, out_buf, len);
          memcpy(out_buf, masked_buf, masked_buf_len);
          set_stream_input(&g_stream_input, addr, out_buf, masked_buf_len);
      
          extend_stream_single(q);
      
          memcpy(out_buf, backup_buf, len);
          set_stream_input(&g_stream_input, addr, out_buf, len);
      
          ck_free(backup_buf);

        }
        stage_cur++;
      }
      
      new_hit_cnt = queued_paths + unique_crashes;
      stage_finds[STAGE_COLORIZATION]  += new_hit_cnt - orig_hit_cnt;
      stage_cycles[STAGE_COLORIZATION] += cur_stage_max_per;
      add_schedule_info(addr, new_hit_cnt - orig_hit_cnt, cur_stage_max_per);
      
      
    }
    
  }
  
  stage_max_per = 0;
  stage_cur_per = 0;

  for (k = kh_begin(cmps_info); k != kh_end(cmps_info); ++k){
    if (kh_exist(cmps_info, k) ) {
      u64 cmp_id = kh_value(cmps_info, k);
      
      //fprintf(stderr,"   direct cmp_id:%llu\n",cmp_id);
      struct stream_byte_cmps* cmps = get_indirect_fti_info(q->fti_info, cmp_id, addr);
        
      valid_idx_len = 0;
      for(int t=0;t<cmps->count;t++) {
        //fprintf(stderr, "        idx:%d v0d:%d v1d:%d\n",cmps->byte_cmp[t].idx, cmps->byte_cmp[t].v0d, cmps->byte_cmp[t].v1d);
        u32 idx = cmps->byte_cmp[t].idx;
        if (idx < len) {
          valid_idx[valid_idx_len++] = idx;
        }
      }
      
      if(valid_idx_len==0){
        continue;
      }
      
      if (skip) {
        if(! ((get_touched(&g_cmp_info,cmp_id) && !(get_untouched(&g_cmp_info,cmp_id))) || (get_untouched(&g_cmp_info,cmp_id) && !(get_touched(&g_cmp_info,cmp_id))))  ){
          continue;
        }
        stage_max -= stage_max_per;
      }

      cur_stage_max_per = stage_max_per;
      orig_hit_cnt = queued_paths + unique_crashes;
      havoc_queued = queued_paths;
      
      perf_score = orig_perf;
      for (stage_cur_per = 0; stage_cur_per < cur_stage_max_per; stage_cur_per++) {
        memcpy(masked_buf, out_buf, len);
        fti_mutate_havoc_stream(masked_buf, masked_buf_len, valid_idx, valid_idx_len);
        
        set_stream_input(&g_stream_input, addr, masked_buf, masked_buf_len);
        get_streams_input_file(&g_stream_input, &file_buf, &file_len);
      
        if (common_fuzz_stuff(file_buf, file_len)) return -1;

        if (queued_paths != havoc_queued) {

          if (perf_score <= HAVOC_MAX_MULT * 100) {
            stage_max += cur_stage_max_per;
            cur_stage_max_per  *= 2;
            perf_score *= 2;
          }

          havoc_queued = queued_paths;
          u8* backup_buf = ck_alloc_nozero(len);
      
          memcpy(backup_buf, out_buf, len);
          memcpy(out_buf, masked_buf, masked_buf_len);
          set_stream_input(&g_stream_input, addr, out_buf, masked_buf_len);
      
          extend_stream_single(q);
      
          memcpy(out_buf, backup_buf, len);
          set_stream_input(&g_stream_input, addr, out_buf, len);
      
          ck_free(backup_buf);
        }
        stage_cur++;
      }
      
      new_hit_cnt = queued_paths + unique_crashes;
      stage_finds[STAGE_COLORIZATION]  += new_hit_cnt - orig_hit_cnt;
      stage_cycles[STAGE_COLORIZATION] += cur_stage_max_per;
      add_schedule_info(addr, new_hit_cnt - orig_hit_cnt, cur_stage_max_per);
      
      
    }
    
  }
  

  ck_free(masked_buf);
  set_stream_input(&g_stream_input, addr, out_buf, len);
  
  return 0;
}

static u8 havoc_multistream(struct queue_entry* q, u8* in_buf, u32 in_len){
  u32 len, i, j;
  u8* file_buf;
  u32 file_len;
  u64 orig_hit_cnt, new_hit_cnt;
  u8  *out_buf = NULL;

  u32 perf_score = 100;
  u32 orig_perf = 100;
 
  stage_cur_byte = -1;

  orig_perf = perf_score = calculate_score(queue_cur);

  u64 havoc_queued;
    
  stage_name  = "multi havoc";
  stage_short = "multi havoc";
  stage_max   = SPLICE_HAVOC * perf_score / havoc_div / 100;


  if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;

  orig_hit_cnt = queued_paths + unique_crashes;
  havoc_queued = queued_paths;

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */

    
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
    
    init_streams_input(&g_stream_input, in_buf, q->len, 0);
  
    khash_t(PTR) * kh_mmios = get_mmios(&g_stream_input);
  
    khiter_t k;
    
    for (k = kh_begin(kh_mmios); k != kh_end(kh_mmios); ++k){
      struct mmio* mmio = NULL;
      if (kh_exist(kh_mmios, k)) {
        mmio = kh_value(kh_mmios, k);
      }
      
      if (!mmio || mmio->valid == false){
        continue;
      }
      
      u64 addr = mmio->mmio_addr;
      // may skip base on addr?
      u16 size = mmio->size;
      u32 stream_id = mmio->stream_id;

      if (unlikely(!get_stream_input(&g_stream_input, addr, &out_buf, &len))) {
        continue;     
      }
      
      if (out_buf == NULL || len==0){
        continue;
      }
    
    
      u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

      stage_cur_val = use_stacking;
 
      for (i = 0; i < use_stacking; i++) {

        switch (UR(15 + ((extras_cnt + a_extras_cnt) ? 2 : 0))) {

          case 0:

            /* Flip a single bit somewhere. Spooky! */
        
            FLIP_BIT(out_buf, UR(len << 3));
            break;

          case 1: 

            /* Set byte to interesting value. */

            out_buf[UR(len)] = interesting_8[UR(sizeof(interesting_8))];
            break;

          case 2:

            /* Set word to interesting value, randomly choosing endian. */
          
            if (len < 2) break;

            if (UR(2)) {

              *(u16*)(out_buf + UR(len - 1)) =
                interesting_16[UR(sizeof(interesting_16) >> 1)];

            } else {

              *(u16*)(out_buf + UR(len - 1)) = SWAP16(
                interesting_16[UR(sizeof(interesting_16) >> 1)]);

            }

            break;

          case 3:
            
            /* Set dword to interesting value, randomly choosing endian. */

            if (len < 4) break;

            if (UR(2)) {
  
              *(u32*)(out_buf + UR(len - 3)) =
                interesting_32[UR(sizeof(interesting_32) >> 2)];

            } else {

              *(u32*)(out_buf + UR(len - 3)) = SWAP32(
                interesting_32[UR(sizeof(interesting_32) >> 2)]);

            }

            break;

          case 4:

            /* Randomly subtract from byte. */

            out_buf[UR(len)] -= 1 + UR(ARITH_MAX);
            break;

          case 5:

            /* Randomly add to byte. */

            out_buf[UR(len)] += 1 + UR(ARITH_MAX);
            break;

          case 6:

            /* Randomly subtract from word, random endian. */

            if (len < 2) break;

            if (UR(2)) {

              u32 pos = UR(len - 1);

              *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

            } else {

              u32 pos = UR(len - 1);
              u16 num = 1 + UR(ARITH_MAX);

              *(u16*)(out_buf + pos) =
                SWAP16(SWAP16(*(u16*)(out_buf + pos)) - num);

            }

            break;

          case 7:

            /* Randomly add to word, random endian. */

            if (len < 2) break;

            if (UR(2)) {

              u32 pos = UR(len - 1);

              *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);

            } else {

              u32 pos = UR(len - 1);
              u16 num = 1 + UR(ARITH_MAX);

              *(u16*)(out_buf + pos) =
                SWAP16(SWAP16(*(u16*)(out_buf + pos)) + num);
 
            }

            break;

          case 8:

            /* Randomly subtract from dword, random endian. */

            if (len < 4) break;

            if (UR(2)) {

              u32 pos = UR(len - 3);

              *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

            } else {

              u32 pos = UR(len - 3);
              u32 num = 1 + UR(ARITH_MAX);

              *(u32*)(out_buf + pos) =
                SWAP32(SWAP32(*(u32*)(out_buf + pos)) - num);

            }

            break;

          case 9:
 
            /* Randomly add to dword, random endian. */
            if (len < 4) break;

            if (UR(2)) {

              u32 pos = UR(len - 3);

              *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);

            } else {

              u32 pos = UR(len - 3);
              u32 num = 1 + UR(ARITH_MAX);

              *(u32*)(out_buf + pos) =
                SWAP32(SWAP32(*(u32*)(out_buf + pos)) + num);

            }

            break;

          case 10:

            /* Just set a random byte to a random value. Because,
               why not. We use XOR with 1-255 to eliminate the
               possibility of a no-op. */

            out_buf[UR(len)] ^= 1 + UR(255);
            break;

          case 11 ... 12: {

             /* Delete bytes. We're making this a bit more likely
                than insertion (the next option) in hopes of keeping
                files reasonably small. */
              
            u32 del_from, del_len;

            if (len < 2) break;

            /* Don't delete too much. */

            del_len = choose_block_len(len - 1);

            del_from = UR(len - del_len + 1);

            memmove(out_buf + del_from, out_buf + del_from + del_len,
                    len - del_from - del_len);

            len -= del_len;
              
            break;

          }

          case 13:
              /* clone, not imp */

          case 14: {

              /* Overwrite bytes with a randomly selected chunk (75%) or fixed
                 bytes (25%). */

            u32 copy_from, copy_to, copy_len;

            if (len < 2) break;

            copy_len  = choose_block_len(len - 1);

            copy_from = UR(len - copy_len + 1);
            copy_to   = UR(len - copy_len + 1);

            if (UR(4)) {

              if (copy_from != copy_to)
                memmove(out_buf + copy_to, out_buf + copy_from, copy_len);
 
            } else memset(out_buf + copy_to,
                          UR(2) ? UR(256) : out_buf[UR(len)], copy_len);
             

            break;

          }

          /* Values 15 and 16 can be selected only if there are any extras
             present in the dictionaries. */

          case 15: case 16: {

            /* Overwrite bytes with an extra. */

            if (!extras_cnt || (a_extras_cnt && UR(2))) {

              /* No user-specified extras or odds in our favor. Let's use an
                 auto-detected one. */

              u32 use_extra = UR(a_extras_cnt);
              u32 extra_len = a_extras[use_extra].len;
              u32 insert_at;

              if (extra_len > len) break;

              insert_at = UR(len - extra_len + 1);
              memcpy(out_buf + insert_at, a_extras[use_extra].data, extra_len);

            } else {

              /* No auto extras or odds in our favor. Use the dictionary. */

              u32 use_extra = UR(extras_cnt);
              u32 extra_len = extras[use_extra].len;
              u32 insert_at;

              if (extra_len > len) break;

              insert_at = UR(len - extra_len + 1);
              memcpy(out_buf + insert_at, extras[use_extra].data, extra_len);

            }

            break;

          }
          
        }
    
      }

    }

      
    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    if (common_fuzz_stuff(file_buf, file_len)) return -1;


    /* If we're finding new stuff, let's run for a bit longer, limits
         permitting. */

    if (queued_paths != havoc_queued) {

      if (perf_score <= HAVOC_MAX_MULT * 100) {
        stage_max  *= 2;
        perf_score *= 2;
      }

      havoc_queued = queued_paths;

    }

  }

  
  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_HAVOC]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_HAVOC] += stage_max;
  
  return 0;
}

#if 0
static u8 havoc_stream_bak(struct queue_entry* q, u8* in_buf, u32 in_len){
  u32 len, i, j;
  u8* file_buf;
  u32 file_len;
  u64 orig_hit_cnt, new_hit_cnt;
  u8  *out_buf = 0;

  u32 perf_score = 100;
  u32 orig_perf = 100;

  static u32 visited_streams[MAX_STREAM_SIZE];
  u32 len_visited_streams = 0;

  static u64 all_mmios[MAX_STREAM_SIZE];
  u32 len_all_mmios = 0;

  init_streams_input(&g_stream_input, in_buf, q->len, 0);
  
  khash_t(PTR) * kh_mmios = get_mmios(&g_stream_input);
  
  
  khiter_t k;
  for (k = kh_begin(kh_mmios); k != kh_end(kh_mmios); ++k){
    struct mmio* mmio = NULL;
    if (kh_exist(kh_mmios, k)) {
      mmio = kh_value(kh_mmios, k);
    }
    if (!mmio || mmio->valid == false){
      continue;
    }
    u64 addr = mmio->mmio_addr;
    // may skip base on addr?
    u16 size = mmio->size;
    u32 stream_id = mmio->stream_id;
    
    if (is_visited(visited_streams, len_visited_streams, stream_id)) {
      continue;
    }
    visited_streams[len_visited_streams++] = stream_id;

    if (unlikely(!get_stream_input(&g_stream_input,addr, &out_buf, &len))) {
      continue;     
    }
    if (out_buf == NULL || len==0){
      continue;
    }
  

// changed begin -----------------
    all_mmios[len_all_mmios++] = addr;
  }
    
    if (len_all_mmios==0){
       return 0;
    }
    u64 addr = schedule(all_mmios, len_all_mmios);
    
    struct mmio* mmio = get_mmio_by_addr(&g_stream_input,addr);
    if (mmio==NULL){
       return 0;
    }
    u16 size = mmio->size;
    u32 stream_id = mmio->stream_id;
    if (unlikely(!get_stream_input(&g_stream_input,addr, &out_buf, &len))) {
      return 0;     
    }
    if (out_buf == NULL || len==0){
      return 0;
    }
// changed end -------------------
    u64 mask_num = 0xffffffffffffffff;
    u32 mask_buf_len = 0;
    u8* mask_buf = NULL;
    u8* mask_num_buf = &mask_num;
    if (q->fti_info){
      khiter_t iter = kh_get(PTR, q->fti_info, stream_id);
      if( iter != kh_end(q->fti_info)) {
        if(kh_exist(q->fti_info, iter)) {
          struct fti_taint* taint = kh_value(q->fti_info, iter);
          if (taint) {
            mask_num = taint->mask_num;
            mask_buf = taint->mask_buf;
            mask_buf_len = taint->mask_buf_len;
          }
        }
      }
      if (mask_num == 0 && UR(10) < 8) {
        //continue;
        return 0;
      }
    }
    
    if (mask_num == 0) {
      mask_num = 0xffffffffffffffff;
    }
    
    stage_cur_byte = -1;

    orig_perf = perf_score = calculate_score(queue_cur);

    u64 havoc_queued;
    
    stage_name  = "havoc";
    stage_short = "havoc";
    stage_max   = HAVOC_CYCLES * perf_score / havoc_div / 100;


    if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;


    u32 tmp_out_buf_len;
    u8* tmp_out_buf;

    u32 backup_masked_buf_len;
    u8* backup_masked_buf;
 
    if (!compress_buf(mask_num, size, mask_buf, mask_buf_len, out_buf, len, &backup_masked_buf, &backup_masked_buf_len)) {
      //continue;
      return 0;
    }
    
    if (backup_masked_buf_len == 0) {
      //continue;
      return 0;
    }
    
    u32 masked_buf_len = backup_masked_buf_len;
    u8* masked_buf = ck_alloc_nozero(masked_buf_len);
    
    memcpy(masked_buf, backup_masked_buf, masked_buf_len);

    
    orig_hit_cnt = queued_paths + unique_crashes;
    havoc_queued = queued_paths;

    /* We essentially just do several thousand runs (depending on perf_score)
       where we take the input file and make random stacked tweaks. */

    
    for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

      u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

      stage_cur_val = use_stacking;
 
      for (i = 0; i < use_stacking; i++) {

        switch (UR(15 + ((extras_cnt + a_extras_cnt) ? 2 : 0))) {

          case 0:

            /* Flip a single bit somewhere. Spooky! */
        
            FLIP_BIT(masked_buf, UR(masked_buf_len << 3));
            break;

          case 1: 

            /* Set byte to interesting value. */

            masked_buf[UR(masked_buf_len)] = interesting_8[UR(sizeof(interesting_8))];
            break;

          case 2:

            /* Set word to interesting value, randomly choosing endian. */
          
            if (masked_buf_len < 2) break;

            if (UR(2)) {

              *(u16*)(masked_buf + UR(masked_buf_len - 1)) =
                interesting_16[UR(sizeof(interesting_16) >> 1)];

            } else {

              *(u16*)(masked_buf + UR(masked_buf_len - 1)) = SWAP16(
                interesting_16[UR(sizeof(interesting_16) >> 1)]);

            }

            break;

          case 3:
            
            /* Set dword to interesting value, randomly choosing endian. */

            if (masked_buf_len < 4) break;

            if (UR(2)) {
  
              *(u32*)(masked_buf + UR(masked_buf_len - 3)) =
                interesting_32[UR(sizeof(interesting_32) >> 2)];

            } else {

              *(u32*)(masked_buf + UR(masked_buf_len - 3)) = SWAP32(
                interesting_32[UR(sizeof(interesting_32) >> 2)]);

            }

            break;

          case 4:

            /* Randomly subtract from byte. */

            masked_buf[UR(masked_buf_len)] -= 1 + UR(ARITH_MAX);
            break;

          case 5:

            /* Randomly add to byte. */

            masked_buf[UR(masked_buf_len)] += 1 + UR(ARITH_MAX);
            break;

          case 6:

            /* Randomly subtract from word, random endian. */

            if (masked_buf_len < 2) break;

            if (UR(2)) {

              u32 pos = UR(masked_buf_len - 1);

              *(u16*)(masked_buf + pos) -= 1 + UR(ARITH_MAX);

            } else {

              u32 pos = UR(masked_buf_len - 1);
              u16 num = 1 + UR(ARITH_MAX);

              *(u16*)(masked_buf + pos) =
                SWAP16(SWAP16(*(u16*)(masked_buf + pos)) - num);

            }

            break;

          case 7:

            /* Randomly add to word, random endian. */

            if (masked_buf_len < 2) break;

            if (UR(2)) {

              u32 pos = UR(masked_buf_len - 1);

              *(u16*)(masked_buf + pos) += 1 + UR(ARITH_MAX);

            } else {

              u32 pos = UR(masked_buf_len - 1);
              u16 num = 1 + UR(ARITH_MAX);

              *(u16*)(masked_buf + pos) =
                SWAP16(SWAP16(*(u16*)(masked_buf + pos)) + num);
 
            }

            break;

          case 8:

            /* Randomly subtract from dword, random endian. */

            if (masked_buf_len < 4) break;

            if (UR(2)) {

              u32 pos = UR(masked_buf_len - 3);

              *(u32*)(masked_buf + pos) -= 1 + UR(ARITH_MAX);

            } else {

              u32 pos = UR(masked_buf_len - 3);
              u32 num = 1 + UR(ARITH_MAX);

              *(u32*)(masked_buf + pos) =
                SWAP32(SWAP32(*(u32*)(masked_buf + pos)) - num);

            }

            break;

          case 9:
 
            /* Randomly add to dword, random endian. */
            if (masked_buf_len < 4) break;

            if (UR(2)) {

              u32 pos = UR(masked_buf_len - 3);

              *(u32*)(masked_buf + pos) += 1 + UR(ARITH_MAX);

            } else {

              u32 pos = UR(masked_buf_len - 3);
              u32 num = 1 + UR(ARITH_MAX);

              *(u32*)(masked_buf + pos) =
                SWAP32(SWAP32(*(u32*)(masked_buf + pos)) + num);

            }

            break;

          case 10:

            /* Just set a random byte to a random value. Because,
               why not. We use XOR with 1-255 to eliminate the
               possibility of a no-op. */

            masked_buf[UR(masked_buf_len)] ^= 1 + UR(255);
            break;

          case 11 ... 12: {

              /* Delete bytes. We're making this a bit more likely
                 than insertion (the next option) in hopes of keeping
                 files reasonably small. */
              
              u32 del_from, del_len;

              if (masked_buf_len < 2) break;

              /* Don't delete too much. */

              del_len = choose_block_len(masked_buf_len - 1);

              del_from = UR(masked_buf_len - del_len + 1);

              memmove(masked_buf + del_from, masked_buf + del_from + del_len,
                      masked_buf_len - del_from - del_len);

              masked_buf_len -= del_len;
              
              break;

            }

          case 13:
            
            if (masked_buf_len + HAVOC_BLK_XL < MAX_FILE) {

              /* Clone bytes (75%) or insert a block of constant bytes (25%). */

              u8  actually_clone = UR(4);
              u32 clone_from, clone_to, clone_len;
              u8* new_buf;

              if (actually_clone) {

                clone_len  = choose_block_len(masked_buf_len);
                clone_from = UR(masked_buf_len - clone_len + 1);

              } else {
 
                clone_len = choose_block_len(HAVOC_BLK_XL);
                clone_from = 0;

              }

              clone_to   = UR(masked_buf_len);

              new_buf = ck_alloc_nozero(masked_buf_len + clone_len);

              /* Head */

              memcpy(new_buf, masked_buf, clone_to);

              /* Inserted part */

              if (actually_clone)
                memcpy(new_buf + clone_to, masked_buf + clone_from, clone_len);
              else
                memset(new_buf + clone_to,
                       UR(2) ? UR(256) : masked_buf[UR(masked_buf_len)], clone_len);

              /* Tail */
              memcpy(new_buf + clone_to + clone_len, masked_buf + clone_to,
                     masked_buf_len - clone_to);

              ck_free(masked_buf);
              masked_buf = new_buf;
              masked_buf_len += clone_len;

            }
            
            break;

          case 14: {

              /* Overwrite bytes with a randomly selected chunk (75%) or fixed
                 bytes (25%). */

              u32 copy_from, copy_to, copy_len;

              if (masked_buf_len < 2) break;

              copy_len  = choose_block_len(masked_buf_len - 1);

              copy_from = UR(masked_buf_len - copy_len + 1);
              copy_to   = UR(masked_buf_len - copy_len + 1);

              if (UR(4)) {

                if (copy_from != copy_to)
                  memmove(masked_buf + copy_to, masked_buf + copy_from, copy_len);
 
              } else memset(masked_buf + copy_to,
                            UR(2) ? UR(256) : masked_buf[UR(masked_buf_len)], copy_len);
              

              break;

            }

          /* Values 15 and 16 can be selected only if there are any extras
             present in the dictionaries. */

          case 15: {

              /* Overwrite bytes with an extra. */

              if (!extras_cnt || (a_extras_cnt && UR(2))) {

                /* No user-specified extras or odds in our favor. Let's use an
                   auto-detected one. */

                u32 use_extra = UR(a_extras_cnt);
                u32 extra_len = a_extras[use_extra].len;
                u32 insert_at;

                if (extra_len > masked_buf_len) break;

                insert_at = UR(masked_buf_len - extra_len + 1);
                memcpy(masked_buf + insert_at, a_extras[use_extra].data, extra_len);

              } else {

                /* No auto extras or odds in our favor. Use the dictionary. */

                u32 use_extra = UR(extras_cnt);
                u32 extra_len = extras[use_extra].len;
                u32 insert_at;

                if (extra_len > masked_buf_len) break;

                insert_at = UR(masked_buf_len - extra_len + 1);
                memcpy(masked_buf + insert_at, extras[use_extra].data, extra_len);

              }

              break;

            }

          case 16: {

              u32 use_extra, extra_len, insert_at = UR(masked_buf_len + 1);
              u8* new_buf;

              /* Insert an extra. Do the same dice-rolling stuff as for the
                 previous case. */

              if (!extras_cnt || (a_extras_cnt && UR(2))) {

                use_extra = UR(a_extras_cnt);
                extra_len = a_extras[use_extra].len;

                if (masked_buf_len + extra_len >= MAX_FILE) break;

                new_buf = ck_alloc_nozero(masked_buf_len + extra_len);

                /* Head */
                memcpy(new_buf, masked_buf, insert_at);

                /* Inserted part */
                memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);

              } else {

                use_extra = UR(extras_cnt);
                extra_len = extras[use_extra].len;

                if (masked_buf_len + extra_len >= MAX_FILE) break;

                new_buf = ck_alloc_nozero(masked_buf_len + extra_len);

                /* Head */
                memcpy(new_buf, masked_buf, insert_at);

                /* Inserted part */
                memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);

              }

              /* Tail */
              memcpy(new_buf + insert_at + extra_len, masked_buf + insert_at,
                     masked_buf_len - insert_at);

              ck_free(masked_buf);
              masked_buf   = new_buf;
              masked_buf_len += extra_len;

              break;

            }

        }

      }

      if (!decompress_buf(mask_num, size, mask_buf, mask_buf_len, masked_buf, masked_buf_len, &tmp_out_buf, &tmp_out_buf_len)) {
        //continue;
        return 0;
      }

      set_stream_input(&g_stream_input, addr, tmp_out_buf, tmp_out_buf_len);
      
      get_streams_input_file(&g_stream_input, &file_buf, &file_len);
      if (common_fuzz_stuff(file_buf, file_len)) return -1;

      /* out_buf might have been mangled a bit, so let's restore it to its
         original size and shape. */

      

      if (masked_buf_len < backup_masked_buf_len) masked_buf = ck_realloc(masked_buf, backup_masked_buf_len);
      masked_buf_len = backup_masked_buf_len;
      memcpy(masked_buf, backup_masked_buf, backup_masked_buf_len);

      /* If we're finding new stuff, let's run for a bit longer, limits
         permitting. */

      if (queued_paths != havoc_queued) {

        if (perf_score <= HAVOC_MAX_MULT * 100) {
          stage_max  *= 2;
          perf_score *= 2;
        }

        havoc_queued = queued_paths;

      }

    }
    

    ck_free(masked_buf);

    set_stream_input(&g_stream_input, addr, out_buf, len);
    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_HAVOC]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_HAVOC] += stage_max;
    
// change begin ----------
 // }
    
    add_schedule_info(addr, new_hit_cnt - orig_hit_cnt, stage_max);
  
// change end -------------
  
  return 0;
}
#endif

static u8 splice_stream(struct queue_entry* q, u8* in_buf, u32 in_len){
  if (queued_paths<2)return 0;
  
  u32 len, i, j;
  u8* file_buf;
  u32 file_len;
  u64 orig_hit_cnt, new_hit_cnt;
  u8  *out_buf = 0;

  u32 perf_score = 100;
  u32 orig_perf = 100;
  u64 havoc_queued;

  static u32 visited_streams[MAX_STREAM_SIZE];
  u32 len_visited_streams = 0;

  static u64 all_mmios[MAX_STREAM_SIZE];
  u32 len_all_mmios = 0;

  if(!init_streams_input(&g_stream_input, in_buf, q->len, 0)) return -1;
  
  orig_perf = perf_score = calculate_score(queue_cur);
  
  stage_name  = "splice";
  stage_short = "splice";
  stage_max   = SPLICE_HAVOC * perf_score / havoc_div / 100;

  if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;
  
  stage_cur = 0;
  
  orig_hit_cnt = queued_paths + unique_crashes;
  havoc_queued = queued_paths;
  
  

retry_splicing:
  while (stage_cur < stage_max) {
    init_streams_input(&g_stream_input, in_buf, q->len, 0);
    khash_t(PTR) * kh_mmios = get_mmios(&g_stream_input);
    
    struct queue_entry* target;
    u32 tid, split_at;
    u8* new_buf;
    s32 f_diff, l_diff;


    stage_cur++;
    /* Pick a random queue entry and seek to it. Don't splice with yourself. */
    
    do { tid = UR(queued_paths); } while (tid == current_entry);

    splicing_with = tid;
    target = queue;

    while (tid >= 100) { target = target->next_100; tid -= 100; }
    while (tid--) target = target->next;

    /* Make sure that the target has a reasonable length. */

    while (target && (target->len < 2 || target == queue_cur)) {
      target = target->next;
      splicing_with++;
    }

    if (!target) goto retry_splicing;

    /* Read the testcase into a new buffer. */

    s32 fd = open(target->fname, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

    new_buf = ck_alloc_nozero(target->len);

    ck_read(fd, new_buf, target->len, target->fname);

    close(fd);

    if(!init_streams_input(&g_stream_input2, new_buf, target->len, 0)){ ck_free(new_buf); goto retry_splicing;};
    len_visited_streams = 0;
    
    khiter_t k;
    for (k = kh_begin(kh_mmios); k != kh_end(kh_mmios); ++k){
      struct mmio* mmio = NULL;
      if (kh_exist(kh_mmios, k)) {
        mmio = kh_value(kh_mmios, k);
      }
      if (!mmio || mmio->valid == false){
        continue;
      }
      u64 addr = mmio->mmio_addr;
      // may skip base on addr?
      u16 size = mmio->size;
      u32 stream_id = mmio->stream_id;
    
      if (is_visited(visited_streams, len_visited_streams, stream_id)) {
        continue;
      }
      visited_streams[len_visited_streams++] = stream_id;

      if (unlikely(!get_stream_input(&g_stream_input,addr, &out_buf, &len))) {
        continue;     
      }
      if (out_buf == NULL || len==0){
        continue;
      }
      
      u8* tmp_out_buf;
      u32 tmp_len;
      
      if (unlikely(!get_stream_input(&g_stream_input2,addr, &tmp_out_buf, &tmp_len))) {
        continue;     
      }
      if (tmp_out_buf == NULL || tmp_len==0){
        continue;
      }
      
      /* Find a suitable splicing location, somewhere between the first and
         the last differing byte. Bail out if the difference is just a single
         byte or so. */

      locate_diffs(out_buf, tmp_out_buf, MIN(len, tmp_len), &f_diff, &l_diff);

      if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
        continue;
      }

      /* Split somewhere between the first and last differing byte. */

      split_at = f_diff + UR(l_diff - f_diff);

      /* Do the thing. */

      stream_set_region(&g_stream_input, addr, 0, split_at, tmp_out_buf);

    }
    
    get_streams_input_file(&g_stream_input, &file_buf, &file_len);
    if (common_fuzz_stuff(file_buf, file_len)) return -1;
    
    ck_free(new_buf);
    
    if (queued_paths != havoc_queued) {
      if (perf_score <= HAVOC_MAX_MULT * 100) {
        stage_max  *= 2;
        perf_score *= 2;
      }
      havoc_queued = queued_paths;
    }
    
  }
  
 
  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_SPLICE]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_SPLICE] += stage_max;
    
  
  return 0;
}

#define MAX_EXTEND_LEN 65536

static void random_extend_stream(u64 addr, u16 len) {
    u8* tmp;
    u32 orig_len;
    static u8 buffer[MAX_EXTEND_LEN];
    random_replace(buffer,len);
    stage_short = "ext_random";
    if(get_stream_input(&g_stream_input,addr, &tmp, &orig_len)) {
        stream_insert_region(&g_stream_input, addr, orig_len, len, buffer);
    }
}

static void copy_extend_stream(u64 addr, u16 len) {
    stage_short = "ext_copy";
    u8* tmp;
    u32 orig_len;
    static u8 buffer[MAX_EXTEND_LEN];

    if(get_stream_input(&g_stream_input, addr, &tmp, &orig_len) ){
        if (tmp && orig_len) {
            u32 tmp_len = 0;
            while (tmp_len < len) {
               u32 start = UR(orig_len);
               u32 tmpp_len = UR(orig_len-start)+1;
               if (tmp_len + tmpp_len>MAX_EXTEND_LEN){
                   break;
               }
               memcpy(buffer+tmp_len,&(tmp[start]),tmpp_len);
               tmp_len += tmpp_len;
            }
            if(len > tmp_len){
               len = tmp_len;
            }   
            stream_insert_region(&g_stream_input,addr, orig_len, len, buffer);
        }
    }
}

static void copy_repeat_extend_stream(u64 addr, u16 len) {
    stage_short = "ext_copy_repeat";
    u8* tmp;
    u32 orig_len;
    static u8 buffer[MAX_EXTEND_LEN];
    
    if(get_stream_input(&g_stream_input, addr, &tmp, &orig_len) ){
        if (tmp && orig_len) {
            u32 tmp_len = 0;
            u32 start = UR(orig_len);
            u32 tmpp_len = UR(orig_len-start)+1;
            while (tmp_len < len) {
               
               if (tmp_len + tmpp_len>MAX_EXTEND_LEN){
                   break;
               }
               memcpy(buffer+tmp_len,&(tmp[start]),tmpp_len);
               tmp_len += tmpp_len;

            }
            if(len > tmp_len){
               len = tmp_len;
            }   
                  
            stream_insert_region(&g_stream_input,addr, orig_len, len, buffer);
        }
    }
}



static void value_extend_stream(u64 addr, u16 len) {
    u8* tmp;
    u32 orig_len;
    u32 start = 0;
    static u8 buffer[MAX_EXTEND_LEN];
    
    u32 tl = 0;
    u8* value;
    u8 zero = 0;
    u8 one = 1;
    
    bool printable = true;
    
    if (UR(10) < 5){
        if (UR(2)) {
            value = &one;
        }else{
            value = &zero;
        }
        tl = 1;
    }else if ((extras_cnt || a_extras_cnt) && (UR(10)<6)) {
        if (extras_cnt && a_extras_cnt) {
            u32 use_extra;
            if (UR(2)) {
              use_extra = UR(extras_cnt);
              tl = extras[use_extra].len;
              value = extras[use_extra].data;
            }else{
              use_extra = UR(a_extras_cnt);
              tl = a_extras[use_extra].len;
              value = a_extras[use_extra].data;
            }
        }else{
            u32 use_extra;
            if (extras_cnt) {
              use_extra = UR(extras_cnt);
              tl = extras[use_extra].len;
              value = extras[use_extra].data;
            }else{
              use_extra = UR(a_extras_cnt);
              tl = a_extras[use_extra].len;
              value = a_extras[use_extra].data;
            }
        }
    
    }else{
        u32 tr = UR(3);
        if (tr == 0) {
            value = &interesting_8[UR(sizeof(interesting_8))];
            tl = 1;
        }else if (tr==1){
            value = &interesting_16[UR(sizeof(interesting_16)/2)];
            tl = 2;
        }else if (tr==2){
            value = &interesting_32[UR(sizeof(interesting_32)/4)];
            tl = 4;
        }
    }
    
    for(int i=0;i<tl;i++){
      if(!is_printable(value[i])){
        printable = false;
      }
    }
    
    u8* splits[] = {" ","\t","\r","\n","\r\n"};
    u8* split = splits[UR(5)];
    u32 split_len = 0;
    
    if(printable && UR(2)) {
      split_len = strlen(split);
    }
    
    
    u32 stride = (1 << UR(3));
    memset(buffer, 0, len);
    
    int i = 0;
    while(i<len) {
      for(int j=0;j<tl+split_len;j++){
        u8 v;
        if(j<tl) {
          v = value[j];
        }else{
          v = split[j-tl];
        }
        for(int k=0;k<stride;k++){
          if(i<len) {
            buffer[i] = v;
            i++;
          }
        }
      }
    }
       
    //u32 tlen = len;
    //for(int i=0;i<len;i+=tl){
    //    memcpy(buffer+i,value,tl);
    //}
    stage_short = "ext_value";
    if(get_stream_input(&g_stream_input, addr, &tmp, &orig_len) ){
        stream_insert_region(&g_stream_input,addr, orig_len, len, buffer);
    }
}


static struct snapshotting_state_t snapshot_state;
static u8* cov_snapshot = NULL;
static u8* cmplog_snapshot = NULL;

#ifdef SMART_STREAM
static CircularQueue last_read_mmio_backup;
#endif
static void extend_stream_snapshot(){
  run_target();
  uint64_t target_ticks = get_global_ticker();
  restore_snapshot_initial(g_uc);
  uint64_t ticks_so_far = get_global_ticker();
  
  if (target_ticks - ticks_so_far > 2){
      set_timer_reload_val(instr_limit_timer_id, target_ticks - ticks_so_far - 2);

  
  }else{
      set_timer_reload_val(instr_limit_timer_id, target_ticks - ticks_so_far - 1);
  }
  
  uc_fuzzer_reset_cov(g_uc, 1);
  if (cmplog_mode) {
      uc_fuzzer_reset_cmplog(g_uc, 1);
  }
  memset(stream_map, 0, sizeof(struct stream_feedback));


  run_single(g_uc);
  set_timer_reload_val(instr_limit_timer_id, instr_limit);
  
 
  // snapshot here
  trigger_snapshotting(g_uc);
  memcpy(&stream_map_initial_backup, stream_map, sizeof(struct stream_feedback));
  //memcpy(fuzz_area_ptr_backup, fuzz_area_ptr, MAP_SIZE);
  if (cov_snapshot) {
      free(cov_snapshot);
  }
  cov_snapshot = uc_fuzzer_snapshot_cov(g_uc);
  if (cmplog_mode) {
      //memcpy(&fuzz_cmp_map_initial_backup, &fuzz_cmp_map_initial, sizeof(struct cmp_map));
      if (cmplog_snapshot) free(cmplog_snapshot);
      cmplog_snapshot = uc_fuzzer_snapshot_cmplog(g_uc);
  }
  
#ifdef SMART_STREAM
  memcpy(&last_read_mmio_backup, &last_read_mmio, sizeof(last_read_mmio));
#endif
  struct snapshotting_state_t* state = get_global_snapshotting(g_uc);
    
  snapshot_state.num_used = state->num_used;
  snapshot_state.num_allocated = state->num_allocated;
  snapshot_state.snapshots = calloc(snapshot_state.num_allocated, sizeof(*snapshot_state.snapshots));
    
  for(int i = 0; i < state->num_used; ++i) {
    snapshot_state.snapshots[i] = state->snapshots[i];
  }

}


static void extend_stream_restore(){

  struct snapshotting_state_t* state = get_global_snapshotting(g_uc);
    
  state->num_used = snapshot_state.num_used;
  state->num_allocated = snapshot_state.num_allocated;
  state->snapshots = calloc(state->num_allocated, sizeof(*state->snapshots));
    
  for(int i = 0; i < state->num_used; ++i) {
     state->snapshots[i] = snapshot_state.snapshots[i];
  }
  
  trigger_restore(g_uc);
  memcpy(stream_map, &stream_map_initial_backup, sizeof(struct stream_feedback));
  //memcpy(fuzz_area_ptr, fuzz_area_ptr_backup, MAP_SIZE);
  uc_fuzzer_restore_cov(g_uc, cov_snapshot);
  if (cmplog_mode) {
      //memcpy(&fuzz_cmp_map_initial, &fuzz_cmp_map_initial_backup, sizeof(struct cmp_map));
      uc_fuzzer_restore_cmplog(g_uc, cmplog_snapshot);
  }
#ifdef SMART_STREAM
  memcpy(&last_read_mmio, &last_read_mmio_backup, sizeof(last_read_mmio));
#endif
  duplicate_exit = false;

}

static void extend_stream_discard(){
  trigger_teardown(g_uc);
  restore_snapshot_initial(g_uc);
}


/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

static u8 stream_snapshot_run_target() {
  u64 start_us, stop_us;
  static u64 exec_ms = 0;

  //int status = 0;
  u32 tb4;
  
  /* After this memset, trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */
  extend_stream_restore();
  MEM_BARRIER();

  start_us = get_cur_time_us();
  kill_signal = run_single(g_uc);
  stop_us = get_cur_time_us();


  exec_ms = (stop_us - start_us) / 1000;

  if (exec_ms > exec_tmout) {
      child_timed_out = 1;
  }

  total_execs++;

  /* Any subsequent operations on trace_bits must not be moved by the
     compiler below this point. Past this location, trace_bits[] behave
     very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  tb4 = *(u32*)trace_bits;

#ifdef WORD_SIZE_64
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);
#endif /* ^WORD_SIZE_64 */

  /* Report outcome to caller. */

  if (kill_signal && !stop_soon) {

    

    if (child_timed_out && kill_signal == SIGKILL) return FAULT_TMOUT;

    return FAULT_CRASH;

  }


 

  /* It makes sense to account for the slowest units only if the testcase was run
  under the user defined timeout. */
  if (!(exec_ms > exec_tmout) && (slowest_exec_ms < exec_ms)) {
    slowest_exec_ms = exec_ms;
  }

  return FAULT_NONE;

}

static u8 stream_fuzz_stuff(u8* out_buf, u32 len) {

  u8 fault = stream_snapshot_run_target();

  if (stop_soon) return 1;

  if (fault == FAULT_TMOUT) {

    if (subseq_tmouts++ > TMOUT_LIMIT) {
      cur_skipped_paths++;
      return 1;
    }

  } else subseq_tmouts = 0;

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (skip_requested) {

     skip_requested = 0;
     cur_skipped_paths++;
     return 1;

  }

  /* This handles FAULT_ERROR for us: */

  queued_discovered += save_if_interesting(out_buf, len, fault);

  if (!(stage_cur % stats_update_freq) || stage_cur + 1 == stage_max)
    show_stats();

  return 0;

}

static u32 get_max_num_extension(struct queue_entry* q){
#define MAX_NUM_EXTENSION 256
  u32 max_num_extension = 1;

  max_num_extension = queue_cycle;

  if (max_num_extension > MAX_NUM_EXTENSION) {
    max_num_extension = MAX_NUM_EXTENSION;
  }
  
  return max_num_extension;
}


static void extend_stream_single(struct queue_entry* q) {
  
  u64 extend_queued, orig_hit_cnt, new_hit_cnt;
  
  u64 addr = 0;
  u32 size = 0;

  u32 len = 0;
  u8* out_buf = NULL;
  
  u32 max_num_extension = get_max_num_extension(q);
  u32 num_extension;
  
  orig_hit_cnt = queued_paths + unique_crashes;
  extend_queued = queued_paths;

  khiter_t k;

  khash_t(PTR) *kh_mmios = get_mmios(&g_stream_input);
    
  num_extension = UR(max_num_extension)+1;
  
  for (int i=0;i<num_extension;i++) {

    for (k = kh_begin(kh_mmios); k != kh_end(kh_mmios); ++k){
      struct mmio* mmio = NULL;
      if (kh_exist(kh_mmios, k)) {
        mmio = kh_value(kh_mmios, k);
      }
        
      if(!mmio) {
        continue;
      }
        
      u64 ext_addr = mmio->mmio_addr;
      u32 ext_len = UR(1024);
      if (ext_len < 4){
        ext_len = 4;
      }
      u8 r = UR(3);
        
      if(r%4 == 0) {
        random_extend_stream(ext_addr,ext_len);
      } else if( r%4 == 1) {
        copy_extend_stream(ext_addr,ext_len);
      }else if(r%4 == 2){
        value_extend_stream(ext_addr,ext_len);
      }else{
        copy_repeat_extend_stream(ext_addr,ext_len);
      }
    }
  }
      
      
  get_streams_input_file(&g_stream_input, &out_buf, &len);

  common_fuzz_stuff(out_buf, len);
      
  new_hit_cnt = queued_paths + unique_crashes;
  stage_finds[STAGE_EXTEND]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTEND] += 1;
  
  return;

}


static void extend_stream(struct queue_entry* q, u8* in_buf, u32 in_len) {
  
  u64 extend_queued, orig_hit_cnt, new_hit_cnt;
  u64 start_us, stop_us, average_us;
  
  u32 new_stream = 0;
  u64 addr = 0;
  u32 size = 0;

  u32 perf_score = 100;
  u32 cal = 0;

  u32 len = 0;
  u8* out_buf = NULL;
  
  stage_name  = "stream ext";
  init_streams_input(&g_stream_input,in_buf, in_len, 0);
  
  static u64 cur_streams[MAX_STREAM_SIZE];
  static u32 cur_streams_extend_len[MAX_STREAM_SIZE];
  u32 cur_streams_num = 0;
  
  
  
  //extend_stream_snapshot();
  //stream_snapshot_run_target();

  addr = stream_bits->status.addr;
  new_stream = stream_bits->status.new_stream;
  size = stream_bits->status.size;

  if (new_stream) {
    insert_mmio(&g_stream_input, addr, size, 0);
    insert_schedule_info(addr);
  }

  //get_streams_input_file(&g_stream_input, &out_buf, &len);
  if (!addr) {
      goto out;
  }

  khiter_t k;
  khash_t(PTR) *kh_mmios;
  for (k = kh_begin(kh_mmios); k != kh_end(kh_mmios); ++k){
    struct mmio* mmio = NULL;
    if (kh_exist(kh_mmios, k)) {
      mmio = kh_value(kh_mmios, k);
    }
        
    if(!mmio) {
      continue;
    }
        
    if(!insert_mmio(&g_stream_input, mmio->mmio_addr, mmio->size, mmio->stream_id)){
      continue;
    }
        
    addr = mmio->mmio_addr;
        
    int csn = 0;
    for(;csn<cur_streams_num;csn++){
      if(cur_streams[csn] == addr) {
        break;
      }
    }
    if(csn==cur_streams_num) {
      u8* tmp;
      u32 orig_len;
      get_stream_input(&g_stream_input, addr, &tmp, &orig_len);
      cur_streams[cur_streams_num] = addr;
      cur_streams_extend_len[cur_streams_num] = orig_len;
      //cur_streams_extend_len[cur_streams_num] = 2048;
      cur_streams_num++;
    }
  }
  
  

#define BASE_EXTEND_LEN 32
  cur_streams[cur_streams_num] = addr;
  cur_streams_extend_len[cur_streams_num] = BASE_EXTEND_LEN;
  cur_streams_num++;
  
  u32 max_extend_len;
  u64 last_extend_addr = 0;
#define EXTEND_CAL_CYCLES 10
  
  u32 max_num_extension = get_max_num_extension(q);
  u32 num_extension;
  
  orig_hit_cnt = queued_paths + unique_crashes;
  extend_queued = queued_paths;
   
  stage_max = EXTEND_CAL_CYCLES;
  stage_cur = 0;
  cal = 1;


extend_stage:
  start_us = get_cur_time_us();
  for(;stage_cur<stage_max;stage_cur++) {
    
    reset_streams_input(&g_stream_input, in_buf, in_len);

    kh_mmios = get_mmios(&g_stream_input);
    
    num_extension = UR(max_num_extension)+1;
    //num_extension = 1;
    for (int i=0;i<num_extension;i++)

      for (k = kh_begin(kh_mmios); k != kh_end(kh_mmios); ++k){
        struct mmio* mmio = NULL;
        if (kh_exist(kh_mmios, k)) {
          mmio = kh_value(kh_mmios, k);
        }
        
        if(!mmio) {
          continue;
        }
        
        if(!insert_mmio(&g_stream_input, mmio->mmio_addr, mmio->size, mmio->stream_id)){
          continue;
        }
        
        u64 ext_addr = mmio->mmio_addr;
        
        int csn = 0;
        for(;csn<cur_streams_num;csn++){
          if(cur_streams[csn] == ext_addr) {
            break;
          }
        }
        if(csn==cur_streams_num) {
           cur_streams[cur_streams_num] = ext_addr;
           cur_streams_extend_len[cur_streams_num] = BASE_EXTEND_LEN;
           cur_streams_num++;
        }
        
        max_extend_len = cur_streams_extend_len[csn]/num_extension;
        
        //max_extend_len = cur_streams_extend_len[csn];
        if (max_extend_len < BASE_EXTEND_LEN) max_extend_len = BASE_EXTEND_LEN;
        if (max_extend_len > 255) {
          max_extend_len = 255;
        }
        //if (max_extend_len > MAX_EXTEND_LEN) {
         // max_extend_len = MAX_EXTEND_LEN;
        //}
        u32 ext_len = UR(max_extend_len);
        //u32 ext_len = max_extend_len;

        if (ext_len < 4){
          ext_len = 4;
        }
        u8 r = UR(3);
        
        if(r%4 == 0) {
          random_extend_stream(ext_addr,ext_len);
        } else if( r%4 == 1) {
          copy_extend_stream(ext_addr,ext_len);
        }else if(r%4 == 2){
          value_extend_stream(ext_addr,ext_len);
        }else{
          copy_repeat_extend_stream(ext_addr,ext_len);
        }
      }
      
      //out_buf = get_file(&len);
      get_streams_input_file(&g_stream_input, &out_buf, &len);

      //if(stream_fuzz_stuff(out_buf, len)) goto out; 
      if (common_fuzz_stuff(out_buf, len)) goto out;
      
      new_stream = stream_bits->status.new_stream;
      addr = stream_bits->status.addr;
      size = stream_bits->status.size;

      if (new_stream) {
        
#ifdef SMART_STREAM
        uint64_t *mmio_arr;
        int len_of_mmios;
        struct mmio* last_mmio = NULL;
        uint64_t last_addr = 0;
        mmio_arr = get_data__CircularQueue(&last_read_mmio, &len_of_mmios);
        if (len_of_mmios > 0) {
          last_addr = mmio_arr[len_of_mmios-1];
          last_mmio = get_mmio_by_addr(&g_stream_input, last_addr);
        }

        if ((fix_checksum_mode || smart_stream) && last_mmio && last_mmio->size == size && last_addr + last_mmio->size == addr) {
          //fprintf(stderr, "merge new mmio %016lx:%d to %016lx\n",addr, size, last_addr);
          insert_mmio(&g_stream_input, addr, size, last_mmio->stream_id);
          insert_schedule_info(addr);
        }else
#endif
        {
          insert_mmio(&g_stream_input, addr, size, 0);
          insert_schedule_info(addr);
        }
      }
      
      if (cal == 0) {
        if (queued_paths != extend_queued) {
          if (perf_score <= EXTEND_MAX_MULT * 100) {
            stage_max  *= 2;
            //stage_max += 100;
            perf_score *= 2;
          }
          extend_queued = queued_paths;
        }
      }
      
      int csn = 0;
      for(;csn<cur_streams_num;csn++){
        if(cur_streams[csn] == addr) {
          break;
        }
      }
      if(csn==cur_streams_num) {
        cur_streams[cur_streams_num] = addr;
        cur_streams_extend_len[cur_streams_num] = BASE_EXTEND_LEN;
        cur_streams_num++;
      }/*else{
        if(last_extend_addr != cur_streams[csn]) {
          last_extend_addr = cur_streams[csn];
        }else{
          last_extend_addr = 0;
          cur_streams_extend_len[csn] *= 2;
          if (cur_streams_extend_len[csn] > 1024) {
            cur_streams_extend_len[csn] = 1024;
          }
        }
      }*/
      
  };
   
  stop_us = get_cur_time_us();
  if (cal) {
    average_us = (stop_us - start_us) / stage_max;
    perf_score = calculate_score_stream(q, average_us);
    cal = 0;
    stage_max += EXTEND_CYCLES * perf_score / havoc_div / 100;
    goto extend_stage;
  }

  new_hit_cnt = queued_paths + unique_crashes;
  stage_finds[STAGE_EXTEND]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTEND] += stage_max;

out:  
  
  reset_streams_input(&g_stream_input, in_buf, in_len);
  
  //stream_snapshot_run_target();
  //extend_stream_discard();
  // add statics
  return;

}

static u8 stream_fuzz_one() {
  s32 len, fd, temp_len, i, j;
  u8  *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
  u64 havoc_queued,  orig_hit_cnt, new_hit_cnt;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;

  u8  ret_val = 1, doing_det = 0;

  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;


#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (queue_cur->depth > 1) return 1;

#else
  if (pending_favored) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
        UR(100) < SKIP_TO_NEW_PROB) return 1;

  } else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (queue_cycle > 1 && !queue_cur->was_fuzzed) {

      if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;

    } else {

      if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;

    }

  }
#endif /* ^IGNORE_FINDS */
if (not_on_tty) {
    ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
         current_entry, queued_paths, unique_crashes);
    fflush(stdout);
  }

  /* Map the test case into memory. */
  
  fd = open(queue_cur->fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", queue_cur->fname);

  len = queue_cur->len;
  
  orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if (orig_in == MAP_FAILED) PFATAL("Unable to mmap '%s'", queue_cur->fname);

  close(fd);

  /* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every
     single byte anyway, so it wouldn't give us any performance or memory usage
     benefits. */

  out_buf = ck_alloc_nozero(len);

  subseq_tmouts = 0;

  cur_depth = queue_cur->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/
  if (queue_cur->cal_failed) {

    u8 res = FAULT_TMOUT;

    if (queue_cur->cal_failed < CAL_CHANCES) {

      /* Reset exec_cksum to tell calibrate_case to re-execute the testcase
         avoiding the usage of an invalid trace_bits.
         For more info: https://github.com/AFLplusplus/AFLplusplus/pull/425 */

      queue_cur->exec_cksum = 0;

      res = calibrate_case(queue_cur, in_buf, queue_cycle - 1, 0);

      if (res == FAULT_ERROR)
        FATAL("Unable to execute target application");

    }

    if (stop_soon || res != crash_mode) {
      cur_skipped_paths++;
      goto abandon_entry;
    }

  }
  
  /************
   * TRIMMING *
   ************/

  if (!dumb_mode && !queue_cur->trim_done) {
    u8 res = trim_stream(queue_cur, in_buf);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    if (stop_soon) {
      cur_skipped_paths++;
      goto abandon_entry;
    }

    /* Don't retry trimming, even if it failed. */

    queue_cur->trim_done = 1;

    if (len != queue_cur->len) len = queue_cur->len;

  }
  
  /*********************
   * PERFORMANCE SCORE *
   *********************/

  orig_perf = perf_score = calculate_score(queue_cur);

  /* Skip right away if -d is given, if we have done deterministic fuzzing on
     this entry ourselves (was_fuzzed), or if it has gone through deterministic
     testing in earlier, resumed runs (passed_det). */

  if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
    goto havoc_stage;

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this master instance. */

  if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
    goto havoc_stage;

  doing_det = 1;


deterministic:
  /********************
   * FUZZ TAINT STAGE *
   ********************/
  
  if (cmplog_mode) {
    if (fuzz_taint_inference_stream_test(queue_cur, in_buf, len)) {
      goto abandon_entry;
    }
  }
  
  if (!queue_cur->passed_det) mark_as_det_done(queue_cur);
  
havoc_stage:  

  orig_hit_cnt = queued_paths + unique_crashes;
  
  /*******************************
   * FUZZ TAINT STAGE PER STREAM *
   *******************************/
   
  //if (cmplog_mode) {
  //  if (fuzz_taint_inference_stream(queue_cur, in_buf, len)) {
  //    goto abandon_entry;
  //  }
  //}

  /******************
   * INPUT TO STATE *
   ******************/
   
  //if (cmplog_mode && (its_mode || fix_checksum_mode)) {
//	  if (input_to_state_stage_stream(queue_cur, in_buf, len)) {
//		  goto abandon_entry;
//	  }
 // }

  /****************
   * RANDOM HAVOC *
   ****************/
  
  if(cmplog_mode && UR(10) < 8) {
    fti_mutate_stream(queue_cur, in_buf, len);
  }else{
    havoc_stream(queue_cur, in_buf, len);
    havoc_multistream(queue_cur, in_buf, len);
  }
  
  
  splice_stream(queue_cur, in_buf, len);
  /*************
   * EXTENSION *
   *************/

  extend_stream(queue_cur, in_buf, len);

  new_hit_cnt = queued_paths + unique_crashes;

abandon_entry:  

   
   return 0;
}

/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig) {

  stop_soon = 1; 

  exit(0);
  if (child_pid > 0) kill(child_pid, SIGKILL);

}


/* Handle skip request (SIGUSR1). */

static void handle_skipreq(int sig) {

  skip_requested = 1;

}

/* Handle timeout (SIGALRM). */

static void handle_timeout(int sig) {

  if (child_pid > 0) {

    child_timed_out = 1; 
    kill(child_pid, SIGKILL);

  } else if (child_pid == -1) {

    child_timed_out = 1; 

  }

}

/* Check if we're on TTY. */

static void check_if_tty(void) {

  struct winsize ws;

  if (getenv("AFL_NO_UI")) {
    OKF("Disabling the UI because AFL_NO_UI is set.");
    not_on_tty = 1;
    return;
  }

  if (ioctl(1, TIOCGWINSZ, &ws)) {

    if (errno == ENOTTY) {
      OKF("Looks like we're not running on a tty, so I'll be a bit less verbose.");
      not_on_tty = 1;
    }

    return;
  }

}


/* Check terminal dimensions after resize. */

static void check_term_size(void) {

  struct winsize ws;

  term_too_small = 0;

  if (ioctl(1, TIOCGWINSZ, &ws)) return;

  if (ws.ws_row == 0 && ws.ws_col == 0) return;
  if (ws.ws_row < 25 || ws.ws_col < 80) term_too_small = 1;

}






/* Prepare output directories and fds. */

EXP_ST void setup_dirs_fds(void) {

  u8* tmp;
  s32 fd;

  ACTF("Setting up output directories...");


  if (mkdir(out_dir, 0700)) {

    if (errno != EEXIST) PFATAL("Unable to create '%s'", out_dir);

    maybe_delete_out_dir();

  } else {

    if (in_place_resume)
      FATAL("Resume attempted but old output directory not found");

    out_dir_fd = open(out_dir, O_RDONLY);

#ifndef __sun

    if (out_dir_fd < 0 || flock(out_dir_fd, LOCK_EX | LOCK_NB))
      PFATAL("Unable to flock() output directory.");

#endif /* !__sun */

  }

  /* Queue directory for any starting & discovered paths. */

  tmp = alloc_printf("%s/queue", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);
  
  if (cmplog_mode) {
    tmp = alloc_printf("%s/taint", out_dir);
    if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
    ck_free(tmp);
  }

  /* Top-level directory for queue metadata used for session
     resume and related tasks. */

  tmp = alloc_printf("%s/queue/.state/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory for flagging queue entries that went through
     deterministic fuzzing in the past. */

  tmp = alloc_printf("%s/queue/.state/deterministic_done/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory with the auto-selected dictionary entries. */

  tmp = alloc_printf("%s/queue/.state/auto_extras/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* The set of paths currently deemed redundant. */

  tmp = alloc_printf("%s/queue/.state/redundant_edges/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* The set of paths showing variable behavior. */

  tmp = alloc_printf("%s/queue/.state/variable_behavior/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);


  /* All recorded crashes. */

  tmp = alloc_printf("%s/crashes", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All recorded hangs. */

  tmp = alloc_printf("%s/hangs", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Generally useful file descriptors. */

  dev_null_fd = open("/dev/null", O_RDWR);
  if (dev_null_fd < 0) PFATAL("Unable to open /dev/null");

  dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (dev_urandom_fd < 0) PFATAL("Unable to open /dev/urandom");

  /* Gnuplot output file. */

  tmp = alloc_printf("%s/plot_data", out_dir);
  fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  plot_file = fdopen(fd, "w");
  if (!plot_file) PFATAL("fdopen() failed");

  fprintf(plot_file, "# unix_time, cycles_done, cur_path, paths_total, "
                     "pending_total, pending_favs, map_size, unique_crashes, "
                     "unique_hangs, max_depth, execs_per_sec\n");
                     /* ignore errors */

}


/* Count the number of logical CPU cores. */

static void get_core_count(void) {

  u32 cur_runnable = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

  size_t s = sizeof(cpu_core_count);

  /* On *BSD systems, we can just use a sysctl to get the number of CPUs. */

#ifdef __APPLE__

  if (sysctlbyname("hw.logicalcpu", &cpu_core_count, &s, NULL, 0) < 0)
    return;

#else

  int s_name[2] = { CTL_HW, HW_NCPU };

  if (sysctl(s_name, 2, &cpu_core_count, &s, NULL, 0) < 0) return;

#endif /* ^__APPLE__ */

#else

#ifdef HAVE_AFFINITY

  cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN);

#else

  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];

  if (!f) return;

  while (fgets(tmp, sizeof(tmp), f))
    if (!strncmp(tmp, "cpu", 3) && isdigit(tmp[3])) cpu_core_count++;

  fclose(f);

#endif /* ^HAVE_AFFINITY */

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  if (cpu_core_count > 0) {

    cur_runnable = (u32)get_runnable_processes();

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

    /* Add ourselves, since the 1-minute average doesn't include that yet. */

    cur_runnable++;

#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

    OKF("You have %u CPU core%s and %u runnable tasks (utilization: %0.0f%%).",
        cpu_core_count, cpu_core_count > 1 ? "s" : "",
        cur_runnable, cur_runnable * 100.0 / cpu_core_count);

    if (cpu_core_count > 1) {

      if (cur_runnable > cpu_core_count * 1.5) {

        WARNF("System under apparent load, performance may be spotty.");

      } else if (cur_runnable + 1 <= cpu_core_count) {

        OKF("Try parallel jobs");
  
      }

    }

  } else {

    cpu_core_count = 0;
    WARNF("Unable to figure out the number of CPU cores.");

  }

}

/* Handle screen resize (SIGWINCH). */

static void handle_resize(int sig) {
  clear_screen = 1;
}

/* Set up signal handlers. More complicated that needs to be, because libc on
   Solaris doesn't resume interrupted reads(), sets SA_RESETHAND when you call
   siginterrupt(), and does other unnecessary things. */

EXP_ST void setup_signal_handlers(void) {

  struct sigaction sa;

  sa.sa_handler   = NULL;
  sa.sa_flags     = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Exec timeout notifications. */

  sa.sa_handler = handle_timeout;
  sigaction(SIGALRM, &sa, NULL);

  /* Window resize */

  sa.sa_handler = handle_resize;
  sigaction(SIGWINCH, &sa, NULL);

  /* SIGUSR1: skip entry */

  sa.sa_handler = handle_skipreq;
  sigaction(SIGUSR1, &sa, NULL);

  /* Things we don't care about. */

  sa.sa_handler = SIG_IGN;
  sigaction(SIGTSTP, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);

}

#ifndef AFL_LIB




static void setup_shm(uc_engine *uc) {
  // Use local backup bitmap to run without AFL

  if (!in_bitmap) memset(virgin_bits, 255, MAP_SIZE);
  memset(virgin_tmout, 255, MAP_SIZE);
  memset(virgin_crash, 255, MAP_SIZE);  

  trace_bits = fuzz_area_initial;
  stream_bits = &stream_map_initial; 
  cmplog_ptr = &fuzz_cmp_map_initial;
  
  fuzz_area_ptr_backup = fuzz_area_initial_backup;
  fuzz_area_ptr = fuzz_area_initial;
  stream_map = &stream_map_initial;
  fuzz_cmp_map = &fuzz_cmp_map_initial;

  uc_fuzzer_init_cmplog(uc, &fuzz_cmp_map->headers, &fuzz_cmp_map->log,  CMP_MAP_W, CMP_MAP_H, cmplog_mode);
  uc_fuzzer_init_cov(uc, fuzz_area_ptr, MAP_SIZE, cov_mode);
  
  atexit(remove_shm);
}

/* Main entry point */
uc_err fuzzer_main(uc_engine *uc, char *p_input_path, char *p_output_path, uint32_t tmout) {

  s32 opt;
  u64 prev_queued = 0;
  u32 seek_to;

  struct timeval tv;
  struct timezone tz;

#ifdef _MODEL_DEBUG
  for(int i = 0; i < passthrough_model_size; ++i) {
      printf("passthrogh:%08lx %08lx\n",passthrough_model[i].pc,passthrough_model[i].start_addr);
  }
  
  
  
  for(int i = 0; i < constant_model_size; ++i) {
      printf("const:%08lx %08lx %08lx\n",constant_model[i].pc,constant_model[i].start_addr,constant_model[i].val);
  }
  
  for(int i = 0; i < value_set_model_size; ++i) {
      printf("value set:%08lx %08lx %08lx",value_set_model[i].pc,value_set_model[i].start_addr,value_set_model[i].num_vals);
      for(int j=0;j<value_set_model[i].num_vals;++j){
        printf(" %08lx",value_set_model[i].values[j]);
      }
      printf("\n");
  }
  
  for(int i = 0; i < bitextract_model_size; ++i) {
      printf("bitextract:%08lx %08lx %08lx\n",bitextract_model[i].pc,bitextract_model[i].start_addr,bitextract_model[i].mask);
    
  }
#endif

  SAYF(cCYA "afl-fuzz " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

  gettimeofday(&tv, &tz);
  srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());

  in_dir = p_input_path;
  out_dir = p_output_path;
  exec_tmout = tmout;
  timeout_given = 1;
  g_uc = uc;

  setup_signal_handlers();

  if (!strcmp(in_dir, out_dir))
    FATAL("Input and output directories can't be the same");

  use_banner = "Fuzzware";
  check_if_tty();

  get_core_count();

#ifdef HAVE_AFFINITY
  bind_to_free_cpu();
#endif /* HAVE_AFFINITY */
  
  setup_shm(uc);
  
  init_count_class16();
  
  init_cmp_info(&g_cmp_info);
  
  init_schedule_info();
  
  setup_dirs_fds();
  
  read_testcases();
  
  load_auto();

  pivot_inputs();


  start_time = get_cur_time();
  snapshot_initial(uc);

  perform_dry_run();

  cull_queue();

  show_init_stats();

  seek_to = find_start_position();

  write_stats_file(0, 0, 0);
  save_auto();

  if (stop_soon) goto stop_fuzzing;

  /* Woop woop woop */

  if (!not_on_tty) {
    sleep(4);
    start_time += 4000;
    if (stop_soon) goto stop_fuzzing;
  }
  
  while (1) {

    u8 skipped_fuzz;
    
    cull_queue();

    if (!queue_cur) {

      queue_cycle++;
      current_entry     = 0;
      cur_skipped_paths = 0;
      queue_cur         = queue;

      while (seek_to) {
        current_entry++;
        seek_to--;
        queue_cur = queue_cur->next;
      }
      
      show_stats();
      
      if (not_on_tty) {
        ACTF("Entering queue cycle %llu.", queue_cycle);
        fflush(stdout);
      }

      /* If we had a full queue cycle with no new finds, try
         recombination strategies next. */

      if (queued_paths == prev_queued) {

        if (use_splicing) cycles_wo_finds++; else use_splicing = 1;

      } else cycles_wo_finds = 0;

      prev_queued = queued_paths;


    }

    skipped_fuzz = stream_fuzz_one();
    

    if (stop_soon) break;

    queue_cur = queue_cur->next;
    current_entry++;

  }

  if (queue_cur) show_stats();


  write_bitmap();
  write_stats_file(0, 0, 0);
  save_auto();

stop_fuzzing:

  SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
       stop_soon == 2 ? "programmatically" : "by user");

  /* Running for more than 30 minutes but still doing first cycle? */

  if (queue_cycle == 1 && get_cur_time() - start_time > 30 * 60 * 1000) {

    SAYF("\n" cYEL "[!] " cRST
           "Stopped during the first cycle, results may be incomplete.\n"
           "    (For info on resuming.)\n");

  }

  fclose(plot_file);
  destroy_queue();
  destroy_extras();

  alloc_report();

  OKF("We're done here. Have a nice day!\n");

  return UC_ERR_OK;
}

#endif /* !AFL_LIB */
