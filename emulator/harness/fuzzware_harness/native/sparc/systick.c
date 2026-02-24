#include "systick.h"

// 0. Constants
//static uint32_t calibration_val = SYSTICK_TICKS_10_MS;

// 1. Static (after initialization) configs
static uc_hook hook_systick_write_handle = -1, hook_systick_read_handle = -1;
static int systick_used = false;
static uint32_t user_configured_reload_val = SYSTICK_RELOAD_VAL_NONE;

// 3. Dynamic State (required for state restore)
static struct SysTick systick = {
    .timer_ind1 = MAX_TIMERS,
    .timer_ind2 = MAX_TIMERS,
    .csr1 = 0,
    .csr2 = 0,
    .reload_val1 = 0,
    .reload_val2 = 0,
    .scar = 0
};

static void hook_syst_mmio_read(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data) {
    #ifdef DEBUG_SYSTICK
    printf("[SysTick] hook_syst_mmio_read: Read from %08lx, value: %08lx\n", addr, value);
    fflush(stdout);
    #endif
}

static void hook_syst_mmio_write(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data) {

    #ifdef DEBUG_SYSTICK
    printf("[SysTick] hook_syst_mmio_write: Write to %08lx, value: %08lx\n", addr, value);
    fflush(stdout);
    #endif

    uint32_t ld,rl,en;
    int64_t csr = value;
    ld = csr | MASK_TIMER_LD;
    rl = csr | MASK_TIMER_RL;
    en = csr | MASK_TIMER_EN;
    if ( addr == TIMCTR1) {
        systick.csr1 = csr;
        if (ld || rl) {
            set_timer_reload_val(systick.timer_ind1, 1 + systick.reload_val1 * (systick.scar + 1) / SPARC_SYSTICK_TICKS_BB);
        }
        if (en) {
            reload_timer(systick.timer_ind1);
            start_timer(uc, systick.timer_ind1);
        }else{
            stop_timer(uc, systick.timer_ind1);
        }

       
    }else if (addr == TIMCTR2) {
        systick.csr2 = csr;
        if (ld || rl) {
            set_timer_reload_val(systick.timer_ind2, 1 + systick.reload_val2 * (systick.scar + 1) / SPARC_SYSTICK_TICKS_BB);
        }
        if (en) {
            reload_timer(systick.timer_ind2);
            start_timer(uc, systick.timer_ind2);
        }else{
            stop_timer(uc, systick.timer_ind2);
        }
        
    }else if(addr == TIMR1) {
        systick.reload_val1 = value;
        set_timer_reload_val(systick.timer_ind1, 1 + systick.reload_val1 * (systick.scar + 1) / SPARC_SYSTICK_TICKS_BB);
    }else if(addr == TIMR2) {
        systick.reload_val2 = value;
        set_timer_reload_val(systick.timer_ind2, 1 + systick.reload_val2 * (systick.scar + 1) / SPARC_SYSTICK_TICKS_BB);
    }else if(addr == SCAR) {
        systick.scar = value;
        set_timer_reload_val(systick.timer_ind1, 1 + systick.reload_val1 * (systick.scar + 1) / SPARC_SYSTICK_TICKS_BB);
        set_timer_reload_val(systick.timer_ind2, 1 + systick.reload_val2 * (systick.scar + 1) / SPARC_SYSTICK_TICKS_BB);
    }
    
}

/*
 * https://developer.arm.com/documentation/dui0552/a/cortex-m3-peripherals/system-timer--systick/systick-control-and-status-register?lang=en
 * 
 * When ENABLE is set to 1, the counter loads the RELOAD value from the SYST_RVR register and then counts down.
 * On reaching 0, it sets the COUNTFLAG to 1 and optionally asserts the SysTick depending on the value of TICKINT.
 * It then loads the RELOAD value again, and begins counting.
 **/
static void systick_trigger_callback (uc_engine *uc, uint32_t id, void *user_data) {
    #ifdef DEBUG_SYSTICK
    printf("[SYSTICK] trigger callback called for timer id=%d\n", id);
    #endif

    uint32_t rl,en;
    uint32_t csr, reload_val;

    if (id == systick.timer_ind1) {
        sparc_ic_set_pending(uc, TIMER1_IRQ, false);
        csr = systick.csr1;
        reload_val = systick.reload_val1;
  
        rl = csr | MASK_TIMER_RL;
        en = csr | MASK_TIMER_EN;
        if (en && rl) {
            set_timer_reload_val(systick.timer_ind1, reload_val);
        }else{
            stop_timer(uc, systick.timer_ind1);
        }
       
    } else if (id == systick.timer_ind2) {
        sparc_ic_set_pending(uc, TIMER2_IRQ, false);
        csr = systick.csr2;
        reload_val = systick.reload_val2;
  
        rl = csr | MASK_TIMER_RL;
        en = csr | MASK_TIMER_EN;
        if (en && rl) {
            set_timer_reload_val(systick.timer_ind2, reload_val);
        }else{
            stop_timer(uc, systick.timer_ind2);
        }
    
    
    }
}

static void *systick_take_snapshot(uc_engine *uc) {
    size_t size = sizeof(systick);
    void *result = malloc(size);
    memcpy(result, &systick, size);
    return result;
}

static void systick_restore_snapshot(uc_engine *uc, void *snapshot) {
    memcpy(&systick, snapshot, sizeof(systick));
}

static void systick_discard_snapshot(uc_engine *uc, void *snapshot) {
    free(snapshot);
}

uc_err sparc_init_systick(uc_engine *uc, uint32_t reload_val) {
    systick_used = true;

    systick.csr1 = SYST_CSR_RESET_VAL;
    systick.csr2 = SYST_CSR_RESET_VAL;


    systick.timer_ind1 = add_timer(0, systick_trigger_callback, NULL, TIMER_IRQ_NOT_USED);
    systick.timer_ind2 = add_timer(0, systick_trigger_callback, NULL, TIMER_IRQ_NOT_USED);

    user_configured_reload_val = reload_val;
    systick.reload_val1 = user_configured_reload_val;
    systick.reload_val2 = user_configured_reload_val;
    #ifdef DEBUG_SYSTICK
    printf("[SYSTICK] Added timer with id %d %d\n", systick.timer_ind1, systick.timer_ind2);
    #endif
    stop_timer(uc, systick.timer_ind1);
    stop_timer(uc, systick.timer_ind2);
    uc_hook_add(uc, &hook_systick_write_handle, UC_HOOK_MEM_WRITE, hook_syst_mmio_write, NULL, SPARC_SYSTICK_BASE, SPARC_SYSTICK_END);
    uc_hook_add(uc, &hook_systick_read_handle, UC_HOOK_MEM_READ, hook_syst_mmio_read, NULL, SPARC_SYSTICK_BASE, SPARC_SYSTICK_END);
    subscribe_state_snapshotting(uc, systick_take_snapshot, systick_restore_snapshot, systick_discard_snapshot);

    return UC_ERR_OK;
}
