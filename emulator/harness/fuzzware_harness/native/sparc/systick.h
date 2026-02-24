#ifndef SYSTICK_H
#define SYSTICK_H

#include "unicorn/unicorn.h"
#include "../timer.h"
#include "interrupt_controller.h"

//#define DEBUG_SYSTICK

#define TIMER1_IRQ 8
#define TIMER2_IRQ 9

#define SYST_CSR_RESET_VAL 0
#define SYSTICK_RELOAD_VAL_NONE 0

#define MASK_TIMER_LD 0x4
#define MASK_TIMER_RL 0x2
#define MASK_TIMER_EN 0x1

#define MASK_SC_CNT   0x3FF
#define MASK_SC_RV    0x3FF

#define SPARC_SYSTICK_BASE  0x80000040
#define TIMC1         0x80000040   // Timer 1 Counter Register
#define TIMR1         0x80000044   // Timer 1 Reload Register 
#define TIMCTR1       0x80000048   // Timer 1 Control Register
#define WDG           0x8000004C   // Watchdog Register

#define TIMC2         0x80000050   // Timer 2 Counter Register
#define TIMR2         0x80000054   // Timer 2 Reload Register
#define TIMCTR2       0x80000058   // Timer 2 Control Register

#define SCAC          0x80000060   // Prescaler Counter Register
#define SCAR          0x80000064   // Prescaler Reload Register
#define SPARC_SYSTICK_END  0x80000064

// Fuzzware specific constants
// base 20CPI 25 ins per block
#define SPARC_SYSTICK_TICKS_BB 500
// 50 MHZ base 20CPI 25 ins per block 10us
#define SPARC_SYSTICK_TICKS_10_US 500

struct SysTick {
    /* 
     * We treat SysTick as a timer. From that abstraction we will also query
     * data such as reload values.
     */
    int timer_ind1;
    int timer_ind2;
    // We have some extra information that is SysTick specific
    int csr1;
    int csr2;
    uint32_t reload_val1;
    uint32_t reload_val2;
    uint32_t scar;
    
};

uc_err sparc_init_systick(uc_engine *uc, uint32_t reload_val);

#endif
