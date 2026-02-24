#ifndef INTERRUPT_CONTROLLER_H
#define INTERRUPT_CONTROLLER_H

//#define DEBUG_IC

#include <string.h>
#include <assert.h>

#include "unicorn/unicorn.h"
#include "../state_snapshotting.h"
#include "../uc_snapshot.h"
// Interrupt 

#define IC_BASE         0x80000090
// Interrupt Mask and Priority Register - ITMP
#define IC_ITMP         0x80000090
// Interrupt Pending Register - ITP
#define IC_ITP          0x80000094
// Interrupt Force Register - ITF
#define IC_ITF          0x80000098
// Interrupt Clear Register - ITC
#define IC_ITC          0x8000009C
#define IC_END          0x8000009C

#define L_MASK_RESERVED (1 << 0)
#define L_MASK_AMBA     (1 << 1)
#define L_MASK_UART2    (1 << 2)
#define L_MASK_UART1    (1 << 3)
#define L_MASK_IO0      (1 << 4)
#define L_MASK_IO1      (1 << 5)
#define L_MASK_IO2      (1 << 6)
#define L_MASK_IO3      (1 << 7)
#define L_MASK_TIMER1   (1 << 8)
#define L_MASK_TIMER2   (1 << 9)
#define L_MASK_IO4      (1 << 10)
#define L_MASK_DSU      (1 << 11)
#define L_MASK_IO5      (1 << 12)
#define L_MASK_IO6      (1 << 13)
#define L_MASK_PCI      (1 << 14)
#define L_MASK_IO7      (1 << 15)

#define H_MASK_RESERVED (1 << 16)
#define H_MASK_AMBA     (1 << 17)
#define H_MASK_UART2    (1 << 18)
#define H_MASK_UART1    (1 << 19)
#define H_MASK_IO0      (1 << 20)
#define H_MASK_IO1      (1 << 21)
#define H_MASK_IO2      (1 << 22)
#define H_MASK_IO3      (1 << 23)
#define H_MASK_TIMER1   (1 << 24)
#define H_MASK_TIMER2   (1 << 25)
#define H_MASK_IO4      (1 << 26)
#define H_MASK_DSU      (1 << 27)
#define H_MASK_IO5      (1 << 28)
#define H_MASK_IO6      (1 << 29)
#define H_MASK_PCI      (1 << 30)
#define H_MASK_IO7      (1 << 31)

#define TIMER1_IRQNO    0x8
#define TIMER2_IRQNO    0x9

#define IC_NUM_SUPPORTED_INTERRUPTS 16
#define GET_EXCEPTION_NO(irqno)     (irqno + 16)


struct IC {
    

    uint8_t InterruptEnabled[IC_NUM_SUPPORTED_INTERRUPTS];
    uint8_t InterruptActive[IC_NUM_SUPPORTED_INTERRUPTS];
    uint8_t InterruptPending[IC_NUM_SUPPORTED_INTERRUPTS];
    // We keep track of enabled interrupts for fuzzing
    int num_enabled;
    uint8_t enabled_irqs[IC_NUM_SUPPORTED_INTERRUPTS];
    int interrupt_count;
};


uc_err sparc_init_nvic(uc_engine *uc, uint32_t p_interrupt_limit, uint32_t num_disabled_interrupts, uint32_t *disabled_interrupts);

// Added for fuzzing purposes
uint16_t sparc_get_num_enabled();
uint8_t sparc_nth_enabled_irq_num(uint8_t n);

// TODO: remove backward-compatible interface
void sparc_ic_set_pending(uc_engine *uc, uint32_t num, int skip_current_instruction);

#endif
