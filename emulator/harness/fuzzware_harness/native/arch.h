#ifndef ARCH_H
#define ARCH_H

#include "unicorn/unicorn.h"

extern uc_arch g_arch;

uc_err init_arch(uc_engine *uc , uc_arch arch);
// interrupt
uc_err arch_init_nvic(uc_engine *uc, uint32_t vtor, uint32_t num_irq, uint32_t interrupt_limit, uint32_t num_disabled_interrupts, uint32_t *disabled_interrupts);
void arch_ic_set_pending(uc_engine *uc, uint32_t num, int skip_current_instruction);
// Added for fuzzing purposes
uint16_t arch_get_num_enabled();
uint8_t arch_nth_enabled_irq_num(uint8_t n);


// systick
uc_err arch_init_systick(uc_engine *uc, uint32_t reload_val);

// other
uc_err arch_get_pc(uc_engine *uc, void *value);
uc_err arch_get_sp(uc_engine *uc, void *value);
#endif
