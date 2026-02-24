#include "arch.h"
#include "mmio.h"
#include "uc_snapshot.h"

// SPARC
#include "sparc/systick.h"
uint64_t sparc_ignored_addresses[] = {
    // interrupt Registers
    0x80000090,
    0x80000094,
    0x80000098,
    0x8000009c,
    // sys timer Registers
    0x80000040,
    0x80000044,
    0x80000048,
    0x8000004c,
    0x80000050,
    0x80000054,
    0x80000058,
    0x80000060,
    0x80000064     
};

uint32_t sparc_ignored_address_pcs[] = {
    MMIO_HOOK_PC_ALL_ACCESS_SITES,
    MMIO_HOOK_PC_ALL_ACCESS_SITES,
    MMIO_HOOK_PC_ALL_ACCESS_SITES,
    MMIO_HOOK_PC_ALL_ACCESS_SITES,
    MMIO_HOOK_PC_ALL_ACCESS_SITES,
    MMIO_HOOK_PC_ALL_ACCESS_SITES,
    MMIO_HOOK_PC_ALL_ACCESS_SITES,
    MMIO_HOOK_PC_ALL_ACCESS_SITES,
    MMIO_HOOK_PC_ALL_ACCESS_SITES,
    MMIO_HOOK_PC_ALL_ACCESS_SITES,
    MMIO_HOOK_PC_ALL_ACCESS_SITES,
    MMIO_HOOK_PC_ALL_ACCESS_SITES,
    MMIO_HOOK_PC_ALL_ACCESS_SITES
};

// ARM
#include "arm/cortexm_nvic.h"
extern uc_err arm_init_systick(uc_engine *uc, uint32_t reload_val);
#define CPUID_ADDR 0xE000ED00
const int CPUID_CORTEX_M4=0x410fc240;
const int CPUID_CORTEX_M3=0x410fc230;
uint32_t arm_num_ignored_state_restore_mem_addresses = 2;
uint64_t arm_ignored_state_restore_mem_addresses[MAX_IGNORED_STATE_RESTORE_MEM_ADDRESSES] = {
    // Ret mask
    0xfffff000,
    // Sysregs
    0xe0000000
};



uc_arch g_arch = UC_ARCH_MAX;

uc_err init_arch(uc_engine *uc , uc_arch arch) {
    if (arch <=0 || arch>= UC_ARCH_MAX) {
        return UC_ERR_ARCH;
    }
    g_arch = arch;
    
    uc_err ret = UC_ERR_OK;
    uint32_t psr = 0x80;
    switch(g_arch) {
    case UC_ARCH_SPARC:
        // step 1: we set psr to supervisor mode  
        ret = uc_reg_write(uc, UC_SPARC_REG_PSR, &psr);
        if (ret != UC_ERR_OK) 
            return ret;
        
        // step 2: set ignore mmio
        ret = set_ignored_mmio_addresses(uc, sparc_ignored_addresses, sparc_ignored_address_pcs, sizeof(sparc_ignored_addresses)/sizeof(sparc_ignored_addresses[0]));
        if (ret != UC_ERR_OK) 
            return ret;
            
        // step 3: set ignore restore memory
        // for sparc, we don't need it now.
        break;
     
    case UC_ARCH_ARM:
        // step 1: set cpu id
        ret = uc_mem_write(uc, CPUID_ADDR, &CPUID_CORTEX_M4, sizeof(CPUID_CORTEX_M4));
        if (ret != UC_ERR_OK) 
            return ret;
        // step 2: set ignore mmio
        // for arm, we don't need it now.
        
        // step 3: set ignore restore memory
        ret = set_ignored_state_restore_addresses(arm_ignored_state_restore_mem_addresses, arm_num_ignored_state_restore_mem_addresses);
        if (ret != UC_ERR_OK) 
            return ret;
        break;
    default:
        printf("Not support arch at: %s\n",__func__);
        return UC_ERR_ARCH;
        break;
    }
    
    return UC_ERR_OK;
};

uc_err arch_init_nvic(uc_engine *uc, uint32_t vtor, uint32_t num_irq, uint32_t interrupt_limit, uint32_t num_disabled_interrupts, uint32_t *disabled_interrupts) {
    switch(g_arch) {
    case UC_ARCH_SPARC:
        return sparc_init_nvic(uc, interrupt_limit, num_disabled_interrupts, disabled_interrupts);
        break;
    case UC_ARCH_ARM:
        return arm_init_nvic(uc, vtor, num_irq, interrupt_limit, num_disabled_interrupts, disabled_interrupts);
        break;
    default:
        printf("Not support arch at: %s\n",__func__);
        break;
    }
    return UC_ERR_ARCH;
}

void arch_ic_set_pending(uc_engine *uc, uint32_t num, int skip_current_instruction) {   
    switch(g_arch) {
    case UC_ARCH_SPARC:
        sparc_ic_set_pending(uc, num, skip_current_instruction);
        break;
    case UC_ARCH_ARM:
        arm_nvic_set_pending(uc, num, skip_current_instruction);
        break;
    default:
        printf("Not support arch at: %s\n",__func__);
        break;
    }
}

uint16_t arch_get_num_enabled() {
    switch(g_arch) {
    case UC_ARCH_SPARC:
        return sparc_get_num_enabled();
        break;
    case UC_ARCH_ARM:
        return arm_get_num_enabled();
        break;
    default:
        printf("Not support arch at: %s\n",__func__);
        break;
    }
    return 0;
};
uint8_t arch_nth_enabled_irq_num(uint8_t n){
    switch(g_arch) {
    case UC_ARCH_SPARC:
        return sparc_nth_enabled_irq_num(n);
        break;
    case UC_ARCH_ARM:
        return arm_nth_enabled_irq_num(n);
        break;
    default:
        printf("Not support arch at: %s\n",__func__);
        break;
    }
    return 0;
};


uc_err arch_get_pc(uc_engine *uc, void *value) {
    switch(g_arch) {
    case UC_ARCH_SPARC:
        return uc_reg_read(uc, UC_SPARC_REG_PC, value);
        break;
    case UC_ARCH_ARM:
        return uc_reg_read(uc, UC_ARM_REG_PC, value);
        break;
    default:
        printf("Not support arch at: %s\n",__func__);
        break;
    }
    return UC_ERR_ARCH;
}

uc_err arch_get_sp(uc_engine *uc, void *value) {
    switch(g_arch) {
    case UC_ARCH_SPARC:
        return uc_reg_read(uc, UC_SPARC_REG_SP, value);
        break;
    case UC_ARCH_ARM:
        return uc_reg_read(uc, UC_ARM_REG_SP, value);
        break;
    default:
        printf("Not support arch at: %s\n",__func__);
        break;
    }
    return UC_ERR_ARCH;
}

uc_err arch_init_systick(uc_engine *uc, uint32_t reload_val) {
    switch(g_arch) {
    case UC_ARCH_SPARC:
        return sparc_init_systick(uc, reload_val);
        break;
    case UC_ARCH_ARM:
        return arm_init_systick(uc, reload_val);
        break;
    default:
        printf("Not support arch at: %s\n",__func__);
        break;
    }
    return UC_ERR_ARCH;
}

