#include "interrupt_controller.h"
#include "../fuzz.h"

//#define FERMCOV 1
// 1. Static (after initialization) configs
static uc_hook hook_mmio_write_handle = -1, 
     hook_mmio_read_handle = -1, hook_ta_handle = -1;
static uint32_t interrupt_limit = 0;
static uint32_t num_config_disabled_interrupts = 0;
static uint32_t *config_disabled_interrupts = NULL;

// 2. Transient variables (not required to be included in state restore)

// 3. Dynamic State (required for state restore)
struct IC ic __attribute__ ((aligned (64)));

#ifdef FERMCOV 
struct fermcov {
    unsigned long excp_prev_loc;
    uint64_t excp_pc; 
};

uc_hook exception_return_handle = -1;
struct fermcov fermcov_context = {
    .excp_prev_loc = 0,
    .excp_pc = 0,
};

void hook_block_exception_return(uc_engine *uc, uint64_t address, uint32_t size, void* user_data) {
    if(fermcov_context.excp_pc != 0 && fermcov_context.excp_pc == address) {
        if (fermcov_context.excp_prev_loc) {
            uc_fuzzer_set_cov_prev_loc(uc, &fermcov_context.excp_prev_loc);
            fermcov_context.excp_prev_loc = 0;
        }
        fermcov_context.excp_pc = 0;
    }
}
#endif

// Forward declarations
static void ExceptionEntry(uc_engine *uc, uint32_t into, bool skip_instruction);


static bool is_disabled_by_config(uint32_t exception_no) {
    for(int i = 0; i < num_config_disabled_interrupts; ++i) {
        if(config_disabled_interrupts[i] == exception_no) {
            return true;
        }
    }

    return false;
}

static void pend_interrupt(uc_engine *uc, int interrupt_no) {
    #ifdef DEBUG_IC
    printf("[pend_interrupt] interrupt_no=%d\n", interrupt_no);
    fflush(stdout);
    #endif
    if(ic.InterruptEnabled[interrupt_no] == 1) {
        ic.InterruptPending[interrupt_no] = 1;
    }
}

static void clear_pend_interrupt(uc_engine *uc, int interrupt_no) {
    if(ic.InterruptPending[interrupt_no] == 1) {
        ic.InterruptPending[interrupt_no] = 0;
    }
}


static void maybe_activate(uc_engine *uc, bool skip_instruction) {
    #ifdef DEBUG_IC
    printf("[maybe_activate] skip_instruction: %d\n", skip_instruction);
    #endif
    
    int interrupt_no = IC_NUM_SUPPORTED_INTERRUPTS -1;
    int psr,pil;
    uc_reg_read(uc, UC_SPARC_REG_PSR, &psr);
    pil = (psr & 0xfff) >> 8;
    
    // higher interrupt has higher prio
    while (interrupt_no > 0) {
        if (ic.InterruptEnabled[interrupt_no] && ic.InterruptPending[interrupt_no]) {
            break;
        }
        interrupt_no--;
    }
    
    if (interrupt_no && (interrupt_no>=pil)) {
        
        ExceptionEntry(uc, GET_EXCEPTION_NO(interrupt_no),skip_instruction);
    }
    clear_pend_interrupt(uc, interrupt_no);
    
}

// SPARC 
static void hook_ic_mmio_read(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data) {
    #ifdef DEBUG_IC
    printf("[IC] hook_nvic_mmio_read: Read from %08lx, value: %08lx\n", addr, value);
    fflush(stdout);
    #endif
}

static void hook_ic_mmio_write(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data) {

    #ifdef DEBUG_IC
    printf("[IC] hook_nvic_mmio_write: Write to %08lx, value: %08lx\n", addr, value);
    fflush(stdout);
    #endif

    // IC register write
    if (addr == IC_ITMP) {
        ic.num_enabled = 0;
        for (int i=0; i < IC_NUM_SUPPORTED_INTERRUPTS;i++) {
            if (value & (1 << i) && !is_disabled_by_config(GET_EXCEPTION_NO(i))) {
                ic.InterruptEnabled[i] = 1;
                ic.enabled_irqs[ic.num_enabled++] = i;
                
                #ifdef DEBUG_IC
                printf("[IC] add irq: %02x\n",GET_EXCEPTION_NO(i));
                fflush(stdout);
                #endif
            }else{
                ic.InterruptEnabled[i] = 0;
                
                #ifdef DEBUG_IC
                printf("[IC] remove irq: %02x\n",GET_EXCEPTION_NO(i));
                fflush(stdout);
                #endif
            }
        }
    }else if (addr == IC_ITC) {
        for (int i=0; i < IC_NUM_SUPPORTED_INTERRUPTS;i++) {
            if (value & (1 << i)) {
                clear_pend_interrupt(uc, i);
            }
        }
    }
    // ITP???
    
}


static void handler_ta(uc_engine *uc, uint32_t intno, void *user_data) {
    #ifdef DEBUG_IC
    uint32_t pc;
    uc_reg_read(uc, UC_SPARC_REG_PC, &pc);
    printf("[TA HOOK %08x] native TA hook called, intno: %d\n", pc, intno); fflush(stdout);
    #endif
    
    if (intno == 0x00 || intno == 0x02 || intno == 0x2a ) {
        // reset, illegal_instruction , division by zero
        force_crash(uc, UC_ERR_INSN_INVALID);
    }

    // handle exception
    ExceptionEntry(uc, intno, true);
    
}

// SPARC IC
static void ExceptionEntry(uc_engine *uc, uint32_t intno, bool skip_instruction) {

    #ifdef DEBUG_IC
    printf("[IC] ExceptionEntry(intno=%d,skip_instruction=%d)\n",intno,skip_instruction); fflush(stdout);
    #endif

    if (intno != GET_EXCEPTION_NO(TIMER1_IRQNO) && intno != GET_EXCEPTION_NO(TIMER2_IRQNO)) {
        if (++ic.interrupt_count >= interrupt_limit) {
            if(do_print_exit_info) {
                printf("Interrupt activation limit of %d reached, exiting\n", interrupt_limit); fflush(stdout);
            }

            do_exit(uc, UC_ERR_OK); 
            return;
        }
    }
    // we may regard some exception as error and force crash!!!
    
    // save context
    uint32_t psr, cwp, psrs, psrps, tbr, pc, npc, tba, tt, l1,l2,et;
    
    uc_reg_read(uc, UC_SPARC_REG_PSR, &psr);
    uc_reg_read(uc, UC_SPARC_REG_TBR, &tbr);
    uc_reg_read(uc, UC_SPARC_REG_PC, &pc);
    uc_reg_read(uc, UC_SPARC_REG_NPC, &npc);

    #ifdef DEBUG_IC
    printf("[IC] ExceptionEntry(pc:%08x npc:%08x)\n",pc,npc);
    #endif
    
    // first step: update psr
    cwp = psr & 0x7;
    psrs = psr & (1 << 7);
    et = psr & (1 << 5);
    if (et == 0){
        return;
        // may crash?
    }

#ifdef FERMCOV
    uc_fuzzer_get_cov_prev_loc(uc, &fermcov_context.excp_prev_loc);
    unsigned long tmp = 0;
    uc_fuzzer_set_cov_prev_loc(uc, &tmp);
    fermcov_context.excp_pc = pc;
#endif

    // disable traps, set PSR.ET = 0
    // copy PSR.S to PSR.PS
    // cwp is decremented by one
    // set PSR.S = 1
    psrps = psrs >> 1;
    cwp = (cwp - 1) & 0x7;
    psrs = (1 << 7);
    psr = (psr & 0xffffff00) | psrps | psrs | cwp;
    
    uc_reg_write(uc, UC_SPARC_REG_PSR, &psr);
    
    // second step: update l1,l2
    l1 = pc;
    l2 = npc;

    uc_reg_write(uc, UC_SPARC_REG_L1, &l1);
    uc_reg_write(uc, UC_SPARC_REG_L2, &l2);
    
    // third step: update tbr
    tba = tbr & 0xfffff000;
    tt = intno << 4;
    tbr = tba | tt;
    
    uc_reg_write(uc, UC_SPARC_REG_TBR, &tbr);
    
    // forth step: update pc
    pc = tbr;
    uc_reg_write(uc, UC_SPARC_REG_PC, &pc);
    
    

    #ifdef DEBUG_IC
    puts("************ POST ExceptionEntry");
    #endif
}


static void *ic_take_snapshot(uc_engine *uc) {
    size_t size = sizeof(ic);

    // IC snapshot: save the sysreg mem page
#ifdef FERMCOV
    char *result = malloc(size + PAGE_SIZE + sizeof(fermcov_context));
#else
    char *result = malloc(size + PAGE_SIZE);
#endif
    memcpy(result, &ic, size);
    //uc_mem_read(uc, IC_BASE, result + size, PAGE_SIZE);
#ifdef FERMCOV
    memcpy(result + size + PAGE_SIZE, &fermcov_context, sizeof(fermcov_context));
#endif
    return result;
}

static void ic_restore_snapshot(uc_engine *uc, void *snapshot) {
    // Restore the ic
    memcpy(&ic, snapshot, sizeof(ic));
    // Restore the sysreg mem page
    //uc_mem_write(uc, IC_BASE, ((char *) snapshot) + sizeof(ic), PAGE_SIZE);
#ifdef FERMCOV
    memcpy(&fermcov_context, ((char *) snapshot) + sizeof(ic) + PAGE_SIZE, sizeof(fermcov_context));
#endif
}

static void ic_discard_snapshot(uc_engine *uc, void *snapshot) {
    free(snapshot);
}

uc_err sparc_init_nvic(uc_engine *uc, uint32_t p_interrupt_limit, uint32_t num_disabled_interrupts, uint32_t *disabled_interrupts) {
    #ifdef DEBUG_IC
    printf("[IC] init_nvic \n"); fflush(stdout);
    #endif
    
    memset(&ic, 0, sizeof(struct IC));
    
    ic.interrupt_count = 0;
    interrupt_limit = p_interrupt_limit;

    num_config_disabled_interrupts = num_disabled_interrupts;
    config_disabled_interrupts = calloc(num_disabled_interrupts, sizeof(*disabled_interrupts));
    
    for(uint32_t i = 0; i < num_disabled_interrupts; ++i) {
        config_disabled_interrupts[i] = GET_EXCEPTION_NO(disabled_interrupts[i]);
    }
    
    // 3. nvic MMIO range read/write handler
    uc_hook_add(uc, &hook_mmio_write_handle, UC_HOOK_MEM_WRITE, hook_ic_mmio_write, NULL, IC_BASE, IC_END);
    uc_hook_add(uc, &hook_mmio_read_handle, UC_HOOK_MEM_READ, hook_ic_mmio_read, NULL, IC_BASE, IC_END);

    uc_hook_add(uc, &hook_ta_handle, UC_HOOK_INTR, handler_ta, NULL, 1, 0);

#ifdef FERMCOV
    uc_hook_add(uc, &exception_return_handle, UC_HOOK_BLOCK_UNCONDITIONAL, (void*) hook_block_exception_return, NULL, 1, 0);
#endif

    subscribe_state_snapshotting(uc, ic_take_snapshot, ic_restore_snapshot, ic_discard_snapshot);

  
    return UC_ERR_OK;
}

uint16_t sparc_get_num_enabled() {
    return ic.num_enabled;
}

uint8_t sparc_nth_enabled_irq_num(uint8_t n) {
    return ic.enabled_irqs[n % ic.num_enabled];
}

void sparc_ic_set_pending(uc_engine *uc, uint32_t num, int delay_activation) {
    pend_interrupt(uc, num);
    maybe_activate(uc, false);
}
