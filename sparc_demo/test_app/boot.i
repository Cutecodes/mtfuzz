# 0 "boot.c"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "boot.c"
# 53 "boot.c"
.data
 .text
 .global _start, _trap_table, start
 .global _privileged_exception
 .global _fp_disable
 .global _window_overflow
 .global _window_underflow
 .global _fp_exception
 .global _flush_windows

        .global __stack
        .global __ram_len
        .global text_start
        .global _text_start
        .global end
        .global _end
        .global __end

start:
_start:
_trap_table:
 mov %g0, %l0;sethi %hi(_hardreset),%l4;jmp %l4+%lo(_hardreset);nop;; ! 00 reset trap
 jmp %l2;rett %l2+4;nop;nop;; ! 01 instruction_access_exception
 jmp %l2;rett %l2+4;nop;nop;; ! 02 illegal_instruction
 mov %psr, %l0;sethi %hi(_privileged_exception),%l4;jmp %l4+%lo(_privileged_exception);nop;; ! 03 priveleged_instruction
 jmp %l2;rett %l2+4;nop;nop;; ! 04 fp_disabled
 mov %psr, %l0;sethi %hi(_window_overflow),%l4;jmp %l4+%lo(_window_overflow);nop;; ! 05 window_overflow
 mov %psr, %l0;sethi %hi(_window_underflow),%l4;jmp %l4+%lo(_window_underflow);nop;; ! 06 window_underflow
 jmp %l2;rett %l2+4;nop;nop;; ! 07 Memory Address Not Aligned
 jmp %l2;rett %l2+4;nop;nop;; ! 08 Floating Point Exception
 jmp %l2;rett %l2+4;nop;nop;; ! 09 Data Miss Exception
 jmp %l2;rett %l2+4;nop;nop;; ! 0a Tagged Instruction Ovrflw
 jmp %l2;rett %l2+4;nop;nop;; ! 0b Watchpoint Detected
 jmp %l2;rett %l2+4;nop;nop;; ! 0c
 jmp %l2;rett %l2+4;nop;nop;; ! 0d
 jmp %l2;rett %l2+4;nop;nop;; ! 0e
 jmp %l2;rett %l2+4;nop;nop;; ! 0f
 jmp %l2;rett %l2+4;nop;nop;; ! 10
 mov %psr, %l0;sethi %hi(irqtrap),%l4;jmp %l4+%lo(irqtrap);nop;; ! 11 IRQ level 1
 mov %psr, %l0;sethi %hi(irqtrap),%l4;jmp %l4+%lo(irqtrap);nop;; ! 12 IRQ level 2
 mov %psr, %l0;sethi %hi(irqtrap),%l4;jmp %l4+%lo(irqtrap);nop;; ! 13 IRQ level 3
 mov %psr, %l0;sethi %hi(irqtrap),%l4;jmp %l4+%lo(irqtrap);nop;; ! 14 IRQ level 4
 mov %psr, %l0;sethi %hi(irqtrap),%l4;jmp %l4+%lo(irqtrap);nop;; ! 15 IRQ level 5
 mov %psr, %l0;sethi %hi(irqtrap),%l4;jmp %l4+%lo(irqtrap);nop;; ! 16 IRQ level 6
 mov %psr, %l0;sethi %hi(irqtrap),%l4;jmp %l4+%lo(irqtrap);nop;; ! 17 IRQ level 7
 mov %psr, %l0;sethi %hi(ENXIT_ENTRY),%l4;jmp %l4+%lo(ENXIT_ENTRY);nop;; ! 18 IRQ level 8
 mov %psr, %l0;sethi %hi(irqtrap),%l4;jmp %l4+%lo(irqtrap);nop;; ! 19 IRQ level 9
 mov %psr, %l0;sethi %hi(irqtrap),%l4;jmp %l4+%lo(irqtrap);nop;; ! 1a IRQ level 10
 mov %psr, %l0;sethi %hi(irqtrap),%l4;jmp %l4+%lo(irqtrap);nop;; ! 1b IRQ level 11
 mov %psr, %l0;sethi %hi(irqtrap),%l4;jmp %l4+%lo(irqtrap);nop;; ! 1c IRQ level 12
 mov %psr, %l0;sethi %hi(irqtrap),%l4;jmp %l4+%lo(irqtrap);nop;; ! 1d IRQ level 13
 mov %psr, %l0;sethi %hi(irqtrap),%l4;jmp %l4+%lo(irqtrap);nop;; ! 1e IRQ level 14
 mov %psr, %l0;sethi %hi(irqtrap),%l4;jmp %l4+%lo(irqtrap);nop;; ! 1f IRQ level 15
     ! NMI (non maskable interrupt)
 jmp %l2;rett %l2+4;nop;nop;; ! 20 r_register_access_error
 jmp %l2;rett %l2+4;nop;nop;; ! 21 instruction access error
 jmp %l2;rett %l2+4;nop;nop;; ! 22
 jmp %l2;rett %l2+4;nop;nop;; ! 23
 mov %psr, %l0;sethi %hi(_cp_disable),%l4;jmp %l4+%lo(_cp_disable);nop;; ! 24 co-processor disabled
 jmp %l2;rett %l2+4;nop;nop;; ! 25 uniplemented FLUSH
 jmp %l2;rett %l2+4;nop;nop;; ! 26
 jmp %l2;rett %l2+4;nop;nop;; ! 27
 jmp %l2;rett %l2+4;nop;nop;; ! 28 co-processor exception
 jmp %l2;rett %l2+4;nop;nop;; ! 29 data access error
 jmp %l2;rett %l2+4;nop;nop;; ! 2a division by zero
 jmp %l2;rett %l2+4;nop;nop;; ! 2b data store error
 jmp %l2;rett %l2+4;nop;nop;; ! 2c data access MMU miss
 jmp %l2;rett %l2+4;nop;nop;; ! 2d
 jmp %l2;rett %l2+4;nop;nop;; ! 2e
 jmp %l2;rett %l2+4;nop;nop;; ! 2f
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 30-33
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 34-37
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 38-3b
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 3c-3f
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 40-43
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 44-47
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 48-4b
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 4c-4f
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 50-53
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 54-57
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 58-5b
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 5c-5f


 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 60-63
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 64-67
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 68-6b
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 6c-6f
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 70-73
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 74-77
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 78-7b
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 7c-7f


 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;;
 jmp %l2;rett %l2+4;nop;nop;; ! div zero
 mov %psr, %l0;sethi %hi(_flush_windows),%l4;jmp %l4+%lo(_flush_windows);nop;;
 jmp %l2;restore;nop;nop;; ! interrupt disbale
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 84-87
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 88-8b
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 8c-8f
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 90-93
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 94-97
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 98-9b
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! 9c-9f
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! a0-a3
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! a4-a7
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! a8-ab
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! ac-af
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! b0-b3
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! b4-b7
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! b8-bb
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! bc-bf
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! c0-c3
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! c4-c7
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! c8-cb
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! cc-cf
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! d0-d3
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! d4-d7
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! d8-db
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! dc-df
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! e0-e3
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! e4-e7
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! e8-eb
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! ec-ef
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! f0-f3
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! f4-f7
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! f8-fb
 jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; jmp %l2;rett %l2+4;nop;nop;; ! fc-ff


_hardreset:
        ! init cache
        nop
        set 0x80000000, %g1
 st %g0,[%g1+0x14]
 nop


 ! init psr, ef s ps
 set 0x10c0, %g1
 mov %g1,%psr
 nop
 nop
 nop


 ! clear registers

 mov %g0, %y
 clr %g1
 clr %g2
 clr %g3
 clr %g4
 clr %g5
 clr %g6
 clr %g7

 set 8,%g1

clear_window:
 mov %g0, %l0
 mov %g0, %l1
 mov %g0, %l2
 mov %g0, %l3
 mov %g0, %l4
 mov %g0, %l5
 mov %g0, %l6
 mov %g0, %l7
 mov %g0, %i0
 mov %g0, %i1
 mov %g0, %i2
 mov %g0, %i3
 mov %g0, %i4
 mov %g0, %i5
 mov %g0, %i6
 mov %g0, %i7
 subcc %g1, 1, %g1
 save
 bne clear_window
 flush
 nop

wiminit:
 set 2, %g3
 mov %g3, %wim
 nop
 nop




tbrinit:
 set _trap_table, %g2
 wr %g0, %g2, %tbr
 nop
 nop
 nop


stackinit:
        sethi %hi(__stack), %g1
        or %g1, %lo(__stack), %g1
        andn %g1,0x0f,%g1
        mov %g1,%sp
        nop


wprinit:
        set 0x80000000, %g1
        clr [%g1 + 0x1c]
        clr [%g1 + 0x20]

timerinit:
        ! timer1
        set 0x80000000, %g1
        mov -1, %g2
        st %g2,[%g1 + 0x44]
        mov 0, %g2
        st %g2,[%g1 + 0x48]

        ! timer2
        mov -1, %g2
        st %g2,[%g1 + 0x54]
        mov 0, %g2
        st %g2,[%g1 + 0x58]

uartinit:
        set 0x80000000, %g1
        ! enable rx,tr and rx interrupt
        mov 7,%g2
        ! uart1
        st %g2,[%g1 + 0x78]
        ! uart2
        st %g2,[%g1 + 0x88]

interruptinit:
        set 0x80000000, %g1
        clr [%g1 + 0x90]
        clr [%g1 + 0x94]
        clr [%g1 + 0x98]
        clr [%g1 + 0x9c]
        clr [%g1 + 0xa0]
        clr [%g1 + 0xa4]


mcfginit:
        set 0x80000000, %g1
        ! mcfg1
        set 0x48000f, %g2
        st %g2, [ %g1 ]

        set 0x106f, %g2
        st %g2, [ %g1 + 4 ]

fsrinit:
        set 0x0, %g1
        st %g1, [ %sp ]
        ld [ %sp ], %fsr

        set 0x40000000, %g1
        st %g1, [%sp]
        st %g1, [%sp+4]
        mov %sp, %g1

        ldd [%g1], %f0
        ldd [%g1], %f2
        ldd [%g1], %f4
        ldd [%g1], %f6
        ldd [%g1], %f8
        ldd [%g1], %f10
        ldd [%g1], %f12
        ldd [%g1], %f14
        ldd [%g1], %f16
        ldd [%g1], %f18
        ldd [%g1], %f20
        ldd [%g1], %f22
        ldd [%g1], %f24
        ldd [%g1], %f26
        ldd [%g1], %f28
        ldd [%g1], %f30
        nop

asrinit:
        mov %g0,%asr24
        nop;nop;nop
        mov %g0,%asr25
        nop;nop;nop
        mov %g0,%asr26
        nop;nop;nop
        mov %g0,%asr27
        nop;nop;nop
        mov %g0,%asr28
        nop;nop;nop
        mov %g0,%asr29
        nop;nop;nop
        mov %g0,%asr30
        nop;nop;nop
        mov %g0,%asr31
        nop;nop;nop
yinit:
        mov %g0,%y
        nop;nop;nop

interruptclr:
        set 0xffffffff,%g2
        st %g2, [%g1 + 0x9c]
        nop
        set 0x10e0,%g1
        mov %g1,%psr
        nop;nop;nop

        call _userinit
        nop

        call main
        nop

_userinit:
        save
        sethi %hi(__bss_start),%g2
        or %g2,%lo(__bss_start),%g2
        sethi %hi(__end),%g3
        or %g2,%lo(__end),%g3
        mov %g0,%g1
        sub %g3,%g2,%g3
        cmp %g3,0
        be over
        nop

 zerobss:
        subcc %g3,8,%g3
        bge zerobss
        std %g0,[%g2+%g3]
        set __end,%o0
        st %g0,[%o0]
        nop

 over:
        ret
        restore

 _privileged_exception:
        set 0xc0,%g1
        mov %psr,%g2
        nop
        nop
        nop

        or %g2,%g1,%g1
        mov %g1,%psr
        nop
        nop
        nop

        jmpl %l1,%g0
        rett %l2
        nop
        nop

_fp_disable:
        set 0x1000,%l4
        andcc %l0,%l4,%l3
        bnz _fp_dis_npc_continue
        nop

        or %l4,%l0,%l0
        mov %l0,%psr
        nop
        nop
        nop

        jmpl %l1,%g0
        rett %l2
        nop
        nop

 _fp_dis_npc_continue:
        mov %l0,%psr
        nop
        nop
        nop

        jmpl %l2,%g0
        rett %l2+4
        nop
        nop

_cp_disable:
        set 0x2000,%l4
        andcc %l0,%l4,%l3
        bnz _cp_dis_npc_continue
        nop

        or %l4,%l0,%l0
        mov %l0,%psr
        nop
        nop
        nop

        jmpl %l1,%g0
        rett %l2
        nop
        nop

_cp_dis_npc_continue:
        mov %l0,%psr
        nop
        nop
        nop
        jmpl %l2,%g0
        rett %l2+4
        nop
        nop




_window_overflow:

 mov %wim, %l3 ! Calculate next WIM
 mov %g1, %l7
 srl %l3, 1, %g1
 sll %l3, 7, %l4
 or %g1, %l4, %g1
 save ! Get into window to be saved.
 mov %g1, %wim
 nop; nop; nop
 st %l0, [%sp + 0] ! Save window to the stack
 st %l1, [%sp + 4]
 st %l2, [%sp + 8]
 st %l3, [%sp + 12]
 st %l4, [%sp + 16]
 st %l5, [%sp + 20]
 st %l6, [%sp + 24]
 st %l7, [%sp + 28]
 st %i0, [%sp + 32]
 st %i1, [%sp + 36]
 st %i2, [%sp + 40]
 st %i3, [%sp + 44]
 st %i4, [%sp + 48]
 st %i5, [%sp + 52]
 st %i6, [%sp + 56]
 st %i7, [%sp + 60]
 restore ! Go back to trap window.
 mov %l7, %g1
 jmp %l1 ! Re-execute save.
  rett %l2






_window_underflow:

 mov %wim, %l3 ! Calculate next WIM
 srl %l3, 7, %l5
 sll %l3, 1, %l4
 or %l5, %l4, %l5
 mov %l5, %wim
 nop; nop; nop
 restore ! Two restores to get into the
 restore ! window to restore
 ld [%sp + 0], %l0; ! Restore window from the stack
 ld [%sp + 4], %l1;
 ld [%sp + 8], %l2;
 ld [%sp + 12], %l3;
 ld [%sp + 16], %l4;
 ld [%sp + 20], %l5;
 ld [%sp + 24], %l6;
 ld [%sp + 28], %l7;
 ld [%sp + 32], %i0;
 ld [%sp + 36], %i1;
 ld [%sp + 40], %i2;
 ld [%sp + 44], %i3;
 ld [%sp + 48], %i4;
 ld [%sp + 52], %i5;
 ld [%sp + 56], %i6;
 ld [%sp + 60], %i7;
 save ! Get back to the trap window.
 save
 jmp %l1 ! Re-execute restore.
  rett %l2

!------------------------------------------------------------------------------



_fp_exception:
        jmpl %l2,%g0
        rett %l2+4
        nop
        nop

_flush_windows:
        mov %g1,%l3
        mov %g2,%l4
        mov %g3,%l5
        mov %g4,%l6
        mov %g5,%l7

        mov %l0,%g1
        mov %wim,%g2
        and %l0,0x07,%g3

        add %g3,1,%g5
        and %g5,8 -1,%g5

        mov 1,%g4
        sll %g4,%g5,%g4

        restore

irqtrap:
        jmp %l2;rett %l2+4;nop;nop;


ENXIT_ENTRY:
        mov 0x0e,%l3
        rd %psr,%l0
        and %l0,0x07,%l4
        mov 1,%l5
        sll %l5,%l4,%l5
        rd %wim,%l4
        andcc %l4,%l5,%g0
        be Window_OK
        nop

        save
        std %l0,[%sp + 0x00]
        std %l2,[%sp + 0x08]
        std %l4,[%sp + 0x10]
        std %l6,[%sp + 0x18]
        std %i0,[%sp + 0x20]
        std %i2,[%sp + 0x28]
        std %i4,[%sp + 0x30]
        std %i6,[%sp + 0x38]
        rd %wim,%l4
        srl %l4,1,%l5
        sll %l4,8-1,%l4
        or %l4,%l5,%l4
        mov %l4,%wim
        nop
        nop
        nop
        restore
        nop

Window_OK:
        sub %fp,0x60,%sp
        st %l0,[%sp + 0x00]
        st %l1,[%sp + 0x04]
        st %l2,[%sp + 0x08]
        st %l3,[%sp + 0x0c]
        st %l4,[%sp + 0x10]
        st %l5,[%sp + 0x14]
        st %l6,[%sp + 0x18]
        st %l7,[%sp + 0x1c]
        st %i0,[%sp + 0x20]
        st %i1,[%sp + 0x24]
        st %i2,[%sp + 0x28]
        st %i3,[%sp + 0x2c]
        st %i4,[%sp + 0x30]
        st %i5,[%sp + 0x34]
        st %i6,[%sp + 0x38]
        st %i7,[%sp + 0x3c]
        st %g1,[%sp + 0x40]
        st %g2,[%sp + 0x44]
        st %g3,[%sp + 0x48]
        st %g4,[%sp + 0x4c]
        st %g5,[%sp + 0x50]
        st %g6,[%sp + 0x54]
        st %g7,[%sp + 0x58]
        rd %psr,%l4
        set 0xfffff0ff,%g2
        and %g2,%l4,%l4
        sll %l3,0x08,%g2
        or %l4,%g2,%l4
        mov %l4,%psr
        nop
        nop
        nop
        rd %psr,%l4
        or %l4,0x20,%l4
        nop
        nop
        mov %l4,%psr
        nop
        nop
        nop
        call c_int
        nop

        rd %psr,%l4
        and %l4,0xfffff0df,%l4
        nop
        nop
        mov %l4,%psr
        nop
        nop
        nop

Underflow_Check:
        rd %psr,%l4
        and %l4,0x07,%l4
        add %l4,1,%l4
        and %l4,0x07,%l4
        mov 1,%l5
        sll %l5,%l4,%l5
        rd %wim,%l4
        andcc %l4,%l5,%g0
        be simple_return
        nop
        sll %l4,1,%l5
        srl %l4,8-1,%l4
        or %l4,%l5,%l4
        wr %l4,0,%wim
        nop
        nop
        nop

        restore
        ldd [%sp + 0x00],%l0
        ldd [%sp + 0x08],%l2
        ldd [%sp + 0x10],%l4
        ldd [%sp + 0x18],%l6
        ldd [%sp + 0x20],%i0
        ldd [%sp + 0x28],%i2
        ldd [%sp + 0x30],%i4
        ldd [%sp + 0x38],%i6
        save

 simple_return:
        ld [%sp + 0x00],%l0
        ld [%sp + 0x04],%l1
        ld [%sp + 0x08],%l2
        ld [%sp + 0x0c],%l3
        ld [%sp + 0x10],%l4
        ld [%sp + 0x14],%l5
        ld [%sp + 0x18],%l6
        ld [%sp + 0x1c],%l7
        ld [%sp + 0x20],%i0
        ld [%sp + 0x24],%i1
        ld [%sp + 0x28],%i2
        ld [%sp + 0x2c],%i3
        ld [%sp + 0x30],%i4
        ld [%sp + 0x34],%i5
        ld [%sp + 0x38],%i6
        ld [%sp + 0x3c],%i7
        ld [%sp + 0x40],%g1
        ld [%sp + 0x44],%g2
        ld [%sp + 0x48],%g3
        ld [%sp + 0x4c],%g4
        ld [%sp + 0x50],%g5
        ld [%sp + 0x54],%g6
        ld [%sp + 0x58],%g7



        rd %psr,%l4
        and %l4,0x07,%l4
        andn %l0,0x07,%l0
        or %l0,%l4,%l0
        set 0x01000,%l4
        or %l0,%l4,%l0
        andn %l0,0x20,%l0
        mov %l0,%psr
        nop
        nop
        nop

        jmp %l1
        rett %l2
        nop
        nop
