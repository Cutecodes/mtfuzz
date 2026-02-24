	.text
	.file	"main.c"
	.globl	read_data
	.p2align	2
	.type	read_data,@function
read_data:
	save %sp, -96, %sp
	st %i0, [%fp+-4]
	ld [%fp+-4], %i0
	ld [%i0], %i0
	ret
	restore
.Lfunc_end0:
	.size	read_data, .Lfunc_end0-read_data

	.globl	init_interrupt
	.p2align	2
	.type	init_interrupt,@function
init_interrupt:
	save %sp, -96, %sp
	sethi 2097152, %i0
	or %i0, 144, %i1
	st %i1, [%fp+-4]
	ld [%fp+-4], %i1
	mov	256, %i2
	st %i2, [%i1]
	or %i0, 168, %i0
	st %i0, [%fp+-4]
	ld [%fp+-4], %i0
	mov	7, %i1
	st %i1, [%i0]
	ret
	restore
.Lfunc_end1:
	.size	init_interrupt, .Lfunc_end1-init_interrupt

	.globl	start_timer
	.p2align	2
	.type	start_timer,@function
start_timer:
	save %sp, -96, %sp
	sethi 2097152, %i0
	or %i0, 68, %i1
	st %i1, [%fp+-4]
	ld [%fp+-4], %i1
	sethi 64, %i2
	st %i2, [%i1]
	or %i0, 64, %i1
	st %i1, [%fp+-4]
	ld [%fp+-4], %i1
	st %g0, [%i1]
	or %i0, 72, %i0
	st %i0, [%fp+-4]
	ld [%fp+-4], %i0
	mov	7, %i1
	st %i1, [%i0]
	ret
	restore
.Lfunc_end2:
	.size	start_timer, .Lfunc_end2-start_timer

	.globl	test_app
	.p2align	2
	.type	test_app,@function
test_app:
	save %sp, -152, %sp
	mov	5, %i0
	st %i0, [%fp+-4]
	st %g0, [%fp+-8]
	ba .LBB3_1
	st %g0, [%fp+-52]
.LBB3_1:
	ld [%fp+-52], %i0
	ld [%fp+-4], %i1
	cmp %i0, %i1
	bge	.LBB3_4
	nop
	ba .LBB3_2
	nop
.LBB3_2:
	sethi 524288, %i0
	call read_data
	or %i0, 32, %o0
	ld [%fp+-52], %i0
	sll %i0, 2, %i1
	add %fp, -48, %i0
	ba .LBB3_3
	st %o0, [%i0+%i1]
.LBB3_3:
	ld [%fp+-52], %i0
	add %i0, 1, %i0
	ba .LBB3_1
	st %i0, [%fp+-52]
.LBB3_4:
	ba .LBB3_5
	st %g0, [%fp+-56]
.LBB3_5:
	ld [%fp+-56], %i0
	ld [%fp+-4], %i1
	add %i1, -1, %i1
	cmp %i0, %i1
	bge	.LBB3_8
	nop
	ba .LBB3_6
	nop
.LBB3_6:
	ld [%fp+-8], %i0
	ld [%fp+-56], %i1
	sll %i1, 2, %i2
	add %fp, -48, %i1
	ld [%i1+%i2], %i1
	add %i0, %i1, %i0
	ba .LBB3_7
	st %i0, [%fp+-8]
.LBB3_7:
	ld [%fp+-56], %i0
	add %i0, 1, %i0
	ba .LBB3_5
	st %i0, [%fp+-56]
.LBB3_8:
	ld [%fp+-4], %i0
	sll %i0, 2, %i0
	add %fp, -48, %i1
	add %i0, %i1, %i0
	ld [%i0+-4], %i0
	ld [%fp+-8], %i1
	cmp %i0, %i1
	be	.LBB3_10
	nop
	ba .LBB3_9
	nop
.LBB3_9:
	ba .LBB3_12
	nop
.LBB3_10:
	ld [%fp+-48], %i0
	sethi 1398101, %i1
	or %i1, 341, %i1
	cmp %i0, %i1
	bne	.LBB3_12
	nop
	ba .LBB3_11
	nop
.LBB3_11:
	mov	999, %i1
	mov	%g0, %i0
	st %i1, [%i0]
	mov	1, %i0
	ba .LBB3_12
	st %i0, [%fp+-48]
.LBB3_12:
	ret
	restore
.Lfunc_end3:
	.size	test_app, .Lfunc_end3-test_app

	.globl	main
	.p2align	2
	.type	main,@function
main:
	save %sp, -96, %sp
	call init_interrupt
	st %g0, [%fp+-4]
	call start_timer
	nop
	ba .LBB4_1
	nop
.LBB4_1:
	call test_app
	nop
	ba .LBB4_1
	nop
.Lfunc_end4:
	.size	main, .Lfunc_end4-main

	.globl	c_int
	.p2align	2
	.type	c_int,@function
c_int:
	save %sp, -104, %sp
	st %g0, [%fp+-4]
	st %g0, [%fp+-8]
	ld [%fp+-4], %i0
	ld [%fp+-8], %i1
	add %i0, %i1, %i0
	st %i0, [%fp+-12]
	ret
	restore
.Lfunc_end5:
	.size	c_int, .Lfunc_end5-c_int

	.type	buffer,@object
	.section	.bss,#alloc,#write
	.globl	buffer
	.p2align	2
buffer:
	.skip	4000
	.size	buffer, 4000

	.ident	"Ubuntu clang version 14.0.0-1ubuntu1.1"
	.section	".note.GNU-stack"
