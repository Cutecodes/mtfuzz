/*
 * (C) Copyright 2007-2008
 * Daniel Hellstrom, Gaisler Research, daniel@gaisler.com.
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */
PROVIDE (__stack = 0x400ffff0);
OUTPUT_ARCH(sparc)
ENTRY(_start)

SECTIONS
{

/* Read-only sections, merged into text segment: */
	. = 0x40000000;
	
	.text : {*(.text)}
	. = ALIGN(16);

	/* CMD Table */


	. = ALIGN(16);


	.data	:
	{
		*(.data)
	}
	_edata	=	.;

        . = ALIGN(16);
	__bss_start = .;
	.bss	:
	{

	 *(.bss)
	}
	. = ALIGN(16);
	__bss_end = . ;
	__bss_end = . ;
	PROVIDE (end = .);
	__end = .;



}
