/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ld.script for compressed kernel support of LoongArch
 *
 * Author: Huacai Chen <chenhuacai@loongson.cn>
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include "../kernel/image-vars.h"

/*
 * Max avaliable Page Size is 64K, so we set SectionAlignment
 * field of EFI application to 64K.
 */
PECOFF_FILE_ALIGN = 0x200;
PECOFF_SEGMENT_ALIGN = 0x10000;

OUTPUT_ARCH(loongarch)
ENTRY(kernel_entry)
PHDRS {
	text PT_LOAD FLAGS(7); /* RWX */
}
SECTIONS
{
	. = VMLINUZ_LOAD_ADDRESS;

	_text = .;
	.head.text : {
		*(.head.text)
	}

	.text : {
		*(.text)
		*(.init.text)
		*(.rodata)
	}: text

	. = ALIGN(PECOFF_SEGMENT_ALIGN);
	_data = .;
	.data : {
		*(.data)
		*(.init.data)
		/* Put the compressed image here */
		__image_begin = .;
		*(.image)
		__image_end = .;
		CONSTRUCTORS
		. = ALIGN(PECOFF_FILE_ALIGN);
	}
	_edata = .;

	.bss : {
		*(.bss)
		*(.init.bss)
	}
	. = ALIGN(PECOFF_SEGMENT_ALIGN);
	_end = .;

	/DISCARD/ : {
		*(.options)
		*(.comment)
		*(.note)
	}
}
