/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/init.h>
#include <linux/linkage.h>
#include <asm/addrspace.h>
#include <asm/asm.h>
#include <asm/loongarch.h>
#include <asm/regdef.h>
#include <generated/compile.h>
#include <generated/utsrelease.h>

#ifdef CONFIG_EFI_STUB

#include "zheader.S"

	__HEAD

_head:
	/* "MZ", MS-DOS header */
	.word	MZ_MAGIC
	.org	0x38
#ifdef CONFIG_32BIT
	.ascii	"LA32"			/* Magic number for BootLoader */
#else
	.ascii	"LA64"			/* Magic number for BootLoader */
#endif
	.org	0x3c
	/* Offset to the PE header */
	.long	pe_header - _head

pe_header:
	__EFI_PE_HEADER

kernel_asize:
	.long _end - _text

kernel_fsize:
	.long _edata - _text

kernel_vaddr:
	.quad VMLINUZ_LOAD_ADDRESS

kernel_offset:
	.long kernel_offset - _text

kernel_version:
	.ascii  UTS_RELEASE " (" LINUX_COMPILE_BY "@" LINUX_COMPILE_HOST ") " UTS_VERSION "\0"

SYM_L_GLOBAL(kernel_asize)
SYM_L_GLOBAL(kernel_fsize)
SYM_L_GLOBAL(kernel_vaddr)
SYM_L_GLOBAL(kernel_offset)

#endif

	__INIT

SYM_CODE_START(kernel_entry)
	/* Save boot rom start args */
	move	s0, a0
	move	s1, a1

	/* Config Direct Mapping */
	li.d	t0, CSR_DMW0_INIT
	csrwr	t0, LOONGARCH_CSR_DMWIN0
	li.d	t0, CSR_DMW1_INIT
	csrwr	t0, LOONGARCH_CSR_DMWIN1

	/* Clear BSS */
	la.abs	a0, _edata
	la.abs	a2, _end
1:	st.d	zero, a0, 0
	addi.d	a0, a0, 8
	bne	a2, a0, 1b

	la.abs	a0, .heap	   /* heap address */
	la.abs	sp, .stack + 8192  /* stack address */

	la	ra, 2f
	la	t4, decompress_kernel
	jirl	zero, t4, 0
2:
	move	a0, s0
	move	a1, s1
	PTR_LI	t4, KERNEL_ENTRY
	jirl	zero, t4, 0
3:
	b	3b
SYM_CODE_END(kernel_entry)

	.comm .heap, BOOT_HEAP_SIZE, 4
	.comm .stack, BOOT_STACK_SIZE, 4

	.align 4
	.section .image, "a", %progbits
	.incbin "arch/loongarch/boot/vmlinux.bin.z"
