/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <asm/alternative-asm.h>
#include <asm/asm.h>
#include <asm/asmmacro.h>
#include <asm/cpu.h>
#include <asm/export.h>
#include <asm/regdef.h>

.macro fixup_ex from, to, offset, fix
.if \fix
	.section .fixup, "ax"
\to:	addi.d	a0, a1, \offset
	jr	ra
	.previous
.endif
	.section __ex_table, "a"
	PTR	\from\()b, \to\()b
	.previous
.endm

SYM_FUNC_START(__clear_user)
	/*
	 * Some CPUs support hardware unaligned access
	 */
	ALTERNATIVE	"b __clear_user_generic",	\
			"b __clear_user_fast", CPU_FEATURE_UAL
SYM_FUNC_END(__clear_user)

EXPORT_SYMBOL(__clear_user)

/*
 * unsigned long __clear_user_generic(void *addr, size_t size)
 *
 * a0: addr
 * a1: size
 */
SYM_FUNC_START(__clear_user_generic)
	beqz	a1, 2f

1:	st.b	zero, a0, 0
	addi.d	a0, a0, 1
	addi.d	a1, a1, -1
	bgt	a1, zero, 1b

2:	move	a0, a1
	jr	ra

	fixup_ex 1, 3, 0, 1
SYM_FUNC_END(__clear_user_generic)

/*
 * unsigned long __clear_user_fast(void *addr, unsigned long size)
 *
 * a0: addr
 * a1: size
 */
SYM_FUNC_START(__clear_user_fast)
	beqz	a1, 10f

	ori	a2, zero, 64
	blt	a1, a2, 9f

	/* set 64 bytes at a time */
1:	st.d	zero, a0, 0
2:	st.d	zero, a0, 8
3:	st.d	zero, a0, 16
4:	st.d	zero, a0, 24
5:	st.d	zero, a0, 32
6:	st.d	zero, a0, 40
7:	st.d	zero, a0, 48
8:	st.d	zero, a0, 56

	addi.d	a0, a0, 64
	addi.d	a1, a1, -64
	bge	a1, a2, 1b

	beqz	a1, 10f

	/* set the remaining bytes */
9:	st.b	zero, a0, 0
	addi.d	a0, a0, 1
	addi.d	a1, a1, -1
	bgt	a1, zero, 9b

	/* return */
10:	move	a0, a1
	jr	ra

	/* fixup and ex_table */
	fixup_ex 1, 11,   0, 1
	fixup_ex 2, 12,  -8, 1
	fixup_ex 3, 13, -16, 1
	fixup_ex 4, 14, -24, 1
	fixup_ex 5, 15, -32, 1
	fixup_ex 6, 16, -40, 1
	fixup_ex 7, 17, -48, 1
	fixup_ex 8, 18, -56, 1
	fixup_ex 9, 11,   0, 0
SYM_FUNC_END(__clear_user_fast)
