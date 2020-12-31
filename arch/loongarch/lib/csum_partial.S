/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Quick'n'dirty IP checksum ...
 *
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */
#include <linux/errno.h>
#include <linux/linkage.h>
#include <asm/alternative-asm.h>
#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/cpu.h>
#include <asm/export.h>
#include <asm/regdef.h>

#define LOAD   ld.d
#define LOAD32 ld.wu
#define ADD    add.d
#define SUB    sub.d
#define SLL    slli.d
#define SRL    srli.d
#define SLLV   sll.d
#define SRLV   srl.d

#define NBYTES 8
#define LOG_NBYTES 3
#define UNIT(unit)  ((unit)*NBYTES)
#define ADDRMASK (NBYTES-1)

#define _ASM_EXTABLE(from, to)			\
	.section __ex_table, "a";		\
	PTR	from, to;			\
	.previous

#define ADDC(sum,reg)						\
	ADD	sum, sum, reg;					\
	sltu	t8, sum, reg;					\
	ADD	sum, sum, t8;					\

#define ADDC32(sum,reg)						\
	add.w	sum, sum, reg;					\
	sltu	t8, sum, reg;					\
	add.w	sum, sum, t8;					\

#define CSUM_BIGCHUNK(src, offset, sum, _t0, _t1, _t2, _t3)	\
	LOAD	_t0, src, (offset + UNIT(0));			\
	LOAD	_t1, src, (offset + UNIT(1));			\
	LOAD	_t2, src, (offset + UNIT(2));			\
	LOAD	_t3, src, (offset + UNIT(3));			\
	ADDC(_t0, _t1);						\
	ADDC(_t2, _t3);						\
	ADDC(sum, _t0);						\
	ADDC(sum, _t2)

/*
 * a0: source address
 * a1: length of the area to checksum
 * a2: partial checksum
 */

#define src a0
#define sum t6

	.text
	.align	5
SYM_FUNC_START(csum_partial)
	or	sum, zero, zero
	or	t7, zero, zero

	sltui	t8, a1, 0x8
	or	t2, a1, zero
	bnez	t8, .Lsmall_csumcpy		/* < 8 bytes to copy */

	andi	t7, src, 0x1			/* odd buffer? */

.Lhword_align:
	andi	t8, src, 0x2
	beqz	t7, .Lword_align

	ld.bu	t0, src, 0x0
	LONG_ADDI	a1, a1, -1
	slli.w	t0, t0, 8
	ADDC(sum, t0)
	PTR_ADDI	src, src, 1
	andi	t8, src, 0x2

.Lword_align:
	sltui	t4, a1, 56
	beqz	t8, .Ldword_align

	ld.hu	t0, src, 0x0
	LONG_ADDI	a1, a1, -2
	ADDC(sum, t0)
	sltui	t4, a1, 56
	PTR_ADDI	src, src, 0x2

.Ldword_align:
	or	t8, a1, zero
	bnez	t4, .Ldo_end_words

	andi	t4, src, 0x4
	andi	t8, src, 0x8
	beqz	t4, .Lqword_align

	LOAD32	t0, src, 0x0
	LONG_ADDI	a1, a1, -4
	ADDC(sum, t0)
	PTR_ADDI	src, src, 4
	andi	t8, src, 0x8

.Lqword_align:
	andi	t4, src, 0x10
	beqz	t8, .Loword_align

	ld.d	t0, src, 0
	LONG_ADDI	a1, a1, -8
	ADDC(sum, t0)
	PTR_ADDI	src, src, 8
	andi	t4, src, 0x10

.Loword_align:
	LONG_SRL	t8, a1, 0x7
	beqz	t4, .Lbegin_movement

	ld.d	t0, src, 0x00
	ld.d	t1, src, 0x08
	ADDC(sum, t0)
	ADDC(sum, t1)
	LONG_ADDI	a1, a1, -16
	PTR_ADDI	src, src, 16
	LONG_SRL	t8, a1, 0x7

.Lbegin_movement:
	andi	t2, a1, 0x40
	beqz	t8, 1f

	or	t5, t8, zero
.Lmove_128bytes:
	CSUM_BIGCHUNK(src, 0x00, sum, t0, t1, t3, t4)
	CSUM_BIGCHUNK(src, 0x20, sum, t0, t1, t3, t4)
	CSUM_BIGCHUNK(src, 0x40, sum, t0, t1, t3, t4)
	CSUM_BIGCHUNK(src, 0x60, sum, t0, t1, t3, t4)
	addi.d	t5, t5, -1
	addi.d	src, src, 0x80
	bnez	t5, .Lmove_128bytes

1:
	or	t4, t2, zero
	andi	t2, a1, 0x20
	beqz	t4, 1f

.Lmove_64bytes:
	CSUM_BIGCHUNK(src, 0x00, sum, t0, t1, t3, t4)
	CSUM_BIGCHUNK(src, 0x20, sum, t0, t1, t3, t4)
	PTR_ADDI	src, src, 64

1:
	andi	t8, a1, 0x1c
	beqz	t2, .Ldo_end_words

.Lmove_32bytes:
	CSUM_BIGCHUNK(src, 0x00, sum, t0, t1, t3, t4)
	andi	t8, a1, 0x1c
	PTR_ADDI	src, src, 32

.Ldo_end_words:
	andi	t2, a1, 0x3
	beqz	t8, .Lsmall_csumcpy
	LONG_SRL	t8, t8, 0x2

.Lend_words:
	or	t4, t8, zero
1:	LOAD32	t0, src, 0x0
	LONG_ADDI	t4, t4, -1
	ADDC(sum, t0)
	PTR_ADDI	src, src, 4
	bnez	t4, 1b

/* unknown src alignment and < 8 bytes to go  */
.Lsmall_csumcpy:
	or	a1, t2, zero

	andi	t4, a1, 4
	andi	t0, a1, 2
	beqz	t4, 1f

	/* Still a full word to go  */
	ld.w	t1, src, 0x0
	PTR_ADDI	src, src, 4
	slli.d	t1, t1, 32			/* clear lower 32bit */
	ADDC(sum, t1)

1:	or	t1, zero, zero
	or	t4, t0, zero
	andi	t0, a1, 1
	beqz	t4, 1f

	/* Still a halfword to go  */
	ld.hu	t1, src, 0x0
	PTR_ADDI	src, src, 2

1:	slli.w	t1, t1, 16
	beqz	t0, 1f

	ld.bu	t2, src, 0

	or	t1, t1, t2

1:	ADDC(sum, t1)

	/* fold checksum */
	slli.d	t4, sum, 32
	add.d	sum, sum, t4
	sltu	t4, sum, t4
	srai.d	sum, sum, 32
	add.w	sum, sum, t4

	/* odd buffer alignment? */
	beqz	t7, 1f
	revb.2h	sum, sum
	/* Add the passed partial csum.	 */
1:	ADDC32(sum, a2)
	or	v0, sum, zero
	jirl	zero, ra, 0x0
SYM_FUNC_END(csum_partial)
EXPORT_SYMBOL(csum_partial)

/*
 * checksum and copy routines based on memcpy.S
 *
 *	csum_partial_copy(src, dst, len)
 *
 * See "Spec" in memcpy.S for details.	Unlike __copy_user, all
 * function in this file use the standard calling convention.
 */

#define src a0
#define dst a1
#define len a2
#define rem t4
#define sum t6
#define odd t7

SYM_FUNC_START(csum_partial_copy_generic)
	xor	sum, sum, sum
	bge	zero, len, .Lend

	andi	odd, dst, 0x1
	beqz	odd, .Leven
1:	ld.b	t0, src, 0
2:	st.b	t0, dst, 0
	slli.d	t1, t0, 8
	add.d	sum, sum, t1
	addi.d	len, len, -1
	addi.d	src, src, 1
	addi.d	dst, dst, 1
.Leven:
	ori	t4, zero, 2
	blt	len, t4, .Lendloop	/* more than 2 bytes */

3:	ld.hu	t1, src, 0
4:	st.h	t1, dst, 0
	addi.d	src, src, 2
	addi.d	dst, dst, 2
	addi.d	len, len, -2
	ADDC32(sum, t1)
	bge	len, t4, 3b

.Lendloop:
	andi	t0, len, 1
	beqz	t0, .Lend
5:	ld.b	t0, src, 0
6:	st.b	t0, dst, 0
	ADDC32(sum, t0)
.Lend:
	beqz	odd, 7f
	revb.2h	sum, sum
7:
	move	v0, sum
	jirl	zero, ra, 0x0

	.section .fixup, "ax"
8:
	move	v0, zero
	jirl	zero, ra, 0x0
	.previous

	_ASM_EXTABLE(1b, 8b)
	_ASM_EXTABLE(2b, 8b)
	_ASM_EXTABLE(3b, 8b)
	_ASM_EXTABLE(4b, 8b)
	_ASM_EXTABLE(5b, 8b)
	_ASM_EXTABLE(6b, 8b)
SYM_FUNC_END(csum_partial_copy_generic)

SYM_FUNC_START(csum_partial_copy_fast)
	or	sum, zero, zero
	sltui	t2, len, NBYTES
	bnez	t2, .Lcopy_bytes_checklen
.Lmore_than_NBYTES:
	beqz	len, .Ldone
	andi	rem, len, (NBYTES - 1)
	/* if rem == len means that len < NBYTES */
	beq	rem, len, .Lcopy_bytes
1:	/* 8 <= len  */
	ld.d	t0, src, 0x0
	addi.d	src, src, NBYTES
	addi.d	len, len, -NBYTES
2:	st.d	t0, dst, 0x0
	ADDC(sum, t0)
	addi.d	dst, dst, NBYTES
	bne	rem, len, 1b
.Lcopy_bytes_checklen:
	beqz	len, .Ldone
.Lcopy_bytes:
	/* len < 8 copy one by one */
	or	t2, zero, zero	/* t2 store len bytes of data */
	or	t3, zero, zero	/* t3 for increase shift */
	/* copy byte 0 */
5:	ld.b	t0, src, 0
	addi.d	len, len, -1
6:	st.b	t0, dst, 0
	addi.d	dst, dst, 1
	sll.d	t0, t0, t3
	addi.d	t3, t3, 8
	or	t2, t2, t0
	beqz	len, .Lcopy_bytes_done
	/* copy byte 1 */
7:	ld.b	t0, src, 1
	addi.d	len, len, -1
8:	st.b	t0, dst, 0
	addi.d	dst, dst, 1
	sll.d	t0, t0, t3
	addi.d	t3, t3, 8
	or	t2, t2, t0
	beqz	len, .Lcopy_bytes_done
	/* copy byte 2 */
9:	ld.b	t0, src, 2
	addi.d	len, len, -1
10:	st.b	t0, dst, 0
	addi.d	dst, dst, 1
	sll.d	t0, t0, t3
	addi.d	t3, t3, 8
	or	t2, t2, t0
	beqz	len, .Lcopy_bytes_done
	/* copy byte 3 */
11:	ld.b	t0, src, 3
	addi.d	len, len, -1
12:	st.b	t0, dst, 0
	addi.d	dst, dst, 1
	sll.d	t0, t0, t3
	addi.d	t3, t3, 8
	or	t2, t2, t0
	beqz	len, .Lcopy_bytes_done
	/* copy byte 4 */
13:	ld.b	t0, src, 4
	addi.d	len, len, -1
14:	st.b	t0, dst, 0
	addi.d	dst, dst, 1
	sll.d	t0, t0, t3
	addi.d	t3, t3, 8
	or	t2, t2, t0
	beqz	len, .Lcopy_bytes_done
	/* copy byte 5 */
15:	ld.b	t0, src, 5
	addi.d	len, len, -1
16:	st.b	t0, dst, 0
	addi.d	dst, dst, 1
	sll.d	t0, t0, t3
	addi.d	t3, t3, 8
	or	t2, t2, t0
	beqz	len, .Lcopy_bytes_done
	/* copy byte 6 */
17:	ld.b	t0, src, 6
	addi.d	len, len, -1
18:	st.b	t0, dst, 0
	addi.d	dst, dst, 1
	sll.d	t0, t0, t3
	addi.d	t3, t3, 8
	or	t2, t2, t0
.Lcopy_bytes_done:
	/* copy one by one then calc csum */
	ADDC(sum, t2)
.Ldone:
	/* fold checksum to 32bit */
	slli.d	t4, sum, 32
	add.d	sum, sum, t4
	sltu	t4, sum, t4
	srai.d	sum, sum, 32
	add.w	sum, sum, t4
19:
	move	v0, sum
	jirl	zero, ra, 0x0

	.section .fixup, "ax"
20:
	move	v0, zero
	jirl	zero, ra, 0x0
	.previous

	_ASM_EXTABLE(1b, 20b)
	_ASM_EXTABLE(2b, 20b)
	_ASM_EXTABLE(5b, 20b)
	_ASM_EXTABLE(6b, 20b)
	_ASM_EXTABLE(7b, 20b)
	_ASM_EXTABLE(8b, 20b)
	_ASM_EXTABLE(9b, 20b)
	_ASM_EXTABLE(10b, 20b)
	_ASM_EXTABLE(11b, 20b)
	_ASM_EXTABLE(12b, 20b)
	_ASM_EXTABLE(13b, 20b)
	_ASM_EXTABLE(14b, 20b)
	_ASM_EXTABLE(15b, 20b)
	_ASM_EXTABLE(16b, 20b)
	_ASM_EXTABLE(17b, 20b)
	_ASM_EXTABLE(18b, 20b)
SYM_FUNC_END(csum_partial_copy_fast)

SYM_FUNC_START(csum_partial_copy)
	ALTERNATIVE   "b csum_partial_copy_generic", \
		      "b csum_partial_copy_fast", CPU_FEATURE_UAL
SYM_FUNC_END(csum_partial_copy)

EXPORT_SYMBOL(csum_partial_copy)
