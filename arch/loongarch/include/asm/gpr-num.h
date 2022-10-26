/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_GPR_NUM_H
#define __ASM_GPR_NUM_H

#ifdef __ASSEMBLY__

	.equ	.L__gpr_num_zero, 0
	.equ	.L__gpr_num_$zero, 0
	.equ	.L__gpr_num_$ra,  1
	.equ	.L__gpr_num_$tp,  2
	.equ	.L__gpr_num_$sp,  3
	.equ	.L__gpr_num_$a0,  4
	.equ	.L__gpr_num_$a1,  5
	.equ	.L__gpr_num_$a2,  6
	.equ	.L__gpr_num_$a3,  7
	.equ	.L__gpr_num_$a4,  8
	.equ	.L__gpr_num_$a5,  9
	.equ	.L__gpr_num_$a6, 10
	.equ	.L__gpr_num_$a7, 11
	.equ	.L__gpr_num_$t0, 12
	.equ	.L__gpr_num_$t1, 13
	.equ	.L__gpr_num_$t2, 14
	.equ	.L__gpr_num_$t3, 15
	.equ	.L__gpr_num_$t4, 16
	.equ	.L__gpr_num_$t5, 17
	.equ	.L__gpr_num_$t6, 18
	.equ	.L__gpr_num_$t7, 19
	.equ	.L__gpr_num_$t8, 20
	.equ	.L__gpr_num_$x,  21
	.equ	.L__gpr_num_$fp, 22
	.equ	.L__gpr_num_$s0, 23
	.equ	.L__gpr_num_$s1, 24
	.equ	.L__gpr_num_$s2, 25
	.equ	.L__gpr_num_$s3, 26
	.equ	.L__gpr_num_$s4, 27
	.equ	.L__gpr_num_$s5, 28
	.equ	.L__gpr_num_$s6, 29
	.equ	.L__gpr_num_$s7, 30
	.equ	.L__gpr_num_$s8, 31

#else /* __ASSEMBLY__ */

#define __DEFINE_ASM_GPR_NUMS					\
"	.equ	.L__gpr_num_zero, 0\n"				\
"	.equ	.L__gpr_num_$zero, 0\n"				\
"	.equ	.L__gpr_num_$ra,  1\n"				\
"	.equ	.L__gpr_num_$tp,  2\n"				\
"	.equ	.L__gpr_num_$sp,  3\n"				\
"	.equ	.L__gpr_num_$a0,  4\n"				\
"	.equ	.L__gpr_num_$a1,  5\n"				\
"	.equ	.L__gpr_num_$a2,  6\n"				\
"	.equ	.L__gpr_num_$a3,  7\n"				\
"	.equ	.L__gpr_num_$a4,  8\n"				\
"	.equ	.L__gpr_num_$a5,  9\n"				\
"	.equ	.L__gpr_num_$a6, 10\n"				\
"	.equ	.L__gpr_num_$a7, 11\n"				\
"	.equ	.L__gpr_num_$t0, 12\n"				\
"	.equ	.L__gpr_num_$t1, 13\n"				\
"	.equ	.L__gpr_num_$t2, 14\n"				\
"	.equ	.L__gpr_num_$t3, 15\n"				\
"	.equ	.L__gpr_num_$t4, 16\n"				\
"	.equ	.L__gpr_num_$t5, 17\n"				\
"	.equ	.L__gpr_num_$t6, 18\n"				\
"	.equ	.L__gpr_num_$t7, 19\n"				\
"	.equ	.L__gpr_num_$t8, 20\n"				\
"	.equ	.L__gpr_num_$x,  21\n"				\
"	.equ	.L__gpr_num_$fp, 22\n"				\
"	.equ	.L__gpr_num_$s0, 23\n"				\
"	.equ	.L__gpr_num_$s1, 24\n"				\
"	.equ	.L__gpr_num_$s2, 25\n"				\
"	.equ	.L__gpr_num_$s3, 26\n"				\
"	.equ	.L__gpr_num_$s4, 27\n"				\
"	.equ	.L__gpr_num_$s5, 28\n"				\
"	.equ	.L__gpr_num_$s6, 29\n"				\
"	.equ	.L__gpr_num_$s7, 30\n"				\
"	.equ	.L__gpr_num_$s8, 31\n"

#endif /* __ASSEMBLY__ */

#endif /* __ASM_GPR_NUM_H */
