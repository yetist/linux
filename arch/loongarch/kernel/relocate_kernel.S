/* SPDX-License-Identifier: GPL-2.0 */
/*
 * relocate_kernel.S for kexec
 * Created by <nschichan@corp.free.fr> on Thu Oct 12 17:49:57 2006
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#include <asm/asm.h>
#include <asm/asmmacro.h>
#include <asm/regdef.h>
#include <asm/loongarch.h>
#include <asm/stackframe.h>
#include <asm/addrspace.h>

SYM_CODE_START(relocate_new_kernel)
	la		t0, arg0
	PTR_L		a0, t0, 0
	la		t0, arg1
	PTR_L		a1, t0, 0
	la		t0, arg2
	PTR_L		a2, t0, 0
	la		t0, arg3
	PTR_L		a3, t0, 0

	la		t0, kexec_indirection_page
	PTR_L		s0, t0, 0
	la		t0, kexec_start_address
	PTR_L		s1, t0, 0

process_entry:
	PTR_L		s2, s0, 0
	PTR_ADDI	s0, s0, SZREG

	/*
	 * In case of a kdump/crash kernel, the indirection page is not
	 * populated as the kernel is directly copied to a reserved location
	 */
	beqz		s2, done

	/* destination page */
	andi		s3, s2, 0x1
	beq		s3, zero, 1f
	li.w		t0, ~0x1
	and		s4, s2, t0	/* store destination addr in s4 */
	b		process_entry

1:
	/* indirection page, update s0	*/
	andi		s3, s2, 0x2
	beq		s3, zero, 1f
	li.w		t0, ~0x2
	and		s0, s2, t0
	b		process_entry

1:
	/* done page */
	andi		s3, s2, 0x4
	beq		s3, zero, 1f
	b		done
1:
	/* source page */
	andi		s3, s2, 0x8
	beq		s3, zero, process_entry
	li.w		t0, ~0x8
	and		s2, s2, t0
	li.w		s6, (1 << _PAGE_SHIFT) / SZREG

copy_word:
	/* copy page word by word */
	REG_L		s5, s2, 0
	REG_S		s5, s4, 0
	PTR_ADDI	s4, s4, SZREG
	PTR_ADDI	s2, s2, SZREG
	LONG_ADDI	s6, s6, -1
	beq		s6, zero, process_entry
	b		copy_word
	b		process_entry

done:
#ifdef CONFIG_SMP
	/*
	 * kexec_flag reset is signal to other CPUs what kernel
	 * was moved to it's location. Note - we need relocated
	 * address of kexec_flag.
	 */
	bl		1f
 1:	move		t1,ra;
	la		t2,1b
	la		t0,kexec_flag
	PTR_SUB		t0,t0,t2;
	PTR_ADD		t0,t1,t0;
	LONG_S		zero,t0,0
#endif

	dbar		0
	/* jump to kexec_start_address */
	jr		s1
SYM_CODE_END(relocate_new_kernel)

#ifdef CONFIG_SMP
/*
 * Other CPUs should wait until code is relocated and
 * then start at entry (?) point.
 */
SYM_CODE_START(kexec_smp_wait)
	la		t0, s_arg0
	PTR_L		a0, t0, 0
	la		t0, s_arg1
	PTR_L		a1, t0, 0
	la		t0, s_arg2
	PTR_L		a2, t0, 0
	la		t0, s_arg3
	PTR_L		a3, t0, 0
	la		t0, kexec_start_address
	PTR_L		s1, t0, 0

	/*
	 * Non-relocated address works for args and kexec_start_address (old
	 * kernel is not overwritten). But we need relocated address of
	 * kexec_flag.
	 */
	bl		1f
1:	move		t1,ra;
	la		t2,1b
	la		t0,kexec_flag
	PTR_SUB		t0,t0,t2;
	PTR_ADD		t0,t1,t0;

1:	LONG_L		s0, t0, 0
	bne		s0, zero,1b

	dbar		0

#ifdef CONFIG_CPU_LOONGSON64
	/*
	 * s1:initfn
	 * a0:base t1:cpuid t2:node t3:core t4:count
	 */
	csrrd		t1, LOONGARCH_CSR_CPUID
	andi		t1, t1, CSR_CPUID_COREID
	andi		t3, t1, 0x3
	slli.w		t3, t3, 8              /* get core id */
	or		a0, a0, t3
	andi		t2, t1, 0x3c
	slli.d		t2, t2, 42             /* get node id */
	or		a0, a0, t2
1:	li.w		t4, 0x100              /* wait for init loop */
2:	addi.w		t4, t4, -1             /* limit mailbox access */
	bnez		t4, 2b
	ld.w		s1, a0, 0x20           /* check PC as an indicator */
	beqz		s1, 1b
	ld.d		s1, a0, 0x20           /* get PC via mailbox */
	ld.d		sp, a0, 0x28           /* get SP via mailbox */
	ld.d		tp, a0, 0x30           /* get TP via mailbox */
	ld.d		a1, a0, 0x38
#endif

	jr		s1                     /* jump to initial PC */
SYM_CODE_END(kexec_smp_wait)
#endif

#ifdef __loongarch64
       /* all PTR's must be aligned to 8 byte in 64-bit mode */
       .align  3
#endif

/*
 * All parameters to new kernel are passed in registers a0-a3.
 * kexec_args[0..3] are used to prepare register values.
 */
SYM_DATA_START(kexec_args)
arg0:	PTR		0x0
arg1:	PTR		0x0
arg2:	PTR		0x0
arg3:	PTR		0x0
SYM_DATA_END(kexec_args)

#ifdef CONFIG_SMP
/*
 * Secondary CPUs may have different kernel parameters in
 * their registers a0-a3. secondary_kexec_args[0..3] are used
 * to prepare register values.
 */
SYM_DATA_START(secondary_kexec_args)
s_arg0: PTR		0x0
s_arg1: PTR		0x0
s_arg2: PTR		0x0
s_arg3: PTR		0x0
SYM_DATA_END(secondary_kexec_args)

SYM_DATA_START(kexec_flag)
	LONG		0x1
SYM_DATA_END(kexec_flag)

#endif

SYM_DATA_START(kexec_start_address)
	PTR		0x0
SYM_DATA_END(kexec_start_address)

SYM_DATA_START(kexec_indirection_page)
	PTR		0
SYM_DATA_END(kexec_indirection_page)

relocate_new_kernel_end:

SYM_DATA_START(relocate_new_kernel_size)
	PTR		relocate_new_kernel_end - relocate_new_kernel
SYM_DATA_END(relocate_new_kernel_size)
