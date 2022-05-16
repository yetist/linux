/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Definitions for the FPU register names
 *
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#ifndef _ASM_FPREGDEF_H
#define _ASM_FPREGDEF_H

/*
 * Current binutils wrongly expects *GPRs* at FCSR position for the FCSR
 * operation insns, so define aliases for those used.
 */
#define fcsr0	$r0
#define fcsr1	$r1
#define fcsr2	$r2
#define fcsr3	$r3
#define vcsr16	$r16

#endif /* _ASM_FPREGDEF_H */
