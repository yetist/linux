/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#ifndef _ASM_INST_H
#define _ASM_INST_H

#include <linux/types.h>
#include <asm/asm.h>
#include <asm/errno.h>
#include <asm/ptrace.h>

#define INSN_NOP 0x03400000
#define INSN_BREAK 0x002a0000

#define ADDR_IMMMASK_LU52ID	0xFFF0000000000000
#define ADDR_IMMMASK_LU32ID	0x000FFFFF00000000
#define ADDR_IMMMASK_ADDU16ID	0x00000000FFFF0000

#define ADDR_IMMSHIFT_LU52ID	52
#define ADDR_IMMSHIFT_LU32ID	32
#define ADDR_IMMSHIFT_ADDU16ID	16

#define ADDR_IMM(addr, INSN)	((addr & ADDR_IMMMASK_##INSN) >> ADDR_IMMSHIFT_##INSN)

#define Inst_UncondBranchSIMM(x) \
	((int)((((LOONGARCHInst(x) & 0x3ff) | ((LOONGARCHInst(x) & 0x200) ? 0xfffffc00 : 0)) << 16) \
	| ((LOONGARCHInst(x) & 0x3fffc00) >> 10)))

enum reg0i15_op {
	break_op	= 0x54,
};

enum reg0i26_op {
	b_op		= 0x14,
	bl_op		= 0x15,
};

enum reg1i20_op {
	lu12iw_op	= 0x0a,
	lu32id_op	= 0x0b,
	pcaddi_op	= 0x0c,
	pcalau12i_op	= 0x0d,
	pcaddu12i_op	= 0x0e,
	pcaddu18i_op	= 0x0f,
};

enum reg1i21_op {
	beqz_op		= 0x10,
	bnez_op		= 0x11,
	bceqz_op	= 0x12,
	bcnez_op	= 0x12,
};

enum reg2_op {
	revb2h_op	= 0x0c,
	revb4h_op	= 0x0d,
	revb2w_op	= 0x0e,
	revbd_op	= 0x0f,
	revh2w_op	= 0x10,
	revhd_op	= 0x11,
};

enum reg2i5_op {
	slliw_op	= 0x81,
	srliw_op	= 0x89,
	sraiw_op 	= 0x91,
};

enum reg2i6_op {
	sllid_op	= 0x41,
	srlid_op	= 0x45,
	sraid_op	= 0x49,
};

enum reg2i12_op {
	addiw_op	= 0x0a,
	addid_op	= 0x0b,
	lu52id_op	= 0x0c,
	andi_op		= 0x0d,
	ori_op		= 0x0e,
	xori_op		= 0x0f,
	ldb_op		= 0xa0,
	ldh_op		= 0xa1,
	ldw_op		= 0xa2,
	ldd_op		= 0xa3,
	stb_op		= 0xa4,
	sth_op		= 0xa5,
	stw_op		= 0xa6,
	std_op		= 0xa7,
	ldbu_op		= 0xa8,
	ldhu_op		= 0xa9,
	ldwu_op		= 0xaa,
	flds_op		= 0xac,
	fsts_op		= 0xad,
	fldd_op		= 0xae,
	fstd_op		= 0xaf,
};

enum reg2i14_op {
	llw_op		= 0x20,
	scw_op		= 0x21,
	lld_op		= 0x22,
	scd_op		= 0x23,
	ldptrw_op	= 0x24,
	stptrw_op	= 0x25,
	ldptrd_op	= 0x26,
	stptrd_op	= 0x27,
};

enum reg2i16_op {
	addu16id_op	= 0x04,
	jirl_op		= 0x13,
	beq_op		= 0x16,
	bne_op		= 0x17,
	blt_op		= 0x18,
	bge_op		= 0x19,
	bltu_op		= 0x1a,
	bgeu_op		= 0x1b,
};

enum reg3_op {
	addw_op		= 0x20,
	addd_op		= 0x21,
	subw_op		= 0x22,
	subd_op		= 0x23,
	nor_op		= 0x28,
	and_op		= 0x29,
	or_op		= 0x2a,
	xor_op		= 0x2b,
	orn_op		= 0x2c,
	andn_op		= 0x2d,
	sllw_op		= 0x2e,
	srlw_op		= 0x2f,
	sraw_op		= 0x30,
	slld_op		= 0x31,
	srld_op		= 0x32,
	srad_op		= 0x33,
	mulw_op		= 0x38,
	mulhw_op	= 0x39,
	mulhwu_op	= 0x3a,
	muld_op		= 0x3b,
	mulhd_op	= 0x3c,
	mulhdu_op	= 0x3d,
	divw_op		= 0x42,
	modw_op		= 0x41,
	divwu_op	= 0x42,
	modwu_op	= 0x43,
	divd_op		= 0x44,
	modd_op		= 0x45,
	divdu_op	= 0x46,
	moddu_op	= 0x47,
	ldxb_op		= 0x7000,
	ldxh_op		= 0x7008,
	ldxw_op		= 0x7010,
	ldxd_op		= 0x7018,
	stxb_op		= 0x7020,
	stxh_op		= 0x7028,
	stxw_op		= 0x7030,
	stxd_op		= 0x7038,
	ldxbu_op	= 0x7040,
	ldxhu_op	= 0x7048,
	ldxwu_op	= 0x7050,
	fldxs_op	= 0x7060,
	fldxd_op	= 0x7068,
	fstxs_op	= 0x7070,
	fstxd_op	= 0x7078,
	amaddw_op	= 0x70c2,
	amaddd_op	= 0x70c3,
};

struct reg0i15_format {
	unsigned int immediate : 15;
	unsigned int opcode : 17;
};

struct reg0i26_format {
	unsigned int immediate_h : 10;
	unsigned int immediate_l : 16;
	unsigned int opcode : 6;
};

struct reg1i20_format {
	unsigned int rd : 5;
	unsigned int immediate : 20;
	unsigned int opcode : 7;
};

struct reg1i21_format {
	unsigned int immediate_h  : 5;
	unsigned int rj : 5;
	unsigned int immediate_l : 16;
	unsigned int opcode : 6;
};

struct reg2_format {
	unsigned int rd : 5;
	unsigned int rj : 5;
	unsigned int opcode : 22;
};

struct reg2i5_format {
	unsigned int rd : 5;
	unsigned int rj : 5;
	unsigned int immediate : 5;
	unsigned int opcode : 17;
};

struct reg2i6_format {
	unsigned int rd : 5;
	unsigned int rj : 5;
	unsigned int immediate : 6;
	unsigned int opcode : 16;
};

struct reg2i12_format {
	unsigned int rd : 5;
	unsigned int rj : 5;
	unsigned int immediate : 12;
	unsigned int opcode : 10;
};

struct reg2i14_format {
	unsigned int rd : 5;
	unsigned int rj : 5;
	unsigned int immediate : 14;
	unsigned int opcode : 8;
};

struct reg2i16_format {
	unsigned int rd : 5;
	unsigned int rj : 5;
	unsigned int immediate : 16;
	unsigned int opcode : 6;
};

struct reg3_format {
	unsigned int rd : 5;
	unsigned int rj : 5;
	unsigned int rk : 5;
	unsigned int opcode : 17;
};

union loongarch_instruction {
	unsigned int word;
	struct reg0i15_format	reg0i15_format;
	struct reg0i26_format	reg0i26_format;
	struct reg1i20_format	reg1i20_format;
	struct reg1i21_format	reg1i21_format;
	struct reg2_format	reg2_format;
	struct reg2i5_format	reg2i5_format;
	struct reg2i6_format	reg2i6_format;
	struct reg2i12_format	reg2i12_format;
	struct reg2i14_format	reg2i14_format;
	struct reg2i16_format	reg2i16_format;
	struct reg3_format	reg3_format;
};

#define LOONGARCH_INSN_SIZE	sizeof(union loongarch_instruction)

enum loongarch_gpr {
	LOONGARCH_GPR_ZERO = 0,
	LOONGARCH_GPR_RA = 1,
	LOONGARCH_GPR_TP = 2,
	LOONGARCH_GPR_SP = 3,
	LOONGARCH_GPR_A0 = 4,	/* Reused as V0 for return value */
	LOONGARCH_GPR_A1,	/* Reused as V1 for return value */
	LOONGARCH_GPR_A2,
	LOONGARCH_GPR_A3,
	LOONGARCH_GPR_A4,
	LOONGARCH_GPR_A5,
	LOONGARCH_GPR_A6,
	LOONGARCH_GPR_A7,
	LOONGARCH_GPR_T0 = 12,
	LOONGARCH_GPR_T1,
	LOONGARCH_GPR_T2,
	LOONGARCH_GPR_T3,
	LOONGARCH_GPR_T4,
	LOONGARCH_GPR_T5,
	LOONGARCH_GPR_T6,
	LOONGARCH_GPR_T7,
	LOONGARCH_GPR_T8,
	LOONGARCH_GPR_FP = 22,
	LOONGARCH_GPR_S0 = 23,
	LOONGARCH_GPR_S1,
	LOONGARCH_GPR_S2,
	LOONGARCH_GPR_S3,
	LOONGARCH_GPR_S4,
	LOONGARCH_GPR_S5,
	LOONGARCH_GPR_S6,
	LOONGARCH_GPR_S7,
	LOONGARCH_GPR_S8,
	LOONGARCH_GPR_MAX
};

static inline bool is_pc_insn(union loongarch_instruction insn)
{
	return insn.reg1i20_format.opcode >= pcaddi_op &&
			insn.reg1i20_format.opcode <= pcaddu18i_op;
}

static inline bool is_branch_insn(union loongarch_instruction insn)
{
	return insn.reg1i21_format.opcode >= beqz_op &&
			insn.reg1i21_format.opcode <= bgeu_op;
}

static inline bool cond_beqz(struct pt_regs *regs, int rj)
{
	return regs->regs[rj] == 0;
}

static inline bool cond_bnez(struct pt_regs *regs, int rj)
{
	return regs->regs[rj] != 0;
}

static inline bool cond_beq(struct pt_regs *regs, int rj, int rd)
{
	return regs->regs[rj] == regs->regs[rd];
}

static inline bool cond_bne(struct pt_regs *regs, int rj, int rd)
{
	return regs->regs[rj] != regs->regs[rd];
}

static inline bool cond_blt(struct pt_regs *regs, int rj, int rd)
{
	return (long)regs->regs[rj] < (long)regs->regs[rd];
}

static inline bool cond_bge(struct pt_regs *regs, int rj, int rd)
{
	return (long)regs->regs[rj] >= (long)regs->regs[rd];
}

static inline bool cond_bltu(struct pt_regs *regs, int rj, int rd)
{
	return regs->regs[rj] < regs->regs[rd];
}

static inline bool cond_bgeu(struct pt_regs *regs, int rj, int rd)
{
	return regs->regs[rj] >= regs->regs[rd];
}

unsigned long bs_dest_16(unsigned long now, unsigned int si);
unsigned long bs_dest_21(unsigned long now, unsigned int h, unsigned int l);
unsigned long bs_dest_26(unsigned long now, unsigned int h, unsigned int l);

int simu_branch(struct pt_regs *regs, union loongarch_instruction insn);
int simu_pc(struct pt_regs *regs, union loongarch_instruction insn);

int larch_insn_read(void *addr, u32 *insnp);
int larch_insn_write(void *addr, u32 insn);
int larch_insn_patch_text(void *addr, u32 insn);

u32 larch_insn_gen_nop(void);
u32 larch_insn_gen_b(unsigned long pc, unsigned long dest);
u32 larch_insn_gen_bl(unsigned long pc, unsigned long dest);

u32 larch_insn_gen_addu16id(enum loongarch_gpr rd, enum loongarch_gpr rj, int imm);
u32 larch_insn_gen_or(enum loongarch_gpr rd, enum loongarch_gpr rj,
			enum loongarch_gpr rk);
u32 larch_insn_gen_move(enum loongarch_gpr rd, enum loongarch_gpr rj);

u32 larch_insn_gen_lu32id(enum loongarch_gpr rd, int imm);
u32 larch_insn_gen_lu52id(enum loongarch_gpr rd, enum loongarch_gpr rj, int imm);
u32 larch_insn_gen_jirl(enum loongarch_gpr rd, enum loongarch_gpr rj, unsigned long pc, unsigned long dest);
#endif /* _ASM_INST_H */
