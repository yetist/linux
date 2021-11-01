// SPDX-License-Identifier: GPL-2.0-or-later
#include <string.h>
#include <stdlib.h>

#include <asm/orc_types.h>
#include <linux/objtool.h>
#include <objtool/orc.h>
#include <objtool/warn.h>
#include <objtool/endianness.h>

struct orc_entry arch_null = {
	.sp_reg  = ORC_REG_UNDEFINED,
	.bp_reg  = ORC_REG_UNDEFINED,
	.type    = UNWIND_HINT_TYPE_CALL,
};

int arch_init_orc_entry(struct orc_entry *orc, struct cfi_state *cfi,
			  struct instruction *insn)
{
	struct cfi_reg *bp = &cfi->regs[CFI_BP];

	memset(orc, 0, sizeof(*orc));

	if (!cfi) {
		orc->end = 0;
		orc->sp_reg = ORC_REG_UNDEFINED;
		return 0;
	}

	orc->end = cfi->end;
	orc->signal = cfi->signal;

	if (cfi->cfa.base == CFI_UNDEFINED) {
		orc->sp_reg = ORC_REG_UNDEFINED;
		return 0;
	}

	switch (cfi->cfa.base) {
	case CFI_SP:
		orc->sp_reg = ORC_REG_SP;
		break;
	case CFI_SP_INDIRECT:
		orc->sp_reg = ORC_REG_SP_INDIRECT;
		break;
	case CFI_BP:
		orc->sp_reg = ORC_REG_BP;
		break;
	case CFI_BP_INDIRECT:
		orc->sp_reg = ORC_REG_BP_INDIRECT;
		break;
	case CFI_R10:
		orc->sp_reg = ORC_REG_R10;
		break;
	case CFI_R13:
		orc->sp_reg = ORC_REG_R13;
		break;
	case CFI_DI:
		orc->sp_reg = ORC_REG_DI;
		break;
	case CFI_DX:
		orc->sp_reg = ORC_REG_DX;
		break;
	default:
		WARN_FUNC("unknown CFA base reg %d",
			  insn->sec, insn->offset, cfi->cfa.base);
		return -1;
	}

	switch (bp->base) {
	case CFI_UNDEFINED:
		orc->bp_reg = ORC_REG_UNDEFINED;
		break;
	case CFI_CFA:
		orc->bp_reg = ORC_REG_PREV_SP;
		break;
	case CFI_BP:
		orc->bp_reg = ORC_REG_BP;
		break;
	default:
		WARN_FUNC("unknown BP base reg %d",
			  insn->sec, insn->offset, bp->base);
		return -1;
	}

	orc->sp_offset = cfi->cfa.offset;
	orc->bp_offset = bp->offset;
	orc->type = cfi->type;

	return 0;
}

int arch_write_orc_entry(struct elf *elf, struct section *orc_sec,
			   struct section *ip_sec, unsigned int idx,
			   struct section *insn_sec, unsigned long insn_off,
			   struct orc_entry *o)
{
	struct orc_entry *orc;

	/* populate ORC data */
	orc = (struct orc_entry *)orc_sec->data->d_buf + idx;
	memcpy(orc, o, sizeof(*orc));
	orc->sp_offset = bswap_if_needed(elf, orc->sp_offset);
	orc->bp_offset = bswap_if_needed(elf, orc->bp_offset);

	/* populate reloc for ip */
	if (!elf_add_reloc_to_insn(elf, ip_sec, idx * sizeof(int), R_X86_64_PC32,
				   insn_sec, insn_off, NULL))
		return -1;

	return 0;
}

static const char *reg_name(unsigned int reg)
{
	switch (reg) {
	case ORC_REG_PREV_SP:
		return "prevsp";
	case ORC_REG_DX:
		return "dx";
	case ORC_REG_DI:
		return "di";
	case ORC_REG_BP:
		return "bp";
	case ORC_REG_SP:
		return "sp";
	case ORC_REG_R10:
		return "r10";
	case ORC_REG_R13:
		return "r13";
	case ORC_REG_BP_INDIRECT:
		return "bp(ind)";
	case ORC_REG_SP_INDIRECT:
		return "sp(ind)";
	default:
		return "?";
	}
}

static const char *orc_type_name(unsigned int type)
{
	switch (type) {
	case UNWIND_HINT_TYPE_CALL:
		return "call";
	case UNWIND_HINT_TYPE_REGS:
		return "regs";
	case UNWIND_HINT_TYPE_REGS_PARTIAL:
		return "regs (partial)";
	default:
		return "?";
	}
}

static void print_reg(unsigned int reg, int offset)
{
	if (reg == ORC_REG_BP_INDIRECT)
		printf("(bp%+d)", offset);
	else if (reg == ORC_REG_SP_INDIRECT)
		printf("(sp)%+d", offset);
	else if (reg == ORC_REG_UNDEFINED)
		printf("(und)");
	else
		printf("%s%+d", reg_name(reg), offset);
}

void arch_print_reg(struct elf *dummy_elf, struct orc_entry orc)
{
	printf(" sp:");

	print_reg(orc.sp_reg, bswap_if_needed(dummy_elf, orc.sp_offset));

	printf(" bp:");

	print_reg(orc.bp_reg, bswap_if_needed(dummy_elf, orc.bp_offset));

	printf(" type:%s signal:%d end:%d\n",
	       orc_type_name(orc.type), orc.signal, orc.end);
}
