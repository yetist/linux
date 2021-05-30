/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Stack trace management functions
 *
 *  Copyright (C) 2006 Atsushi Nemoto <anemo@mba.ocn.ne.jp>
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 */
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#include <linux/stacktrace.h>
#include <linux/export.h>

#include <asm/stacktrace.h>
#include <asm/unwind.h>

typedef bool (*stack_trace_consume_fn)(struct stack_trace *trace,
					      unsigned long addr);

static bool consume_entry(struct stack_trace *trace, unsigned long addr)
{
	if (trace->nr_entries >= trace->max_entries)
		return false;

	if (trace->skip > 0) {
		trace->skip--;
		return true;
	}

	trace->entries[trace->nr_entries++] = addr;
	return trace->nr_entries < trace->max_entries;
}

static bool consume_entry_nosched(struct stack_trace *trace,
					  unsigned long addr)
{
	if (in_sched_functions(addr))
		return true;
	return consume_entry(trace, addr);
}

static void save_context_stack(struct task_struct *tsk,
					struct stack_trace *trace,
					struct pt_regs *regs,
					stack_trace_consume_fn fn)
{
	struct pt_regs dummyregs;
	struct unwind_state state;
	unsigned long addr;

	regs = &dummyregs;

	if (tsk == current) {
		regs->csr_era = (unsigned long)__builtin_return_address(0);
		regs->regs[3] = (unsigned long)__builtin_frame_address(0);
	} else {
		regs->csr_era = thread_saved_ra(tsk);
		regs->regs[3] = thread_saved_fp(tsk);
	}

	regs->regs[1] = 0;
	regs->regs[22] = 0;

	for (unwind_start(&state, tsk, regs);
	      !unwind_done(&state); unwind_next_frame(&state)) {
		addr = unwind_get_return_address(&state);
		if (!addr || !fn(trace, addr))
			return;
	}
}

/*
 * Save stack-backtrace addresses into a stack_trace buffer.
 */
void save_stack_trace(struct stack_trace *trace)
{
	stack_trace_consume_fn consume = consume_entry;

	WARN_ON(trace->nr_entries || !trace->max_entries);

	save_context_stack(current, trace, NULL, consume);
}
EXPORT_SYMBOL_GPL(save_stack_trace);

void save_stack_trace_regs(struct pt_regs *regs, struct stack_trace *trace)
{
	stack_trace_consume_fn consume = consume_entry;

	/* We don't want this function nor the caller */
	trace->skip += 7;
	WARN_ON(trace->nr_entries || !trace->max_entries);

	save_context_stack(current, trace, regs, consume);
}
EXPORT_SYMBOL_GPL(save_stack_trace_regs);

void save_stack_trace_tsk(struct task_struct *tsk,
					struct stack_trace *trace)
{
	stack_trace_consume_fn consume = consume_entry_nosched;

	WARN_ON(trace->nr_entries || !trace->max_entries);

	save_context_stack(tsk, trace, NULL, consume);
}
EXPORT_SYMBOL_GPL(save_stack_trace_tsk);
