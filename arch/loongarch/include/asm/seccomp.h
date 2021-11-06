/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_SECCOMP_H
#define _ASM_SECCOMP_H

#include <asm/unistd.h>

#include <asm-generic/seccomp.h>

#ifdef CONFIG_64BIT
# define SECCOMP_ARCH_NATIVE		AUDIT_ARCH_LOONGARCH64
# define SECCOMP_ARCH_NATIVE_NR		NR_syscalls
# define SECCOMP_ARCH_NATIVE_NAME	"loongarch64"
#else /* !CONFIG_64BIT */
# define SECCOMP_ARCH_NATIVE		AUDIT_ARCH_LOONGARCH32
# define SECCOMP_ARCH_NATIVE_NR		NR_syscalls
# define SECCOMP_ARCH_NATIVE_NAME	"loongarch32"
#endif

#endif /* _ASM_SECCOMP_H */
