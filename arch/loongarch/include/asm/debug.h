/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */

#ifndef __LOONGARCH_ASM_DEBUG_H__
#define __LOONGARCH_ASM_DEBUG_H__

#include <linux/dcache.h>

/*
 * loongarch_debugfs_dir corresponds to the "loongarch" directory at the top
 * level of the DebugFS hierarchy. LoongArch-specific DebugFS entires should
 * be placed beneath this directory.
 */
extern struct dentry *loongarch_debugfs_dir;

#endif /* __LOONGARCH_ASM_DEBUG_H__ */
