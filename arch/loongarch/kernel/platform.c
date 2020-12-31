// SPDX-License-Identifier: GPL-2.0
/*
 * Author: Huacai Chen <chenhuacai@loongson.cn>
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 *
 * This program is free software; you can redistribute	it and/or modify it
 * under  the terms of	the GNU General	 Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/smp.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/acpi.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <asm/bootinfo.h>
#include <asm/loongson.h>

static struct platform_device loongson3_cpufreq_device = {
	.name = "loongson3_cpufreq",
	.id = -1,
};

static int __init loongson_cpufreq_init(void)
{
	return platform_device_register(&loongson3_cpufreq_device);
}

arch_initcall(loongson_cpufreq_init);

static void enable_sci(void)
{
	u16 value;
	value = readw(LS7A_PM1_CNT_REG);
	value |= 1;
	writew(value, LS7A_PM1_CNT_REG);
}

static int __init loongson3_acpi_suspend_init(void)
{
#ifdef CONFIG_ACPI
	acpi_status status;
	unsigned long long suspend_addr = 0;

	if (acpi_disabled)
		return 0;

	enable_sci();
	status = acpi_evaluate_integer(NULL, "\\SADR", NULL, &suspend_addr);
	if (ACPI_FAILURE(status) || !suspend_addr) {
		pr_err("ACPI S3 is not support!\n");
		return -1;
	}
	loongson_sysconf.suspend_addr = (u64)phys_to_virt(suspend_addr);
#endif
	return 0;
}

device_initcall(loongson3_acpi_suspend_init);
