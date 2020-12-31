// SPDX-License-Identifier: GPL-2.0
/*
 * Author: Huacai Chen <chenhuacai@loongson.cn>
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 */
#include <linux/acpi.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/pm.h>
#include <linux/suspend.h>

#include <asm/loongson.h>
#include <asm/setup.h>
#include <asm/tlbflush.h>

void enable_gpe_wakeup(void)
{
	struct list_head *node, *next;
	u32 data = 0;

	list_for_each_safe(node, next, &acpi_wakeup_device_list) {
		struct acpi_device *dev =
			container_of(node, struct acpi_device, wakeup_list);

		if (!dev->wakeup.flags.valid
			|| ACPI_STATE_S3 > (u32) dev->wakeup.sleep_state
			|| !(device_may_wakeup(&dev->dev)
			|| dev->wakeup.prepare_count))
			continue;

		data |= (1 << dev->wakeup.gpe_number);
	}
	writel(data, (volatile void *)loongson_sysconf.gpe0_ena_reg);
}

void enable_pci_wakeup(void)
{
	u16 value;

	value = readw((volatile void *)loongson_sysconf.pm1_evt_reg);
	value |= ACPI_PCI_WAKE_STATUS;
	writew(value, (volatile void *)loongson_sysconf.pm1_evt_reg);

	if (loongson_sysconf.pci_wake_enabled) {
		value = readw((volatile void *)loongson_sysconf.pm1_ena_reg);
		value &= (~ACPI_PCI_WAKE_STATUS);
		writew(value, (volatile void *)loongson_sysconf.pm1_ena_reg);
	}
}
