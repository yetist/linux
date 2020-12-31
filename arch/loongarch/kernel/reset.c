// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#include <linux/kernel.h>
#include <linux/acpi.h>
#include <linux/cpu.h>
#include <linux/efi.h>
#include <linux/export.h>
#include <linux/pm.h>
#include <linux/types.h>
#include <linux/reboot.h>
#include <linux/delay.h>
#include <linux/console.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/of_fdt.h>

#include <acpi/reboot.h>
#include <asm/compiler.h>
#include <asm/idle.h>
#include <asm/loongarch.h>
#include <asm/reboot.h>

static void default_halt(void)
{
	local_irq_disable();
	clear_csr_ecfg(ECFG0_IM);

	pr_notice("\n\n** You can safely turn off the power now **\n\n");
	console_flush_on_panic(CONSOLE_FLUSH_PENDING);

	while (true) {
		__arch_cpu_idle();
	}
}

static void default_poweroff(void)
{
#ifdef CONFIG_EFI
	efi.reset_system(EFI_RESET_SHUTDOWN, EFI_SUCCESS, 0, NULL);
#endif
	while (true) {
		__arch_cpu_idle();
	}
}

static void default_restart(void)
{
#ifdef CONFIG_EFI
	if (efi_capsule_pending(NULL))
		efi_reboot(REBOOT_WARM, NULL);
	else
		efi_reboot(REBOOT_COLD, NULL);
#endif
	if (!acpi_disabled)
		acpi_reboot();

	while (true) {
		__arch_cpu_idle();
	}
}

void (*pm_restart)(void);
EXPORT_SYMBOL(pm_restart);

void (*pm_power_off)(void);
EXPORT_SYMBOL(pm_power_off);

void machine_halt(void)
{
#ifdef CONFIG_SMP
	preempt_disable();
	smp_send_stop();
#endif
	default_halt();
}

void machine_power_off(void)
{
#ifdef CONFIG_SMP
	preempt_disable();
	smp_send_stop();
#endif
	pm_power_off();
}

void machine_restart(char *command)
{
#ifdef CONFIG_SMP
	preempt_disable();
	smp_send_stop();
#endif
	do_kernel_restart(command);
	pm_restart();
}

#ifdef CONFIG_KEXEC

/* 0X80000000~0X80200000 is safe */
#define KEXEC_CTRL_CODE	TO_CACHE(0x100000UL)
#define KEXEC_BLOB_ADDR	TO_CACHE(0x108000UL)

static char *kexec_cmdline;
static char *kdump_cmdline;

#define FDT_PROP_BOOTARGS	"bootargs"

static int setup_dtb(char *cmdline, void *dtb)
{
	int offs;

	fdt_open_into(initial_boot_params, dtb, SZ_64K);

	offs = fdt_path_offset(dtb, "/chosen");
	if (offs < 0)
		return -EINVAL;

	/* add bootargs */
	fdt_setprop_string(dtb, offs, FDT_PROP_BOOTARGS, cmdline);

	fdt_pack(dtb);

	return 0;
}

static int loongson_kexec_prepare(struct kimage *image)
{
	int i;
	void *dtb = (void *)KEXEC_BLOB_ADDR;
	char *cmdline, *bootloader = "kexec";

	if (image->type == KEXEC_TYPE_DEFAULT)
		cmdline = kexec_cmdline;
	else
		cmdline = kdump_cmdline;

	for (i = 0; i < image->nr_segments; i++) {
		if (!strncmp(bootloader, (char *)image->segment[i].buf, 5)) {
			memcpy(cmdline, image->segment[i].buf, COMMAND_LINE_SIZE);
			break;
		}
	}

	setup_dtb((char *)cmdline, dtb);

	/* kexec/kdump need a safe page to save reboot_code_buffer */
	image->control_code_page = virt_to_page((void *)KEXEC_CTRL_CODE);

	return 0;
}

static void loongson_kexec_shutdown(void)
{
#ifdef CONFIG_SMP
	int cpu;

	/* All CPUs go to reboot_code_buffer */
	for_each_possible_cpu(cpu)
		if (!cpu_online(cpu))
			cpu_device_up(get_cpu_device(cpu));

	secondary_kexec_args[0] = TO_UNCACHE(0x1fe01000);
#endif
	kexec_args[0] = fw_arg0;
	kexec_args[1] = TO_PHYS(KEXEC_BLOB_ADDR);
}

static void loongson_crash_shutdown(struct pt_regs *regs)
{
	default_machine_crash_shutdown(regs);
#ifdef CONFIG_SMP
	secondary_kexec_args[0] = TO_UNCACHE(0x1fe01000);
#endif
	kexec_args[0] = fw_arg0;
	kexec_args[1] = TO_PHYS(KEXEC_BLOB_ADDR);
}

#endif

static int __init loongarch_reboot_setup(void)
{
	pm_restart = default_restart;
	pm_power_off = default_poweroff;

#ifdef CONFIG_KEXEC
	_machine_kexec_prepare = loongson_kexec_prepare;
	_machine_kexec_shutdown = loongson_kexec_shutdown;
	_machine_crash_shutdown = loongson_crash_shutdown;

	kexec_cmdline = kmalloc(COMMAND_LINE_SIZE, GFP_KERNEL);
	kdump_cmdline = kmalloc(COMMAND_LINE_SIZE, GFP_KERNEL);
#endif

	return 0;
}

arch_initcall(loongarch_reboot_setup);
