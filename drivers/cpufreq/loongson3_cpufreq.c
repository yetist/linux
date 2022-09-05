/*
 * CPUFreq driver for the loongson-3 processors
 *
 * All revisions of Loongson-3 processor support this feature.
 *
 * Author: Huacai Chen <chenhuacai@loongson.cn>
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/cpufreq.h>
#include <linux/platform_device.h>

#include <asm/idle.h>
#include <asm/loongarch.h>
#include <asm/loongson.h>

struct smc_message {
	union {
		u32 value;
		struct {
			u32 arg : 24;
			u8  cmd : 7; /* Return 0x7f if command failed */
			u8  complete : 1;
		};
	};
};

/* Belows are commands in cmd registers */

#define CMD_GET_VERSION			0x1
/* Interface Version, input none, return version */

/* Features */
#define CMD_GET_FEATURES		0x2
/* Get features that SMC implemented, input index, output feature flags */
#define CMD_GET_ENABLED_FEATURES	0x3
/* Get currently enabled features, input index, output feature flags */
#define CMD_SET_ENABLED_FEATURES	0x4
/* Set features enabled state, input index and flags, output sucessfully enabled flags */
struct feature_args {
	u16 flags : 16;
	u8  index : 8;
};

#define FEATURE_INDEX_GENERAL	0x0
#define FEATURE_INDEX_ADVANCED	0x1

/* General Feature Flags */
#define FEATURE_FREQ_SCALE	BIT(0)
#define FEATURE_VOLTAGE_SCALE	BIT(1)
#define FEATURE_BOOST		BIT(2) /* Enable Boost means set PLL from 1.6GHz to 2GHz */
#define FEATURE_SENSORS		BIT(3) /* Sensors mounted on EC */
#define FEATURE_FAN_CONTROL	BIT(4)

/* Freqscale Related */
#define CMD_SET_DVFS_POLICY	0x5
/* Input CPUNum, output frequency, in MHz? */
#define CMD_GET_FREQ_LEVELS	0x6
/* Input none, output levels */
struct freq_level_args {
	u8 min_level : 8;
	u8 max_normal_level : 8;
	u8 max_boost_level : 8;
};

#define CMD_GET_FREQ_INFO	0x7
/* Input index and info, output info */
#define CMD_SET_FREQ_INFO	0x8
/* Input index and info, output none */

#define FREQ_INFO_INDEX_LEVEL_FREQ	0x0 /* Freq in MHz? For each shadow level */
#define FREQ_INFO_INDEX_CORE_FREQ	0x1 /* Freq in MHz? Current frequency of each core.*/
struct freq_info_args {
	u16 info : 16;
	u8  index : 8;
};

#define CMD_SET_CPU_LEVEL	0x9
/* Input cpu mask and level, output none */
/*
 * Note: This command return as completed only means
 * SMC already knows the request, does not means the
 * CPU freqency have changed. SMC should ensure constant
 * counter frequency unchanged.
 */
struct freq_level_setting_args {
	u16 cpumask : 16;
	u8  level : 8;
};

/* TEMP Sensors */
#define CMD_GET_SENSOR_NUM	0x10
/* Input none, output Number of sensors in u4 */

#define CMD_GET_SENSOR_STATUS	0x11
/* Input sensor_id and info_type, output info */
#define SENSOR_INFO_TYPE_TEMP	0x0
#define SENSOR_INFO_TYPE_VOLTAGE	0x1
#define SENSOR_INFO_TYPE_NAMESTR1	0x2
#define SENSOR_INFO_TYPE_NAMESTR2	0x3
#define SENSOR_INFO_TYPE_NAMESTR3	0x4
#define SENSOR_INFO_TYPE_NAMESTR4	0x5
#define SENSOR_INFO_TYPE_FLAGS		0xf
#define SENSOR_FLAG_TEMP	BIT(0)
#define SENSOR_FLAG_VOLTAGE	BIT(1)
struct sensor_info_args {
	union {
		u16 val;
		u16 volt; /* Voltage, in mV */
		s16 temp; /* Signed 16bit, in Celsius */
	};
	u8 info_type : 4;
	u8 sensor_id : 4;
};

/* Fan Control */
#define CMD_GET_FAN_NUM		0x12
/* Input none, output Number of fans in u4 */

#define CMD_GET_FAN_INFO	0x13
/* Input sensor_id and info_type, output info */
#define CMD_SET_FAN_INFO	0x14
/* Input sensor_id andinfo_type info, output none */
#define FAN_INFO_TYPE_INDEX_RPM	0x0 /* Return RPM, can not set */
#define FAN_INFO_TYPE_LEVEL	0x1 /* PWM Level, 0~255, only set with manual mode */
#define FAN_INFO_TYPE_FLAGS	0xf /* Determine Mode */
#define FAN_INFO_TYPE_NAMESTR1	0x2
#define FAN_INFO_TYPE_NAMESTR2	0x3
#define FAN_INFO_TYPE_NAMESTR3	0x4
#define FAN_INFO_TYPE_NAMESTR4	0x5
#define FAN_FLAG_AUTO	BIT(0)
#define FAN_FLAG_MANUAL	BIT(1)

struct fan_info_args {
	u16 val;
	u8  info_type : 4;
	u8  fan_id : 4;
};

static inline int do_service_request(u8 cmd, void *arg)
{
	int retries;
	struct smc_message msg;

	msg.value = iocsr_read32(LOONGARCH_IOCSR_SMCMBX);
	if (!msg.complete)
		return -1;

	msg.cmd = cmd;
	msg.arg = *(u32 *)arg;
	msg.complete = 0x0;

	iocsr_write32(msg.value, LOONGARCH_IOCSR_SMCMBX);
	iocsr_write32(iocsr_read32(LOONGARCH_IOCSR_MISC_FUNC) | IOCSR_MISC_FUNC_SOFT_INT,
			LOONGARCH_IOCSR_MISC_FUNC);

	for (retries = 0; retries < 10000; retries++) {
		msg.value = iocsr_read32(LOONGARCH_IOCSR_SMCMBX);
		if (msg.complete)
			break;

		usleep_range(4, 5);
	}

	if (!msg.complete || msg.cmd == 0x7f)
		return -1;

	*(u32 *)arg = msg.arg;

	return 0;
}

static int boost_supported = 0;
static struct mutex cpufreq_mutex[MAX_PACKAGES];

enum freq {
	FREQ_LEV0, /* Reserved */
	FREQ_LEV1, FREQ_LEV2, FREQ_LEV3, FREQ_LEV4,
	FREQ_LEV5, FREQ_LEV6, FREQ_LEV7, FREQ_LEV8,
	FREQ_LEV9, FREQ_LEV10, FREQ_LEV11, FREQ_LEV12,
	FREQ_LEV13, FREQ_LEV14, FREQ_LEV15, FREQ_LEV16,
	FREQ_RESV
};

/* For Loongson-3A5000, support boost */
static struct cpufreq_frequency_table loongson3_cpufreq_table[] = {
	{0, FREQ_LEV0, CPUFREQ_ENTRY_INVALID},
	{0, FREQ_LEV1, CPUFREQ_ENTRY_INVALID},
	{0, FREQ_LEV2, CPUFREQ_ENTRY_INVALID},
	{0, FREQ_LEV3, CPUFREQ_ENTRY_INVALID},
	{0, FREQ_LEV4, CPUFREQ_ENTRY_INVALID},
	{0, FREQ_LEV5, CPUFREQ_ENTRY_INVALID},
	{0, FREQ_LEV6, CPUFREQ_ENTRY_INVALID},
	{0, FREQ_LEV7, CPUFREQ_ENTRY_INVALID},
	{0, FREQ_LEV8, CPUFREQ_ENTRY_INVALID},
	{0, FREQ_LEV9, CPUFREQ_ENTRY_INVALID},
	{0, FREQ_LEV10, CPUFREQ_ENTRY_INVALID},
	{0, FREQ_LEV11, CPUFREQ_ENTRY_INVALID},
	{0, FREQ_LEV12, CPUFREQ_ENTRY_INVALID},
	{0, FREQ_LEV13, CPUFREQ_ENTRY_INVALID},
	{0, FREQ_LEV14, CPUFREQ_ENTRY_INVALID},
	{0, FREQ_LEV15, CPUFREQ_ENTRY_INVALID},
	{0, FREQ_LEV16, CPUFREQ_ENTRY_INVALID},
	{0, FREQ_RESV, CPUFREQ_TABLE_END},
};

static unsigned int loongson3_cpufreq_get(unsigned int cpu)
{
	struct freq_info_args args;

	args.info = cpu;
	args.index = FREQ_INFO_INDEX_CORE_FREQ;
	do_service_request(CMD_GET_FREQ_INFO, &args);

	return (args.info * 1000);
}

static int loongson3_cpufreq_set(struct cpufreq_policy *policy, int freq_level)
{
	uint32_t core_id = cpu_data[policy->cpu].core;
	struct freq_level_setting_args args;

	args.level = freq_level;
	args.cpumask = 1 << core_id;
	do_service_request(CMD_SET_CPU_LEVEL, &args);

	return 0;
}

/*
 * Here we notify other drivers of the proposed change and the final change.
 */
static int loongson3_cpufreq_target(struct cpufreq_policy *policy,
				     unsigned int index)
{
	unsigned int cpu = policy->cpu;
	unsigned int package = cpu_data[cpu].package;

	if (!cpu_online(cpu))
		return -ENODEV;

	/* setting the cpu frequency */
	mutex_lock(&cpufreq_mutex[package]);
	loongson3_cpufreq_set(policy, index);
	mutex_unlock(&cpufreq_mutex[package]);

	return 0;
}

static int loongson3_cpufreq_cpu_init(struct cpufreq_policy *policy)
{
	if (!cpu_online(policy->cpu))
		return -ENODEV;

	policy->cur = loongson3_cpufreq_get(policy->cpu);

	policy->cpuinfo.transition_latency = 5000;
	policy->freq_table = loongson3_cpufreq_table;

	return 0;
}

static int loongson3_cpufreq_exit(struct cpufreq_policy *policy)
{
	return 0;
}

static struct cpufreq_driver loongson3_cpufreq_driver = {
	.name = "loongson3",
	.flags = CPUFREQ_CONST_LOOPS,
	.init = loongson3_cpufreq_cpu_init,
	.verify = cpufreq_generic_frequency_table_verify,
	.target_index = loongson3_cpufreq_target,
	.get = loongson3_cpufreq_get,
	.exit = loongson3_cpufreq_exit,
	.attr = cpufreq_generic_attr,
};

static struct platform_device_id cpufreq_id_table[] = {
	{ "loongson3_cpufreq", },
	{ /* sentinel */ }
};

MODULE_DEVICE_TABLE(platform, cpufreq_id_table);

static struct platform_driver cpufreq_driver = {
	.driver = {
		.name = "loongson3_cpufreq",
		.owner = THIS_MODULE,
	},
	.id_table = cpufreq_id_table,
};

static int configure_cpufreq_info(void)
{
	int i, r, max_level;
	struct feature_args args1;
	struct freq_level_args args2;
	struct freq_info_args args3;

	if (!cpu_has_csr)
		return -EPERM;

	args1.index = FEATURE_INDEX_GENERAL;
	r = do_service_request(CMD_GET_FEATURES, &args1);
	if (r < 0)
		return -EPERM;

	if (!(args1.flags & FEATURE_FREQ_SCALE))
		return -EPERM;

	if (args1.flags & FEATURE_BOOST)
		boost_supported = 1;

	r = do_service_request(CMD_SET_ENABLED_FEATURES, &args1);
	if (r < 0)
		return -EPERM;

	r = do_service_request(CMD_GET_FREQ_LEVELS, &args2);
	if (r < 0)
		return -EPERM;

	if (boost_supported)
		max_level = args2.max_boost_level;
	else
		max_level = args2.max_normal_level;

	for (i = args2.min_level; i <= max_level; i++) {
		args3.info = i;
		args3.index = FREQ_INFO_INDEX_LEVEL_FREQ;
		do_service_request(CMD_GET_FREQ_INFO, &args3);
		loongson3_cpufreq_table[i].frequency = args3.info * 1000;
		if (i > args2.max_normal_level)
			loongson3_cpufreq_table[i].flags = CPUFREQ_BOOST_FREQ;
	}

	return 0;
}

static int __init cpufreq_init(void)
{
	int i, ret;

	ret = platform_driver_register(&cpufreq_driver);
	if (ret)
		goto err;

	ret = configure_cpufreq_info();
	if (ret)
		goto err;

	for (i = 0; i < MAX_PACKAGES; i++)
		mutex_init(&cpufreq_mutex[i]);

	ret = cpufreq_register_driver(&loongson3_cpufreq_driver);

	if (boost_supported)
		cpufreq_enable_boost_support();

	pr_info("cpufreq: Loongson-3 CPU frequency driver.\n");

	return ret;

err:
	platform_driver_unregister(&cpufreq_driver);
	return ret;
}

static void __exit cpufreq_exit(void)
{
	cpufreq_unregister_driver(&loongson3_cpufreq_driver);
	platform_driver_unregister(&cpufreq_driver);
}

module_init(cpufreq_init);
module_exit(cpufreq_exit);

MODULE_AUTHOR("Huacai Chen <chenhuacaic@loongson.cn>");
MODULE_DESCRIPTION("CPUFreq driver for Loongson-3 processors");
MODULE_LICENSE("GPL");
