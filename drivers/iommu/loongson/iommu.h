// SPDX-License-Identifier: GPL-2.0-only
/*
 * Loongson IOMMU Driver
 *
 * Copyright (C) 2020-2021 Loongson Technology Ltd.
 * Author:	Lv Chen <lvchen@loongson.cn>
 *		Wang Yang <wangyang@loongson.cn>
 */

#ifndef LOONGSON_IOMMU_H
#define LOONGSON_IOMMU_H

#include <linux/device.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/list.h>
#include <linux/sizes.h>
#include <linux/spinlock.h>
#include <asm/addrspace.h>

#define IOVA_WIDTH		47

/* Bit value definition for I/O PTE fields */
#define IOMMU_PTE_PR		(1ULL << 0)	/* Present */
#define IOMMU_PTE_HP		(1ULL << 1)	/* HugePage */
#define IOMMU_PTE_IR		(1ULL << 2)	/* Readable */
#define IOMMU_PTE_IW		(1ULL << 3)	/* Writeable */

#define IOMMU_PTE_PRESENT(pte)	((pte) & IOMMU_PTE_PR)
#define IOMMU_PTE_HUGEPAGE(pte)	((pte) & IOMMU_PTE_HP)

#define LA_IOMMU_PGSIZE		(SZ_16K | SZ_32M)

/* IOMMU page table */
#define IOMMU_PAGE_SHIFT	14
#define IOMMU_PAGE_SIZE		(_AC(1, UL) << IOMMU_PAGE_SHIFT)
#define IOMMU_PAGE_MASK		(~(IOMMU_PAGE_SIZE - 1))
#define IOMMU_PTRS_PER_PTE	(IOMMU_PAGE_SIZE >> 3)
#define IOMMU_PMD_SHIFT		(IOMMU_PAGE_SHIFT + (IOMMU_PAGE_SHIFT - 3))
#define IOMMU_PMD_SIZE		(1UL << IOMMU_PMD_SHIFT)
#define IOMMU_PMD_MASK		(~(IOMMU_PMD_SIZE-1))
#define IOMMU_PTRS_PER_PMD	(IOMMU_PAGE_SIZE >> 3)
#define IOMMU_PGDIR_SHIFT	(IOMMU_PMD_SHIFT + (IOMMU_PAGE_SHIFT - 3))
#define IOMMU_PGDIR_SIZE	(1ULL << IOMMU_PGDIR_SHIFT)
#define IOMMU_PGDIR_MASK	(~(IOMMU_PGDIR_SIZE-1))
#define IOMMU_PTRS_PER_PGD	(IOMMU_PAGE_SIZE >> 3)
#define IOMMU_PTE_WIDTH		(IOMMU_PMD_SHIFT - IOMMU_PAGE_SHIFT)
#define IOMMU_PMD_WIDTH		(IOMMU_PGDIR_SHIFT - IOMMU_PMD_SHIFT)
#define IOMMU_PGDIR_WIDTH	(IOVA_WIDTH - IOMMU_PGDIR_SHIFT)

/* Virtio page use size of 16k */
#define LA_VIRTIO_PAGE_SHIFT	14
#define LA_VIRTIO_PAGE_SIZE	(_AC(1, UL) << LA_VIRTIO_PAGE_SHIFT)
#define LA_VIRTIO_PAGE_MASK	(~((1ULL << LA_VIRTIO_PAGE_SHIFT) - 1))

/* Bits of iommu map address space field */
#define LA_IOMMU_PFN_LO			0x0
#define PFN_LO_SHIFT			12
#define LA_IOMMU_PFN_HI			0x4
#define PFN_HI_MASK			0x3ffff
#define LA_IOMMU_VFN_LO			0x8
#define VFN_LO_SHIFT			12
#define LA_IOMMU_VFN_HI			0xC
#define VFN_HI_MASK			0x3ffff

/* wired | index | domain | shift */
#define LA_IOMMU_WIDS			0x10
/* valid | busy | tlbar/aw | cmd */
#define LA_IOMMU_VBTC			0x14
#define IOMMU_PGTABLE_BUSY		(1 << 16)
/* enable |index | valid | domain | bdf */
#define LA_IOMMU_EIVDB			0x18
/* enable | valid | cmd */
#define LA_IOMMU_CMD			0x1C
#define LA_IOMMU_PGD0_LO		0x20
#define LA_IOMMU_PGD0_HI		0x24
#define STEP_PGD			0x8
#define STEP_PGD_SHIFT			3
#define LA_IOMMU_PGD_LO(domain_id)	\
		(LA_IOMMU_PGD0_LO + ((domain_id) << STEP_PGD_SHIFT))
#define LA_IOMMU_PGD_HI(domain_id)	\
		(LA_IOMMU_PGD0_HI + ((domain_id) << STEP_PGD_SHIFT))

#define LA_IOMMU_DIR_CTRL0		0xA0
#define LA_IOMMU_DIR_CTRL1		0xA4
#define LA_IOMMU_DIR_CTRL(x)		(LA_IOMMU_DIR_CTRL0 + ((x) << 2))

#define LA_IOMMU_SAFE_BASE_HI		0xE0
#define LA_IOMMU_SAFE_BASE_LO		0xE4
#define LA_IOMMU_EX_ADDR_LO		0xE8
#define LA_IOMMU_EX_ADDR_HI		0xEC

#define LA_IOMMU_PFM_CNT_EN		0x100

#define LA_IOMMU_RD_HIT_CNT_0		0x110
#define LA_IOMMU_RD_MISS_CNT_O		0x114
#define LA_IOMMU_WR_HIT_CNT_0		0x118
#define LA_IOMMU_WR_MISS_CNT_0		0x11C
#define LA_IOMMU_RD_HIT_CNT_1		0x120
#define LA_IOMMU_RD_MISS_CNT_1		0x124
#define LA_IOMMU_WR_HIT_CNT_1		0x128
#define LA_IOMMU_WR_MISS_CNT_1		0x12C
#define LA_IOMMU_RD_HIT_CNT_2		0x130
#define LA_IOMMU_RD_MISS_CNT_2		0x134
#define LA_IOMMU_WR_HIT_CNT_2		0x138
#define LA_IOMMU_WR_MISS_CNT_2		0x13C

#define MAX_DOMAIN_ID			16
#define MAX_ATTACHED_DEV_ID		16
#define MAX_PAGES_NUM			(SZ_128M / IOMMU_PAGE_SIZE)

/* To find an entry in an iommu page table directory */
#define iommu_pgd_index(addr)		\
		(((addr) >> IOMMU_PGDIR_SHIFT) & (IOMMU_PTRS_PER_PGD - 1))
#define iommu_pmd_index(addr)		\
		(((addr) >> IOMMU_PMD_SHIFT) & (IOMMU_PTRS_PER_PMD - 1))
#define iommu_pte_index(addr)		\
		(((addr) >> IOMMU_PAGE_SHIFT) & (IOMMU_PTRS_PER_PTE - 1))
#define iommu_page_offset(addr)		\
		(addr & (IOMMU_PAGE_SIZE - 1))

#define iommu_pgd_offset(pgd, addr)	(pgd + iommu_pgd_index(addr))

/* IOMMU iommu_table entry */
typedef struct { unsigned long iommu_pte; } iommu_pte;

static inline void *iommu_gmem_phys_to_virt(unsigned long paddr)
{
	return (void *)(UNCACHE_BASE + paddr);
}

static inline unsigned long iommu_gmem_virt_to_phys(unsigned long va)
{
	return (unsigned long)(va - UNCACHE_BASE);
}

static inline void *iommu_phys_to_virt(unsigned long paddr)
{
	return phys_to_virt(paddr);
}

static inline u64 iommu_virt_to_phys(void *vaddr)
{
	return (u64)virt_to_phys(vaddr);
}

static inline unsigned long *iommu_pmd_offset(unsigned long *pgd_entry,
							unsigned long addr)
{
	unsigned long pmd_base;

	pmd_base = (*pgd_entry) & IOMMU_PAGE_MASK;
	pmd_base = (unsigned long)iommu_phys_to_virt(pmd_base);

	return (unsigned long *)(pmd_base) + iommu_pmd_index(addr);
}

static inline unsigned long *iommu_pte_offset(unsigned long *pmd_entry,
							unsigned long addr)
{
	unsigned long pte_base;

	pte_base = (*pmd_entry) & IOMMU_PAGE_MASK;
	pte_base = (unsigned long)iommu_phys_to_virt(pte_base);

	return (unsigned long *)(pte_base) + iommu_pte_index(addr);
}

/* One vm is equal to a domain,one domain has a priv */
typedef struct loongson_iommu_priv {
	/* For list of all domains */
	struct list_head	list;
	/* List of all devices in this domain */
	struct list_head	dev_list;
	struct iommu_domain	domain;
	struct device		*dev;
	/* priv dev list lock */
	spinlock_t		devlock;
	/* 0x10000000~0x8fffffff */
	unsigned long           *virtio_pgtable;
	short			id;
	iommu_pte		*pgd;
	/* devices assigned to this domain */
	unsigned int		dev_cnt;
	int			used_pages;
	bool			is_hugepage;
} loongson_iommu_priv;

/* A device for passthrough */
struct loongson_iommu_dev_data {
	struct list_head list;		/* for domain->dev_list */
	struct list_head glist;		/* for global dev_data_list */
	loongson_iommu_priv	*priv;
	unsigned short bdf;
	int count;
	int index;			/* index in device table */
};

/* shadow page table entry */
typedef struct shadow_pg_entry {
	struct list_head pglist;	/* for iommu_shadow_pglist */
	unsigned long *va;		/* virtual address base for shadow page */
	unsigned long pa;		/* physical address base for shadow page */
	int index;			/* index 128M gmem */
	int dirty;
	int present;
} shadow_pg_entry;

#endif	/* LOONGSON_IOMMU_H */
