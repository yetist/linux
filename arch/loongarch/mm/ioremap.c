// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/io.h>
#include <linux/mm.h>
#include <asm/pgtable.h>

void __init __iomem *early_ioremap(u64 phys_addr, unsigned long size)
{
	return ((void __iomem *)TO_CACHE(phys_addr));
}

void __init early_iounmap(void __iomem *addr, unsigned long size)
{

}

void *early_memremap_ro(resource_size_t phys_addr, unsigned long size)
{
	return early_memremap(phys_addr, size);
}

void *early_memremap_prot(resource_size_t phys_addr, unsigned long size,
		    unsigned long prot_val)
{
	return early_memremap(phys_addr, size);
}

#ifdef CONFIG_IOREMAP_WITH_TLB
static void __iomem *__ioremap_caller(phys_addr_t phys_addr, size_t size,
				      pgprot_t prot, void *caller)
{
	unsigned long last_addr;
	unsigned long offset = phys_addr & ~PAGE_MASK;
	int err;
	unsigned long addr;
	struct vm_struct *area;

	/*
	 * Page align the mapping address and size, taking account of any
	 * offset.
	 */
	phys_addr &= PAGE_MASK;
	size = PAGE_ALIGN(size + offset);

	/*
	 * Don't allow wraparound, zero size or outside PHYS_MASK.
	 */
	last_addr = phys_addr + size - 1;
	if (!size || last_addr < phys_addr)
		return NULL;

	area = get_vm_area_caller(size, VM_IOREMAP, caller);
	if (!area)
		return NULL;
	addr = (unsigned long)area->addr;
	area->phys_addr = phys_addr;

	err = ioremap_page_range(addr, addr + size, phys_addr, prot);
	if (err) {
		vunmap((void *)addr);
		return NULL;
	}

	return (void __iomem *)(offset + addr);
}
#else
static void __iomem *__ioremap_caller(phys_addr_t phys_addr, size_t size,
				      pgprot_t prot, void *caller)
{
	if (pgprot_val(prot) & _CACHE_CC)
		return (void __iomem *)(unsigned long)(CACHE_BASE + phys_addr);
	else
		return (void __iomem *)(unsigned long)(UNCACHE_BASE + phys_addr);
}
#endif

void __iomem *ioremap(phys_addr_t phys_addr, size_t size)
{
	return __ioremap_caller(phys_addr, size, PAGE_KERNEL_SUC, __builtin_return_address(0));
}
EXPORT_SYMBOL(ioremap);

void __iomem *ioremap_wc(phys_addr_t phys_addr, size_t size)
{
	return __ioremap_caller(phys_addr, size, PAGE_KERNEL_WUC, __builtin_return_address(0));
}
EXPORT_SYMBOL(ioremap_wc);

void __iomem *ioremap_cache(phys_addr_t phys_addr, size_t size)
{
	return __ioremap_caller(phys_addr, size, PAGE_KERNEL, __builtin_return_address(0));
}
EXPORT_SYMBOL(ioremap_cache);

void __iomem *ioremap_prot(phys_addr_t phys_addr, size_t size, unsigned long prot)
{
	return __ioremap_caller(phys_addr, size, __pgprot(prot), __builtin_return_address(0));
}
EXPORT_SYMBOL(ioremap_prot);

void iounmap(const volatile void __iomem *io_addr)
{
#ifdef CONFIG_IOREMAP_WITH_TLB
	unsigned long addr = (unsigned long)io_addr & PAGE_MASK;

	/*
	 * We could get an address outside vmalloc range in case
	 * of ioremap_cache() reusing a RAM mapping.
	 */
	if (is_vmalloc_addr((void *)addr))
		vunmap((void *)addr);
#endif
}

EXPORT_SYMBOL(iounmap);
