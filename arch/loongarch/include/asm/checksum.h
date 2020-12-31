/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 */
#ifndef _ASM_CHECKSUM_H
#define _ASM_CHECKSUM_H

#ifdef CONFIG_GENERIC_CSUM
#include <asm-generic/checksum.h>
#else

#include <linux/in6.h>

#include <linux/uaccess.h>

/*
 * computes the checksum of a memory block at buff, length len,
 * and adds in "sum" (32-bit)
 *
 * returns a 32-bit number suitable for feeding into itself
 * or csum_tcpudp_magic
 *
 * this function must be called with even lengths, except
 * for the last fragment, which may be odd
 *
 * it's best to have buff aligned on a 32-bit boundary
 */
__wsum csum_partial(const void *buff, int len, __wsum sum);
__wsum csum_partial_copy(const void *src, void *dst, int len);

#define _HAVE_ARCH_COPY_AND_CSUM_FROM_USER
static inline
__wsum csum_and_copy_from_user(const void __user *src, void *dst, int len)
{
	might_fault();
	if (!access_ok(src, len))
		return 0;
	return csum_partial_copy(src, dst, len);
}

#define HAVE_CSUM_COPY_USER
static inline
__wsum csum_and_copy_to_user(const void *src, void __user *dst, int len)
{
	might_fault();
	if (!access_ok(dst, len))
		return 0;
	return csum_partial_copy(src, dst, len);
}

/*
 * the same as csum_partial, but copies from user space (but on LoongArch
 * we have just one address space, so this is identical to the above)
 */
#define _HAVE_ARCH_CSUM_AND_COPY
static inline __wsum csum_partial_copy_nocheck(const void *src, void *dst, int len)
{
	return csum_partial_copy(src, dst, len);
}

/*
 *	Fold a partial checksum without adding pseudo headers
 */
static inline __sum16 csum_fold(__wsum csum)
{
	u32 sum = (__force u32)csum;

	sum += (sum << 16);
	csum = (sum < csum);
	sum >>= 16;
	sum += csum;

	return (__force __sum16)~sum;
}
#define csum_fold csum_fold

/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 *
 *	By Jorge Cwik <jorge@laser.satlink.net>, adapted for linux by
 *	Arnt Gulbrandsen.
 */
static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	const unsigned int *word = iph;
	const unsigned int *stop = word + ihl;
	unsigned int csum;
	int carry;

	csum = word[0];
	csum += word[1];
	carry = (csum < word[1]);
	csum += carry;

	csum += word[2];
	carry = (csum < word[2]);
	csum += carry;

	csum += word[3];
	carry = (csum < word[3]);
	csum += carry;

	word += 4;
	do {
		csum += *word;
		carry = (csum < *word);
		csum += carry;
		word++;
	} while (word != stop);

	return csum_fold(csum);
}
#define ip_fast_csum ip_fast_csum

static inline __wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
					__u32 len, __u8 proto,
					__wsum sum)
{
	__asm__(
#ifdef CONFIG_64BIT
	"	add.d	%0, %0, %2	\n"
	"	add.d	%0, %0, %3	\n"
	"	add.d	%0, %0, %4	\n"
	"	slli.d	$t7, %0, 32	\n"
	"	add.d	%0, %0, $t7	\n"
	"	sltu	$t7, %0, $t7	\n"
	"	srai.d	%0, %0, 32	\n"
	"	add.w	%0, %0, $t7	\n"
#endif
	: "=r" (sum)
	: "0" ((__force unsigned long)daddr),
	  "r" ((__force unsigned long)saddr),
	  "r" ((proto + len) << 8),
	  "r" ((__force unsigned long)sum)
	: "t7");

	return sum;
}
#define csum_tcpudp_nofold csum_tcpudp_nofold

/*
 * this routine is used for miscellaneous IP-like checksums, mainly
 * in icmp.c
 */
static inline __sum16 ip_compute_csum(const void *buff, int len)
{
	return csum_fold(csum_partial(buff, len, 0));
}

#define _HAVE_ARCH_IPV6_CSUM
static __inline__ __sum16 csum_ipv6_magic(const struct in6_addr *saddr,
					  const struct in6_addr *daddr,
					  __u32 len, __u8 proto,
					  __wsum sum)
{
	__wsum tmp;

	__asm__(
	"	add.w	%0, %0, %5	# proto (long in network byte order)\n"
	"	sltu	$t7, %0, %5	\n"
	"	add.w	%0, %0, $t7	\n"

	"	add.w	%0, %0, %6	# csum\n"
	"	sltu	$t7, %0, %6	\n"
	"	ld.w	%1, %2, 0	# four words source address\n"
	"	add.w	%0, %0, $t7	\n"
	"	add.w	%0, %0, %1	\n"
	"	sltu	$t7, %0, %1	\n"

	"	ld.w	%1, %2, 4	\n"
	"	add.w	%0, %0, $t7	\n"
	"	add.w	%0, %0, %1	\n"
	"	sltu	$t7, %0, %1	\n"

	"	ld.w	%1, %2, 8	\n"
	"	add.w	%0, %0, $t7	\n"
	"	add.w	%0, %0, %1	\n"
	"	sltu	$t7, %0, %1	\n"

	"	ld.w	%1, %2, 12	\n"
	"	add.w	%0, %0, $t7	\n"
	"	add.w	%0, %0, %1	\n"
	"	sltu	$t7, %0, %1	\n"

	"	ld.w	%1, %3, 0	\n"
	"	add.w	%0, %0, $t7	\n"
	"	add.w	%0, %0, %1	\n"
	"	sltu	$t7, %0, %1	\n"

	"	ld.w	%1, %3, 4	\n"
	"	add.w	%0, %0, $t7	\n"
	"	add.w	%0, %0, %1	\n"
	"	sltu	$t7, %0, %1	\n"

	"	ld.w	%1, %3, 8	\n"
	"	add.w	%0, %0, $t7	\n"
	"	add.w	%0, %0, %1	\n"
	"	sltu	$t7, %0, %1	\n"

	"	ld.w	%1, %3, 12	\n"
	"	add.w	%0, %0, $t7	\n"
	"	add.w	%0, %0, %1	\n"
	"	sltu	$t7, %0, %1	\n"

	"	add.w	%0, %0, $t7	# Add final carry\n"
	: "=&r" (sum), "=&r" (tmp)
	: "r" (saddr), "r" (daddr),
	  "0" (htonl(len)), "r" (htonl(proto)), "r" (sum)
	:"t7");

	return csum_fold(sum);
}

#include <asm-generic/checksum.h>
#endif /* CONFIG_GENERIC_CSUM */

#endif /* _ASM_CHECKSUM_H */
