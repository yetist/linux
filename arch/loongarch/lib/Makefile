# SPDX-License-Identifier: GPL-2.0
#
# Makefile for LoongArch-specific library files.
#

lib-y	+= delay.o memset.o memcpy.o memmove.o unaligned.o \
	   clear_user.o copy_user.o dump_tlb.o csum_partial.o

lib-$(CONFIG_GENERIC_CSUM)	:= $(filter-out csum_partial.o, $(lib-y))
obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
