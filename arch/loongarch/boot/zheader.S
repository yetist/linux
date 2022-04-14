/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/pe.h>
#include <linux/sizes.h>

	.macro	__EFI_PE_HEADER
	.long	PE_MAGIC
coff_header:
#ifdef CONFIG_32BIT
	.short	IMAGE_FILE_MACHINE_LOONGARCH32		/* Machine */
#else
	.short	IMAGE_FILE_MACHINE_LOONGARCH64		/* Machine */
#endif
	.short	section_count				/* NumberOfSections */
	.long	0 					/* TimeDateStamp */
	.long	0					/* PointerToSymbolTable */
	.long	0					/* NumberOfSymbols */
	.short	section_table - optional_header		/* SizeOfOptionalHeader */
	.short	IMAGE_FILE_DEBUG_STRIPPED | \
		IMAGE_FILE_EXECUTABLE_IMAGE | \
		IMAGE_FILE_LINE_NUMS_STRIPPED		/* Characteristics */

optional_header:
	.short	PE_OPT_MAGIC_PE32PLUS			/* PE32+ format */
	.byte	0x02					/* MajorLinkerVersion */
	.byte	0x14					/* MinorLinkerVersion */
	.long	_data - efi_header_end			/* SizeOfCode */
	.long	_end - _data				/* SizeOfInitializedData */
	.long	0					/* SizeOfUninitializedData */
	.long	__efistub_efi_pe_entry - _head		/* AddressOfEntryPoint */
	.long	efi_header_end - _head			/* BaseOfCode */

extra_header_fields:
	.quad	0					/* ImageBase */
	.long	PECOFF_SEGMENT_ALIGN			/* SectionAlignment */
	.long	PECOFF_FILE_ALIGN			/* FileAlignment */
	.short	0					/* MajorOperatingSystemVersion */
	.short	0					/* MinorOperatingSystemVersion */
	.short	0					/* MajorImageVersion */
	.short	0					/* MinorImageVersion */
	.short	0					/* MajorSubsystemVersion */
	.short	0					/* MinorSubsystemVersion */
	.long	0					/* Win32VersionValue */

	.long	_end - _head				/* SizeOfImage */

	/* Everything before the kernel image is considered part of the header */
	.long	efi_header_end - _head			/* SizeOfHeaders */
	.long	0					/* CheckSum */
	.short	IMAGE_SUBSYSTEM_EFI_APPLICATION		/* Subsystem */
	.short	0					/* DllCharacteristics */
	.quad	0					/* SizeOfStackReserve */
	.quad	0					/* SizeOfStackCommit */
	.quad	0					/* SizeOfHeapReserve */
	.quad	0					/* SizeOfHeapCommit */
	.long	0					/* LoaderFlags */
	.long	(section_table - .) / 8			/* NumberOfRvaAndSizes */

	.quad	0					/* ExportTable */
	.quad	0					/* ImportTable */
	.quad	0					/* ResourceTable */
	.quad	0					/* ExceptionTable */
	.quad	0					/* CertificationTable */
	.quad	0					/* BaseRelocationTable */

	/* Section table */
section_table:
	.ascii	".text\0\0\0"
	.long	_data - efi_header_end			/* VirtualSize */
	.long	efi_header_end - _head			/* VirtualAddress */
	.long	_data - efi_header_end			/* SizeOfRawData */
	.long	efi_header_end - _head			/* PointerToRawData */

	.long	0					/* PointerToRelocations */
	.long	0					/* PointerToLineNumbers */
	.short	0					/* NumberOfRelocations */
	.short	0					/* NumberOfLineNumbers */
	.long	IMAGE_SCN_CNT_CODE | \
		IMAGE_SCN_MEM_READ | \
		IMAGE_SCN_MEM_EXECUTE			/* Characteristics */

	.ascii	".data\0\0\0"
	.long	_end - _data				/* VirtualSize */
	.long	_data - _head				/* VirtualAddress */
	.long	_edata - _data				/* SizeOfRawData */
	.long	_data - _head				/* PointerToRawData */

	.long	0					/* PointerToRelocations */
	.long	0					/* PointerToLineNumbers */
	.short	0					/* NumberOfRelocations */
	.short	0					/* NumberOfLineNumbers */
	.long	IMAGE_SCN_CNT_INITIALIZED_DATA | \
		IMAGE_SCN_MEM_READ | \
		IMAGE_SCN_MEM_WRITE			/* Characteristics */

	.org 0x20e
	.word kernel_version - 512 -  _head

	.set	section_count, (. - section_table) / 40
efi_header_end:
	.endm
