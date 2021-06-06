/*
 * sydbox/arch.c
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "arch.h"

int32_t arch_from_string(const char *arch) {
	if (!strcmp(arch, "native")) { return SCMP_ARCH_NATIVE; }
	else if (!strcmp(arch, "x86_64")) { return SCMP_ARCH_X86_64; }
	else if (!strcmp(arch, "x86")) { return SCMP_ARCH_X86; }
	else if (!strcmp(arch, "x32")) { return SCMP_ARCH_X32; }
	else if (!strcmp(arch, "arm")) { return SCMP_ARCH_ARM; }
	else if (!strcmp(arch, "aarch64")) { return SCMP_ARCH_AARCH64; }
	else if (!strcmp(arch, "mips")) { return SCMP_ARCH_MIPS; }
	else if (!strcmp(arch, "mips64")) { return SCMP_ARCH_MIPS64; }
	else if (!strcmp(arch, "mips64n32")) { return SCMP_ARCH_MIPS64N32; }
	else if (!strcmp(arch, "mipsel")) { return SCMP_ARCH_MIPSEL; }
	else if (!strcmp(arch, "mipsel64")) { return SCMP_ARCH_MIPSEL64; }
	else if (!strcmp(arch, "mipsel64n32")) { return SCMP_ARCH_MIPSEL64N32; }
	else if (!strcmp(arch, "ppc")) { return SCMP_ARCH_PPC; }
	else if (!strcmp(arch, "ppc64")) { return SCMP_ARCH_PPC64; }
	else if (!strcmp(arch, "ppc64le")) { return SCMP_ARCH_PPC64LE; }
	else if (!strcmp(arch, "s390")) { return SCMP_ARCH_S390; }
	else if (!strcmp(arch, "s390x")) { return SCMP_ARCH_S390X; }
	else if (!strcmp(arch, "parisc")) { return SCMP_ARCH_PARISC; }
	else if (!strcmp(arch, "parisc64")) { return SCMP_ARCH_PARISC64; }
	else if (!strcmp(arch, "riscv64")) { return SCMP_ARCH_RISCV64; }
	else return -1;
}


