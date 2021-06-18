/*
 * sydbox/syd_seccomp_arch_default.c
 *
 * Copyright (c) 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef SYD_ARCH_X86
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_X86)) < 0) {
			errno = -r;
			say_errno("arch add error: X86, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("x86");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_X86_64
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_X86_64)) < 0) {
			errno = -r;
			say_errno("arch add error: X86_64, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("x86_64");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_X32
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_X32)) < 0) {
			errno = -r;
			say_errno("arch add error: X32, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("x32");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_ARM
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_ARM)) < 0) {
			errno = -r;
			say_errno("arch add error: ARM, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("arm");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_AARCH64
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_AARCH64)) < 0) {
			errno = -r;
			say_errno("arch add error: AARCH64, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("aarch64");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_MIPS
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_MIPS)) < 0) {
			errno = -r;
			say_errno("arch add error: MIPS, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("mips");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_MIPS64
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_MIPS64)) < 0) {
			errno = -r;
			say_errno("arch add error: MIPS64, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("mips64");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_MIPS64N32
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_MIPS64N32)) < 0) {
			errno = -r;
			say_errno("arch add error: MIPS64N32, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("mips64n32");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_MIPSEL
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_MIPSEL)) < 0) {
			errno = -r;
			say_errno("arch add error: MIPSEL, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("mipsel");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_MIPSEL64
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_MIPSEL64)) < 0) {
			errno = -r;
			say_errno("arch add error: MIPSEL64, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("mipsel64");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_MIPSEL64N32
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_MIPSEL64N32)) < 0) {
			errno = -r;
			say_errno("arch add error: MIPSEL64N32, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("mipsel64n32");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_PPC
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_PPC)) < 0) {
			errno = -r;
			say_errno("arch add error: PPC, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("ppc");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_PPC64
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_PPC64)) < 0) {
			errno = -r;
			say_errno("arch add error: PPC64, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("ppc64");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_PPC64LE
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_PPC64LE)) < 0) {
			errno = -r;
			say_errno("arch add error: PPC64LE, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("ppc64le");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_S390
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_S390)) < 0) {
			errno = -r;
			say_errno("arch add error: S390, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("s390");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_S390X
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_S390X)) < 0) {
			errno = -r;
			say_errno("arch add error: S390X, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("s390x");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_PARISC
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_PARISC)) < 0) {
			errno = -r;
			say_errno("arch add error: PARISC, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("parisc");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_PARISC64
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_PARISC64)) < 0) {
			errno = -r;
			say_errno("arch add error: PARISC64, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("parisc64");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#ifdef SYD_ARCH_RISCV64
		if ((r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_RISCV64)) < 0) {
			errno = -r;
			say_errno("arch add error: RISCV64, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("riscv64");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif
