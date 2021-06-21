/*
 * sydbox/syd_seccomp_arch_default.c
 *
 * Copyright (c) 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define arch_ok(ret) ((ret) == 0 || (ret) == -EEXIST)

#define SAY_ERRNO(msg) if (!in_sydbox_test) { say_errno((msg)); }

#if defined(X86_64) && defined(SYD_ARCH_X86_64)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_X86_64);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: X86_64, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("x86_64");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_X86_64);
#endif

#if (defined(X86_64) || defined(X86)) && defined(SYD_ARCH_X86)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_X86);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: X86, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("x86");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_X86);
#endif

#if (defined(X86_64) || defined(X86)) && defined(SYD_ARCH_X32)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_X32);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: X32, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("x32");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_X32);
#endif

#if defined(AARCH64) && defined(SYD_ARCH_AARCH64)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_AARCH64);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: AARCH64, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("aarch64");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_AARCH64);
#endif

#if (defined(AARCH64) || defined(ARM)) && defined(SYD_ARCH_ARM)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_ARM);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: ARM, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("arm");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_ARM);
#endif

#if defined(MIPS) && defined(SYD_ARCH_MIPS64)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_MIPS64);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: MIPS64, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("mips64");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_MIPS64);
#endif

#if defined(MIPS) && defined(SYD_ARCH_MIPS64N32)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_MIPS64N32);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: MIPS64N32, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("mips64n32");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_MIPS64N32);
#endif

#if defined(MIPS) && defined(SYD_ARCH_MIPS)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_MIPS);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: MIPS, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("mips");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_MIPS);
#endif

#if defined(MIPS) && defined(SYD_ARCH_MIPSEL64)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_MIPSEL64);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: MIPSEL64, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("mipsel64");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_MIPSEL64);
#endif

#if defined(MIPS) && defined(SYD_ARCH_MIPSEL64N32)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_MIPSEL64N32);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: MIPSEL64N32, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("mipsel64n32");
			arch_argv[arch_argv_idx] = NULL;
		}
#endif

#if defined(MIPS) && defined(SYD_ARCH_MIPSEL)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_MIPSEL);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: MIPSEL, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("mipsel");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_MIPSEL);
#endif

#if defined(POWERPC64) && defined(SYD_ARCH_PPC64)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_PPC64);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: PPC64, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("ppc64");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_PPC64);
#endif

#if defined(POWERPC64LE) && defined(SYD_ARCH_PPC64LE)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_PPC64LE);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: PPC64LE, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("ppc64le");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_PPC64LE);
#endif

#if defined(POWERPC) && defined(SYD_ARCH_PPC)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_PPC);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: PPC, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("ppc");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_PPC);
#endif

#if defined(S390) && defined(SYD_ARCH_S390)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_S390);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: S390, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("s390");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_S390);
#endif

#if defined(S390X) && defined(SYD_ARCH_S390X)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_S390X);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: S390X, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("s390x");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_S390X);
#endif

#if defined(PARISC64) && defined(SYD_ARCH_PARISC64)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_PARISC64);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: PARISC64, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("parisc64");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_PARISC64);
#endif

#if (defined(PARISC64) || defined(PARISC)) && defined(SYD_ARCH_PARISC)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_PARISC);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: PARISC, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("parisc");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_PARISC);
#endif

#if defined(RISCV64) && defined(SYD_ARCH_RISCV64)
		r = seccomp_arch_add(sydbox->ctx, SCMP_ARCH_RISCV64);
		if (!arch_ok(r)) {
			errno = -r;
			SAY_ERRNO("arch add error: RISCV64, continuing...");
		} else {
			arch_argv[arch_argv_idx++] = xstrdup("riscv64");
			arch_argv[arch_argv_idx] = NULL;
		}
#else
		seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_RISCV64);
#endif

#undef arch_ok
#undef SAY_ERRNO
