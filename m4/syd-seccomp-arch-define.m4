dnl m4/syd-seccomp-arch-check.c
dnl
dnl LibSeccomp Architecture Definer
dnl AutoTools AC_RUN_IFELSE Program.
dnl
dnl Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
dnl SPDX-License-Identifier: GPL-2.0-only

m4_define([include_seccomp_headers], [
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <seccomp.h>
])

dnl Check if any architecture is defined.
dnl This may not be the case e.g:
dnl If we're building with --enable-static,
dnl and libseccomp's static libraries are missing.
SYD_SECCOMP_OK=no

save_LDFLAGS="$LDFLAGS"
LDFLAGS="$SYDBOX_STATIC_CFLAGS"
save_LIBS="$LIBS"
LIBS="-lseccomp"

AC_MSG_CHECKING([for x86 architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_X86) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_X86_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_X86], [1], [Architecture x86 is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_X86_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for x86_64 architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_X86_64) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_X86_64_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_X86_64], [1], [Architecture x86_64 is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_X86_64_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for x32 architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_X32) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_X32_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_X32], [1], [Architecture x32 is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_X32_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for arm architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_ARM) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_ARM_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_ARM], [1], [Architecture arm is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_ARM_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for aarch64 architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_AARCH64) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_AARCH64_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_AARCH64], [1], [Architecture aarch64 is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_AARCH64_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for aarch64 architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_AARCH64) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_AARCH64_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_AARCH64], [1], [Architecture aarch64 is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_AARCH64_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for mips architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_MIPS) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_MIPS_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_MIPS], [1], [Architecture mips is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_MIPS_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for mips64 architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_MIPS64) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_MIPS64_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_MIPS64], [1], [Architecture mips64 is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_MIPS64_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for mips64n32 architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_MIPS64N32) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_MIPS64N32_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_MIPS64N32], [1], [Architecture mips64n32 is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_MIPS64N32_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for mipsel architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_MIPSEL) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_MIPSEL_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_MIPSEL], [1], [Architecture mipsel is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_MIPSEL_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for mipsel64 architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_MIPSEL64) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_MIPSEL64_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_MIPSEL64], [1], [Architecture mipsel64 is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_MIPSEL64_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for mipsel64n32 architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_MIPSEL64N32) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_MIPSEL64N32_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_MIPSEL64N32], [1], [Architecture mipsel64n32 is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_MIPSEL64N32_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for ppc architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_PPC) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_PPC_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_PPC], [1], [Architecture ppc is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_PPC_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for ppc64 architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_PPC64) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_PPC64_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_PPC64], [1], [Architecture ppc64 is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_PPC64_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for ppc64le architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_PPC64LE) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_PPC64LE_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_PPC64LE], [1], [Architecture ppc64le is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_PPC64LE_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for ppc64le architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_PPC64LE) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_PPC64LE_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_PPC64LE], [1], [Architecture ppc64le is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_PPC64LE_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for s390 architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_S390) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_S390_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_S390], [1], [Architecture s390 is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_S390_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for s390 architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_S390X) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_S390X_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_S390X], [1], [Architecture s390 is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_S390X_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for parisc architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_PARISC) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_PARISC_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_PARISC], [1], [Architecture parisc is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_PARISC_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for parisc64 architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_PARISC64) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_PARISC64_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_PARISC64], [1], [Architecture parisc64 is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_PARISC64_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

AC_MSG_CHECKING([for riscv64 architecture support])
AC_RUN_IFELSE([AC_LANG_PROGRAM([
include_seccomp_headers
SYD_SECCOMP_ARCH_CHECK],
[[exit(syd_seccomp_check_support(SCMP_ARCH_RISCV64) ? 0 : 1);]])],
[AC_MSG_RESULT([yes])
SYD_SECCOMP_OK=yes
SYD_SECCOMP_RISCV64_OK=yes
AC_DEFINE_UNQUOTED([SYD_ARCH_RISCV64], [1], [Architecture riscv64 is supported])
],[AC_MSG_RESULT([no])
SYD_SECCOMP_RISCV64_OK=no
],[SYD_ARCH_CROSS_COMPILE_WARN=yes])

LDFLAGS="$save_LDFLAGS"
LIBS="$save_LIBS"

if test x"$SYD_SECCOMP_OK" = x"no"; then
	AC_MSG_ERROR([No libseccomp supported architectures found!])
fi
