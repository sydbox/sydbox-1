dnl
dnl sydbox/configure.ac
dnl
dnl Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2018, 2021 Ali Polatel <alip@exherbo.org>
dnl SPDX-License-Identifier: GPL-2.0-only

dnl Program, version
AC_PREREQ(2.59)

dnl Versioning
dnl major: User interface changes (magic commands, configuration format)
dnl minor: Major changes without UI breakage
dnl micro: Every other change increases micro version
dnl suffix: For prerelease, alpha, beta versions
m4_define([sydbox_version_major],  [2])
m4_define([sydbox_version_minor],  [1])
m4_define([sydbox_version_micro],  [0])
m4_define([sydbox_version_suffix], [])
m4_define([sydbox_version_full],   [sydbox_version_major.sydbox_version_minor.sydbox_version_micro[]sydbox_version_suffix])
m4_define([sydbox_version],        [sydbox_version_full])
m4_define([libsyd_pc_version],     [sydbox_version_full])
m4_define([libsyd_pc_slot],        [sydbox_version_major.sydbox_version_minor[]sydbox_version_suffix])

m4_define([sydbox_api_version],    [sydbox_version_major])
m4_define([sydbox_fname_ext],      [syd-])

AC_INIT([sydbox], [sydbox_version], [alip@exherbo.org], [sydbox])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([src/sydbox.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AC_GNU_SOURCE
AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([dist-bzip2 no-dist-gzip std-options subdir-objects foreign])
AM_MAINTAINER_MODE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl Git revision
GITHEAD=
GITVERSION=
if test -d "${GIT_DIR:-${ac_top_srcdir:-./}/.git}" ; then
	GITHEAD=`git describe 2>/dev/null`
	if test -z "${GITHEAD}" ; then
		GITHEAD=`git rev-parse --short HEAD`
	fi
	if test -n "`git diff-index -m --name-only HEAD`" ; then
		GITHEAD="${GITHEAD}-dirty"
	fi
fi
AC_MSG_CHECKING([for git head])
AC_ARG_WITH([git-head],
	AS_HELP_STRING([--with-git-head], [Specify Git head]),
	GITHEAD=`eval echo $withval`,
	GITHEAD=`eval echo $GITHEAD`)
AC_MSG_RESULT([$GITHEAD])
AC_SUBST([GITHEAD])

if test -n "${GITHEAD}" ; then
	GITVERSION="-${GITHEAD}"
fi
AC_SUBST([GITVERSION])

SYDBOX_API_VERSION=sydbox_api_version
SYDBOX_FNAME_EXT="sydbox_fname_ext"
AC_DEFINE_UNQUOTED([SYDBOX_API_VERSION], [$SYDBOX_API_VERSION], [Sydbox magic API version])
AC_SUBST([SYDBOX_API_VERSION])
AC_DEFINE_UNQUOTED([SYDBOX_FNAME_EXT], ["$SYDBOX_FNAME_EXT"], [Sydbox filename extension])
AC_SUBST([SYDBOX_FNAME_EXT])

LIBSYD_PC_VERSION="libsyd_pc_version"
LIBSYD_PC_SLOT="libsyd_pc_slot"
AC_SUBST([LIBSYD_PC_VERSION])
AC_SUBST([LIBSYD_PC_SLOT])

dnl remove the check for c++ and fortran compiler
m4_defun([_LT_AC_LANG_CXX_CONFIG], [:])
m4_defun([_LT_AC_LANG_F77_CONFIG], [:])

dnl toolchain checks
: ${CFLAGS=""}
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_LD
AC_PROG_CC_C99
if test x"$ac_cv_prog_cc_c99" = x"no"; then
	AC_MSG_ERROR([sydbox requires a C compiler that supports ISO C99!])
fi
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_PROG_SED
LT_INIT
AC_PROG_YACC
AM_PROG_LEX

AM_CONDITIONAL([HAVE_GNU_CC], [test x"$GCC" = x"yes"])
AM_CONDITIONAL([HAVE_GNU_LD], [test x"$with_gnu_ld" = x"yes"])

dnl check for supported operating system
KERNEL_VERSION=
KERNEL_VERSION_WARN=0
AC_CANONICAL_HOST
AC_MSG_CHECKING([for supported operating system])
case "$host_os" in
linux*)
	opsys="linux"
	AC_MSG_RESULT([$host_os])
	AC_MSG_CHECKING([for supported kernel])
	kernel_version=`uname -r | cut -d'-' -f1`
	KERNEL_VERSION="$kernel_version"
	case "$kernel_version" in
	0.*|1.*|2.*|3.*|4.*|5.0.*|5.1.*|5.2.*|5.3.*|5.4.*|5.5.*)
		KERNEL_VERSION_WARN=1
		AC_MSG_RESULT([NO!])
		AC_MSG_WARN([Linux kernel version $kernel_version is not supported by sydbox])
		;;
	5.6.*)
		KERNEL_VERSION_WARN=1
		kernel_minor_version=`echo $kernel_version | cut -d'.' -f3`
		if test "$kernel_minor_version" -lt 0; then
			AC_MSG_RESULT([NO!])
			AC_MSG_WARN([Linux kernel version $kernel_version is not supported by sydbox])
		fi
		AC_MSG_RESULT([$kernel_version])
		;;
	*)
		AC_MSG_RESULT([$kernel_version])
		;;
	esac
	;;
*)
	AC_MSG_RESULT([NO!])
	AC_MSG_ERROR([Operating system $host_os is not supported by sydbox])
	;;
esac

dnl check for sizes
AC_CHECK_SIZEOF([int])
AC_CHECK_SIZEOF([long])
AC_CHECK_SIZEOF([long long])
AC_CHECK_SIZEOF([short])
AC_CHECK_SIZEOF([int16_t])
AC_CHECK_SIZEOF([uint16_t])
AC_CHECK_SIZEOF([int32_t])
AC_CHECK_SIZEOF([uint32_t])
AC_CHECK_SIZEOF([int64_t])
AC_CHECK_SIZEOF([off_t])
AC_CHECK_SIZEOF([off64_t])

dnl check for sydbox headers
AC_CHECK_HEADER([limits.h],      [], AC_MSG_ERROR([I need limits.h]))
AC_CHECK_HEADER([signal.h],      [], AC_MSG_ERROR([I need signal.h]))
AC_CHECK_HEADER([sys/utsname.h], [], AC_MSG_ERROR([I need sys/utsname.h]))
AC_CHECK_HEADER([sys/socket.h],  [], AC_MSG_ERROR([I need sys/socket.h]))
AC_CHECK_HEADER([ctype.h],       [], AC_MSG_ERROR([I need ctype.h]))
AC_CHECK_HEADER([arpa/inet.h],   [], AC_MSG_ERROR([I need arpa/inet.h]))
AC_CHECK_HEADER([netdb.h],       [], AC_MSG_ERROR([I need netdb.h]))
AC_CHECK_HEADER([sched.h],       [], AC_MSG_ERROR([I need sched.h]))
AC_CHECK_HEADER([asm/unistd.h],  [], AC_MSG_ERROR([I need asm/unistd.h]))

dnl check for everything (for tests)
AC_FUNC_ALLOCA
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(m4_flatten([
	dirent.h
	dlfcn.h
	elf.h
	errno.h
	execinfo.h
	fcntl.h
	grp.h
	inttypes.h
	libgen.h
	limits.h
	memory.h
	pthread.h
	pwd.h
	siginfo.h
	signal.h
	sigsegv.h
	stdarg.h
	stdbool.h
	stddef.h
	stdint.h
	stdio.h
	stdlib.h
	string.h
	strings.h
	syscall.h
	unistd.h
	utime.h
	sys/file.h
	sys/mman.h
	sys/param.h
	sys/reg.h
	sys/stat.h
	sys/syscall.h
	sys/time.h
	sys/types.h
	sys/uio.h
	sys/user.h
	sys/wait.h
	sys/syscall.h
	asm/signal.h
	linux/fs.h
	linux/mount.h
	linux/openat2.h
	linux/stat.h
	linux/uio.h
	linux/unistd.h
]))

dnl check for types
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_CHECK_DECLS_ONCE([environ])
AC_CHECK_TYPES([ptrdiff_t])
AC_CHECK_TYPES([sig_atomic_t], [], AC_MSG_ERROR([I need sigatomic_t]), [#include <signal.h>])
AC_CHECK_TYPES([sighandler_t, sig_t, __sighandler_t],,,[#include <signal.h>])
AC_MSG_CHECKING([struct open_how])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <linux/openat2.h>]],
		  [[struct open_how *buf;]])],
		  [AC_MSG_RESULT([yes])
		   AC_DEFINE_UNQUOTED([HAVE_STRUCT_OPEN_HOW],
				      [1], [Have struct open_how])],
		  [AC_MSG_RESULT([no])])
AC_MSG_CHECKING([struct statx])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <sys/stat.h>]],
		  [[struct statx *buf;]])],
		  [AC_MSG_RESULT([yes])
		   AC_DEFINE_UNQUOTED([HAVE_STRUCT_STATX],
				      [1], [Have struct statx])],
		  [AC_MSG_RESULT([no])])
AC_CHECK_TYPES([struct msghdr],
	       [],
	       [AC_MSG_ERROR([I need struct msghdr!])],
	       [#include <sys/socket.h>])
AC_CHECK_TYPES([struct sockaddr_storage],
	       [],
	       [AC_MSG_ERROR([I need struct sockaddr_storage!])],
	       [#include <sys/socket.h>])
AC_MSG_CHECKING([struct mmsghdr])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <sys/socket.h>]],
		  [[struct mmsghdr *hdr;]])],
		  [AC_MSG_RESULT([yes])
		   AC_DEFINE_UNQUOTED([HAVE_STRUCT_MMSGHDR],
				      [1], [Have struct mmsghdr])],
		  [AC_MSG_RESULT([no])])

HAVE_NEWFSTATAT=
AC_CHECK_DECL([__NR_newfstatat],
	      [HAVE_NEWFSTATAT=1],
	      [HAVE_NEWFSTATAT=0],
	      [#include <asm/unistd.h>])
if test x"$HAVE_NEWFSTATAT" = x"1"; then
	AC_DEFINE_UNQUOTED([HAVE_NEWFSTATAT], [1], [Have newfstatat() system call])
fi
AC_SUBST([HAVE_NEWFSTATAT])

dnl check for functions
AC_CHECK_FUNCS([asprintf],      [], [AC_MSG_ERROR([I need asprintf])])
AC_CHECK_FUNCS([isdigit],       [], [AC_MSG_ERROR([I need isdigit])])
AC_CHECK_FUNCS([ntohs],         [], [AC_MSG_ERROR([I need ntohs])])
AC_CHECK_FUNCS([getservbyname], [], [AC_MSG_ERROR([I need getservbyname])])
AC_CHECK_FUNCS([pipe2])
AC_CHECK_FUNCS([fchdir])

dnl check for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_CHECK_FUNCS_ONCE(m4_flatten([
	clone
	__clone2
	creat64
	faccessat
	fchmodat
	fchownat
	fopen64
	ftruncate
	futimesat
	lchown
	linkat
	lutimes
	mkdir
	mkdirat
	mkdtemp
	mkfifoat
	mknodat
	open64
	openat
	openat64
	remove
	renameat
	rmdir
	symlinkat
	truncate64
	unlinkat
	utime
	utimensat
	utimes
]))

dnl check for large file support
AC_SYS_LARGEFILE

dnl check for pthreads
AX_PTHREAD([],
	   [AC_MSG_WARN([POSIX threads library is missing, some tests may not build!])])

dnl check for pkg-config
PKG_PROG_PKG_CONFIG([0.20.0])

dnl check for libseccomp
LIBSECCOMP_REQUIRED=2.4.3
PKG_CHECK_MODULES([libseccomp], [libseccomp >= $LIBSECCOMP_REQUIRED],,
		  AC_MSG_ERROR([sydbox requires libseccomp-$LIBSECCOMP_REQUIRED or newer]))

dnl check for libseccomp architectures
m4_sinclude([m4/syd-seccomp-arch-check.m4])
m4_sinclude([m4/syd-seccomp-arch-define.m4])

dnl AC_MSG_WARN(["Libseccomp arch check unavailable during cross compiling"])
dnl AC_MSG_WARN(["
dnl check for debugging support (requires libunwind)
LIBUNWIND_REQUIRED=1.1

AC_MSG_CHECKING([for debug support])
AC_ARG_ENABLE([debug],
	      [AS_HELP_STRING([--enable-debug], [Enable debug support (requires: libunwind)])],
	      [WANT_DEBUG="$enableval"],
	      [WANT_DEBUG="no"])
AC_MSG_RESULT([$WANT_DEBUG])
if test x"$WANT_DEBUG" = x"yes"; then
	PKG_CHECK_MODULES([libunwind], [libunwind >= $LIBUNWIND_REQUIRED],,
			  AC_MSG_ERROR([sydbox requires libunwind-$LIBUNWIND_REQUIRED or newer for --enable-debug]))
	SYDBOX_DEBUG=1
else
	SYDBOX_DEBUG=0
fi
AM_CONDITIONAL([WANT_DEBUG], test x"$WANT_DEBUG" = x"yes")
AC_DEFINE_UNQUOTED([SYDBOX_DEBUG], [$SYDBOX_DEBUG], ['Enable debug support (requires: libunwind)'])
AC_SUBST([SYDBOX_DEBUG])

dnl check for process_vm_readv and process_vm_writev
STRUCT_IOVEC_WARN=0
PROCESS_VM_WARN=0
m4_define([include_process_vm_headers], [
	   #include <sys/types.h>
	   #include <asm/unistd.h>
	   #ifdef HAVE_SYS_UIO_H
	   #include <sys/uio.h>
	   #endif
           #include <unistd.h>
])
AC_MSG_CHECKING([struct iovec])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([include_process_vm_headers],
		  [[struct iovec *iovec;]])],
		  [AC_MSG_RESULT([yes])
		   STRUCT_IOVEC_WARN=1],
		  [AC_MSG_RESULT([no])
		   STRUCT_IOVEC_WARN=0])

AC_CHECK_DECL([__NR_process_vm_readv],
	      [PROCESS_VM_WARN=0],
	      [PROCESS_VM_WARN=1],
	      [include_process_vm_headers])
AC_CHECK_DECL([__NR_process_vm_writev],
	      [PROCESS_VM_WARN=0],
	      [PROCESS_VM_WARN=1],
	      [include_process_vm_headers])

if test x"$STRUCT_IOVEC_WARN" = x"0" -a x"$PROCESS_VM_WARN" = x"0"
then
	AC_MSG_WARN(["Neither struct iovec, nor process_vm_{read,write}v found, using /proc/pid/mem"])
	SYDBOX_DEF_PROC_MEM=1
else
	SYDBOX_DEF_PROC_MEM=0
fi
AC_DEFINE_UNQUOTED([SYDBOX_DEF_PROC_MEM], [$SYDBOX_DEF_PROC_MEM], [Default to reading /proc/pid/mem])

dnl check for pidfd_open and pidfd_getfd.
m4_define([include_pidfd_headers], [
	   #include <asm/unistd.h>
	   #ifdef HAVE_SYS_SYSCALL_H
	   #include <sys/syscall.h>
	   #endif
	   #ifdef HAVE_LINUX_UNISTD_H
	   #include <linux/unistd.h>
	   #endif
])
PIDFD_OPEN_WARN=0
PIDFD_GETFD_WARN=0
PIDFD_SEND_SIGNAL_WARN=0
AC_CHECK_DECL([__NR_pidfd_open],  [],
	      [PIDFD_OPEN_WARN=1],
	      [include_pidfd_headers])
AC_CHECK_DECL([__NR_pidfd_getfd], [],
	      [PIDFD_OPEN_WARN=1],
	      [include_pidfd_headers])
AC_CHECK_DECL([__NR_pidfd_send_signal], [],
	      [PIDFD_OPEN_WARN=1],
	      [include_pidfd_headers])

AC_MSG_CHECKING([for dump])
AC_ARG_ENABLE([dump],
	AS_HELP_STRING([--disable-dump],
		       [Avoid linking event dumper into sydbox binary, required for sydbox -d option]),
	[WANT_DUMP_BUILTIN="$withval"],
	[WANT_DUMP_BUILTIN=yes])
if test x"$WANT_DUMP_BUILTIN" = x"yes"; then
	SYDBOX_WANT_DUMP_BUILTIN=1
else
	SYDBOX_WANT_DUMP_BUILTIN=0
fi
AC_MSG_RESULT([$WANT_DUMP_BUILTIN])
AM_CONDITIONAL([SYDBOX_HAVE_DUMP_BUILTIN], test x"$WANT_DUMP_BUILTIN" = x"yes")
AC_DEFINE_UNQUOTED([SYDBOX_HAVE_DUMP_BUILTIN], [$SYDBOX_WANT_DUMP_BUILTIN], [Enable builtin event dumper])
AC_SUBST([SYDBOX_WANT_DUMP_BUILTIN])

dnl extra CFLAGS
SYDBOX_WANTED_CFLAGS="-pedantic -W -Wall -Wextra -Wshadow -Wno-unused-parameter -Wno-missing-field-initializers"
for flag in $SYDBOX_WANTED_CFLAGS ; do
	AX_CHECK_COMPILER_FLAGS([$flag], [SYDBOX_CFLAGS="$SYDBOX_CFLAGS $flag"],)
done
AC_SUBST([SYDBOX_CFLAGS])

dnl extra LDFLAGS
dnl Build sydbox binary static by default.
dnl Disable with --disable-static
SYDBOX_LDFLAGS=
if test x"$enable_static" = x"yes"; then
	SYDBOX_LDFLAGS="-all-static"
fi
AC_SUBST([SYDBOX_LDFLAGS])
AM_CONDITIONAL([ENABLE_STATIC], test x"$enable_static" = x"yes")

dnl check for xsltproc
AC_PATH_PROG([XSLTPROC], [xsltproc])
AM_CONDITIONAL([HAVE_XSLTPROC], test x"$XSLTPROC" != x"")

dnl installed tests
AC_MSG_CHECKING([whether tests should be installed])
AC_ARG_ENABLE([installed-tests],
	      AS_HELP_STRING([--enable-installed-tests], [Install tests]),
	      [ENABLE_INSTALLED_TESTS=$enableval],
	      [ENABLE_INSTALLED_TESTS=no])
AC_MSG_RESULT([$ENABLE_INSTALLED_TESTS])
if test x"$ENABLE_INSTALLED_TESTS" = x"yes"; then
	if test x"$HAVE_CHECK" = x"no"; then
		AC_MSG_ERROR([Installed tests require check-$CHECK_REQ or newer])
	fi
fi
AM_CONDITIONAL([ENABLE_INSTALLED_TESTS], test "x$ENABLE_INSTALLED_TESTS" = x"yes")

dnl ####
dnl coverity checks
dnl ####
AC_CHECK_PROG(have_coverity, cov-build, "yes", "no")
AM_CONDITIONAL(COVERITY, test "$have_coverity" = yes)

dnl ####
dnl code coverage checks
dnl -> https://www.gnu.org/software/autoconf-archive/ax_code_coverage.html
dnl ####
AX_CODE_COVERAGE

dnl built sources
GENERATED_FILE=misc/generated-file.txt
AC_SUBST_FILE([GENERATED_FILE])

dnl output
AC_REQUIRE_AUX_FILE([tap-driver.sh])
AC_CONFIG_FILES([Makefile
		 src/Makefile
		 syd/Makefile
		 data/Makefile
		 man/Makefile
		 t/Makefile
		 t/bin-wrappers/Makefile
		 t/test-bin/Makefile
		 t/test-data/Makefile
		 t/valgrind/Makefile])
AC_OUTPUT

echo "Build options:"
echo "- debug:$WANT_DEBUG"
echo "- dump:$WANT_DUMP_BUILTIN"
echo "- static:$enable_static"
echo "Secure Computing Architecture Support:"
echo "- x86: ${SYD_SECCOMP_X86_OK:-?}"
echo "- x86_64: ${SYD_SECCOMP_X86_64_OK:-?}"
echo "- x32: ${SYD_SECCOMP_X32_OK:-?}"
echo "- arm: ${SYD_SECCOMP_ARM_OK:-?}"
echo "- aarch64: ${SYD_SECCOMP_AARCH64_OK:-?}"
echo "- mips: ${SYD_SECCOMP_MIPS_OK:-?}"
echo "- mips64: ${SYD_SECCOMP_MIPS64_OK:-?}"
echo "- mips64n32: ${SYD_SECCOMP_MIPS64N32_OK:-?}"
echo "- mipsel: ${SYD_SECCOMP_MIPSEL_OK:-?}"
echo "- mipsel64: ${SYD_SECCOMP_MIPSEL64_OK:-?}"
echo "- mipsel64n32: ${SYD_SECCOMP_MIPSEL64N32_OK:-?}"
echo "- ppc: ${SYD_SECCOMP_PPC_OK:-?}"
echo "- ppc64: ${SYD_SECCOMP_PPC64_OK:-?}"
echo "- ppc64le: ${SYD_SECCOMP_PPC64LE_OK:-?}"
echo "- s390: ${SYD_SECCOMP_S390_OK:-?}"
echo "- s390x: ${SYD_SECCOMP_S390X_OK:-?}"
echo "- parisc: ${SYD_SECCOMP_PARISC_OK:-?}"
echo "- parisc64: ${SYD_SECCOMP_PARISC64_OK:-?}"
echo "- riscv64: ${SYD_SECCOMP_RISCV64_OK:-?}"

if test x"$SYD_ARCH_CROSS_COMPILE_WARN" = x"yes"; then
	AC_MSG_WARN([SydBox does not support cross-compiling for added architectures yet.])
	AC_MSG_WARN([This build will only have support for the native architecture of the system.])
	AC_MSG_WARN([This means you may not use SydBox to sandbox programs])
	AC_MSG_WARN([running under a non-native architecture.])
	AC_MSG_WARN([These programs will be killed by SydBox' seccomp filter immediately.])
	AC_MSG_WARN([To support cross-compiling, someone should])
	AC_MSG_WARN([move the SYD_ARCH_* defines out of the file])
	AC_MSG_WARN([m4/syd-secomp-arch-define.m4 and add a configuration option])
	AC_MSG_WARN([to specify the architectures that libseccomp supports, such as])
	AC_MSG_WARN([--enable-seccomp-host=x86,x86_64,x32,arm,aarch64,...])
fi

PIDFD_WARN=0
if test x"$SYDBOX_DEF_PROC_MEM" = x"1"; then
	AC_MSG_WARN([SydBox won't use cross memory attach and will read from /proc/pid/mem.])
fi
if test x"$PIDFD_OPEN_WARN" = x"1"; then
	AC_MSG_WARN([__NR_pidfd_open not declared! Setting pidfd_open to 434.])
	PIDFD_WARN=1
fi
if test x"$PIDFD_GETFD_WARN" = x"1"; then
	AC_MSG_WARN([__NR_pidfd_getfd not declared! Setting pidfd_getfd to 438.])
	PIDFD_WARN=1
fi
if test x"$PIDFD_SEND_SIGNAL" = x"1"; then
	AC_MSG_WARN([__NR_pidfd_send_signal not declared! Setting pidfd_getfd to 424.])
	PIDFD_WARN=1
fi
if test x"$PROCESS_VM_WARN" = x"1"; then
	AC_MSG_WARN([__NR_process_vm_readv not declared! Setting process_vm_readv to 310.])
	AC_MSG_WARN([__NR_process_vm_writev not declared! Setting process_vm_writev to 311.])
fi
if test x"$KERNEL_VERSION_WARN" = x"1" -o x"$PIDFD_WARN" = x"1" -o x"$PROCESS_VM_WARN" = x"1"
then
	AC_MSG_WARN([SydBox may not work correctly with your kernel version v$KERNEL_VERSION!])
	AC_MSG_WARN([Try updating your kernel headers or using a newer Linux kernel version.])
fi

if test -x ./tao/tao.pl; then
	dnl We don't distribute this file and the fortune cookie in the tarball.
	./tao/tao.pl
else
	dnl Krad ASCII ART#!#@$!@#$
	dnl Randomly store the name of one of the ASCII Art files in FILENAME
	dnl Source: from nmap/configure.ac
	FILENAME=`ls $srcdir/tao/art/art*.txt 2>/dev/null | $AWK '
    BEGIN {
        srand();
    }

    {
        lines[[++d]] = $0
    }

    END {
        # This makes AWKs random numbers more random
        print lines[[int(rand()*49139)%d+1]];
    }
    '`
dnl Print the file to screen, if any such file exists (i.e. $FILENAME is not empty)
	if test "$FILENAME"; then
		cat "$FILENAME"
	fi
fi

cat ./tao/make.txt
