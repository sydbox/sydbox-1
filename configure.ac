dnl Program, version
AC_PREREQ(2.59)

dnl Versioning
dnl major: User interface changes (magic commands, configuration format)
dnl minor: Major changes without UI breakage
dnl micro: Every other change increases micro version
dnl suffix: For prerelease, alpha, beta versions
m4_define([sydbox_version_major],  [1])
m4_define([sydbox_version_minor],  [2])
m4_define([sydbox_version_micro],  [1])
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
AC_PROG_CC_C99
if test x"$ac_cv_prog_cc_c99" = x"no"; then
	AC_MSG_ERROR([sydbox requires a C compiler that supports ISO C99!])
fi
AC_PROG_LD
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_PROG_SED
LT_INIT

AM_CONDITIONAL([HAVE_GNU_CC], [test x"$GCC" = x"yes"])
AM_CONDITIONAL([HAVE_GNU_LD], [test x"$with_gnu_ld" = x"yes"])

dnl check for supported operating system
AC_CANONICAL_HOST
AC_MSG_CHECKING([for supported operating system])
case "$host_os" in
linux*)
	opsys="linux"
	AC_MSG_RESULT([$host_os])
	AC_MSG_CHECKING([for supported kernel])
	kernel_version=`uname -r | cut -d'-' -f1`
	case "$kernel_version" in
	0.*|1.*|2.0.*|2.1.*|2.2.*|2.3.*|2.4.*)
		AC_MSG_RESULT([NO!])
		AC_MSG_ERROR([Linux kernel version $kernel_version is not supported by sydbox])
		;;
	2.5.*)
		kernel_minor_version=`echo $kernel_version | cut -d'.' -f3`
		if test "$kernel_minor_version" -lt 46; then
			AC_MSG_RESULT([NO!])
			AC_MSG_ERROR([Linux kernel version $kernel_version is not supported by sydbox])
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

dnl check for everything (for tests)
AC_FUNC_ALLOCA
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS_ONCE(m4_flatten([
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
	sys/ptrace.h
	sys/reg.h
	sys/stat.h
	sys/syscall.h
	sys/time.h
	sys/types.h
	sys/uio.h
	sys/user.h
	sys/wait.h
	asm/ptrace.h
	linux/ptrace.h
	linux/openat2.h
]))

dnl check for types
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_CHECK_DECLS_ONCE([environ])
AC_CHECK_TYPES([ptrdiff_t])
AC_CHECK_TYPES([struct pt_all_user_regs, struct ia64_fpreg, struct ptrace_peeksiginfo_args],,,[#include <sys/ptrace.h>])
AC_CHECK_TYPES([sig_atomic_t], [], AC_MSG_ERROR([I need sigatomic_t]), [#include <signal.h>])
AC_CHECK_TYPES([sighandler_t, sig_t, __sighandler_t],,,[#include <signal.h>])
AC_CHECK_TYPES([struct open_how],,,[#include <linux/openat2.h>])

HAVE_NEWFSTATAT=
AC_CHECK_DECL([SYS_newfstatat],
	      [HAVE_NEWFSTATAT=1],
	      [HAVE_NEWFSTATAT=0],
	      [#include <sys/syscall.h>])
AC_DEFINE_UNQUOTED([HAVE_NEWFSTATAT], [$HAVE_NEWFSTATAT], ['Have newfstatat() system call'])
AC_SUBST([HAVE_NEWFSTATAT])

save_CPPFLAGS=$CPPFLAGS
CPPFLAGS="-I$srcdir/t $CPPFLAGS"
AC_CHECK_TYPES([struct user_regs_struct, struct pt_regs],,,[#include "headers.h"])
AC_CHECK_SIZEOF([struct user_regs_struct],,[#include "headers.h"])
AC_CHECK_SIZEOF([struct pt_regs],,[#include "headers.h"])
CPPFLAGS=$save_CPPFLAGS

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
	ptrace
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

dnl check for pinktrace
PINKTRACE_REQUIRED=0.9

PKG_PROG_PKG_CONFIG([0.20.0])
PKG_CHECK_MODULES([pinktrace], [pinktrace >= $PINKTRACE_REQUIRED],,
		  AC_MSG_ERROR([sydbox requires pinktrace-$PINKTRACE_REQUIRED or newer]))

AC_MSG_CHECKING([whether pinktrace supports PTRACE_SEIZE])
PINKTRACE_HAVE_SEIZE=`${PKG_CONFIG} --variable=PINK_HAVE_SEIZE pinktrace`
if test x"$PINKTRACE_HAVE_SEIZE" = x"1"; then
	AC_MSG_RESULT([yes])
else
	PINKTRACE_HAVE_SEIZE=0
	AC_MSG_RESULT([no])
fi
AC_SUBST([PINKTRACE_HAVE_SEIZE])

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

dnl check for seccomp support
AC_ARG_ENABLE([seccomp],
	      [AS_HELP_STRING([--disable-seccomp], [enable seccomp support])],
	      [WANT_SECCOMP="$enableval"],
	      [WANT_SECCOMP="yes"])
if test x"$WANT_SECCOMP" = x"yes" ; then
	AC_CHECK_HEADER([sys/prctl.h],       [], [AC_MSG_ERROR([I need sys/prctl.h for seccomp support!])])
	AC_CHECK_HEADERS([linux/audit.h linux/seccomp.h])
	m4_define([include_seccomp_headers],
		  [#include <stdint.h>
		   #include <sys/prctl.h>
		   #ifdef HAVE_LINUX_AUDIT_H
		   #include <linux/audit.h>
		   #endif
		   #ifdef HAVE_LINUX_SECCOMP_H
		   #include <linux/seccomp.h>
		   #endif
		  ])
	AC_CHECK_DECL([SECCOMP_MODE_FILTER], [], [AC_MSG_WARN([SECCOMP_MODE_FILTER not declared! (seccomp may not work!)])],
		      [include_seccomp_headers])
	AC_CHECK_DECL([SECCOMP_RET_TRACE],   [], [AC_MSG_WARN([SECCOMP_RET_TRACE not declared! (seccomp may not work!)])],
		      [include_seccomp_headers])
	SYDBOX_HAVE_SECCOMP=1
else
	SYDBOX_HAVE_SECCOMP=0
fi
AC_MSG_CHECKING([for seccomp support])
AC_MSG_RESULT([$WANT_SECCOMP])
AM_CONDITIONAL([WANT_SECCOMP], test x"$WANT_SECCOMP" = x"yes")
AC_DEFINE_UNQUOTED([SYDBOX_HAVE_SECCOMP], [$SYDBOX_HAVE_SECCOMP], [Enable seccomp support])
AC_SUBST([SYDBOX_HAVE_SECCOMP])

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
SYDBOX_WANTED_CFLAGS="-pedantic -W -Wall -Wextra -Wshadow -Wno-unused-parameter"
for flag in $SYDBOX_WANTED_CFLAGS ; do
	AX_CHECK_COMPILER_FLAGS([$flag], [SYDBOX_CFLAGS="$SYDBOX_CFLAGS $flag"],)
done
AC_SUBST([SYDBOX_CFLAGS])

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

dnl built sources
GENERATED_FILE=misc/generated-file.txt
AC_SUBST_FILE([GENERATED_FILE])

dnl output
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
