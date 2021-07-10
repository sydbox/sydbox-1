/* headers.h: include all system headers
 *
 * Copyright 1999-2008 Gentoo Foundation
 * Licensed under the GPL-2
 */

#ifndef __SB_HEADERS_H__
#define __SB_HEADERS_H__

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_DIRENT_H
# include <dirent.h>
#endif
#ifdef HAVE_DLFCN_H
# include <dlfcn.h>
#endif
#ifdef HAVE_ELF_H
# include <elf.h>
#endif
#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif
#ifdef HAVE_EXECINFO_H
# include <execinfo.h>
#endif
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#ifdef HAVE_GRP_H
# include <grp.h>
#endif
#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif
#ifdef HAVE_LIBGEN_H
# include <libgen.h>
#endif
#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif
#ifdef HAVE_MEMORY_H
# include <memory.h>
#endif
#ifdef HAVE_PTHREAD_H
# include <pthread.h>
#endif
#ifdef HAVE_PWD_H
# include <pwd.h>
#endif
#ifdef HAVE_SIGINFO_H
# include <siginfo.h>
#endif
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#ifdef HAVE_STDARG_H
# include <stdarg.h>
#endif
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif
#ifdef HAVE_STDDEF_H
# include <stddef.h>
#endif
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
# include <string.h>
#endif
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif
#ifdef HAVE_SYSCALL_H
# include <syscall.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_UTIME_H
# include <utime.h>
#endif

#ifdef HAVE_SYS_FILE_H
# include <sys/file.h>
#endif
#ifdef HAVE_SYS_MMAN_H
# include <sys/mman.h>
#else
#error
#endif
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYS_PTRACE_H
# include <sys/ptrace.h>
#endif
#ifdef HAVE_SYS_REG_H
# include <sys/reg.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef HAVE_SYS_SYSCALL_H
# include <sys/syscall.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_USER_H
# include <sys/user.h>
#endif
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif
#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#ifdef HAVE_ASM_PTRACE_H
# include <asm/ptrace.h>
#endif
#ifdef HAVE_LINUX_PTRACE_H
# if __ia64__
#  ifdef HAVE_STRUCT_IA64_FPREG
#   define ia64_fpreg XXX_ia64_fpreg
#  endif
#  ifdef HAVE_STRUCT_PT_ALL_USER_REGS
#   define pt_all_user_regs XXX_pt_all_user_regs
#  endif
# endif
# ifdef HAVE_STRUCT_PTRACE_PEEKSIGINFO_ARGS
#  define ptrace_peeksiginfo_args XXX_ptrace_peeksiginfo_args
# endif
# include <linux/ptrace.h>
# if __ia64__
#  undef ia64_fpreg
#  undef pt_all_user_regs
# endif
# ifdef HAVE_STRUCT_PTRACE_PEEKSIGINFO_ARGS
#  undef ptrace_peeksiginfo_args
# endif
#endif

#ifdef HAVE_CONFIG_H
# include "localdecls.h"
#endif

#endif
