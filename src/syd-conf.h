/*
 * sydbox/sydconf.h
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon strace/src/clone.c which is:
 *   Copyright (c) 1999-2000 Wichert Akkerman <wichert@cistron.nl>
 *   Copyright (c) 2002-2005 Roland McGrath <roland@redhat.com>
 *   Copyright (c) 2008 Jan Kratochvil <jan.kratochvil@redhat.com>
 *   Copyright (c) 2009-2013 Denys Vlasenko <dvlasenk@redhat.com>
 *   Copyright (c) 2006-2015 Dmitry V. Levin <ldv@strace.io>
 *   Copyright (c) 2014-2021 The strace developers.
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SYDCONF_H
#define SYDCONF_H

#include "HELPME.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif /* !_GNU_SOURCE */

#ifndef IN_SYDBOX
# define IN_SYDBOX 0
# endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#ifdef HAVE_LINUX_FS_H
# include <linux/fs.h>
#endif

#define SYDBOX_BPF_EXPORT_FLAGS (O_WRONLY|O_NOFOLLOW|O_CREAT|O_EXCL)
#define SYDBOX_BPF_EXPORT_MODE 0600
#define SYDBOX_BPF_DUMP_FLAGS (O_WRONLY|O_NOFOLLOW|O_CREAT|O_EXCL)
#define SYDBOX_BPF_DUMP_MODE 0600
#define SYDBOX_PFC_EXPORT_FLAGS (O_WRONLY|O_NOFOLLOW|O_CREAT)
#define SYDBOX_PFC_EXPORT_MODE 0600
#define SYDBOX_DUMP_FLAGS (O_WRONLY|O_NOFOLLOW|O_CREAT)
#define SYDBOX_DUMP_MODE 0600

#define SYSCALL_ARG_MAX 6
#define SYD_ARG_SEP 040
#define SYD_UNIT_SEP 037

#include <limits.h>
#define UID_MAX INT_MAX
#define GID_MAX INT_MAX

#ifndef NR_FILE
# warning "Your system does not define NR_FILE, defaulting to 1024"
# define NR_FILE 1024
#endif
#ifndef SYDBOX_MAP_LOAD_FAC
# define SYDBOX_MAP_LOAD_FAC 75
#endif
#ifndef SYDBOX_PROCMAP_CAP
# define SYDBOX_PROCMAP_CAP 64
#endif
#ifndef SYDBOX_SOCKMAP_CAP
# define SYDBOX_SOCKMAP_CAP 16
#endif
#ifndef SYDBOX_SYSMAP_CAP
# define SYDBOX_SYSMAP_CAP 64
#endif
#ifndef SYDBOX_API_VERSION
# error "SYDBOX_API_VERSION is not defined!"
#endif

#include <limits.h>
#include <unistd.h>

#define SYD_SHA1_CHECK_DEF ".syd.sha1sum"
#define SYD_SHA1_XATTR_MAX 0

#ifndef PAGE_SIZE
# define PAGE_SIZE sysconf(_SC_PAGESIZE)
#endif
#define MAX_ARG_STRLEN (PAGE_SIZE * 32)
#define MAX_ARG_STRINGS 0x7FFFFFFF

#if defined IA64
# define SYD_CLONE_ARG_FLAGS	0
# define SYD_CLONE_ARG_STACK	1
# define SYD_CLONE_ARG_STACKSIZE(sysnum)	((sysnum) == __NR_clone2 ? 2 : -1)
# define SYD_CLONE_ARG_PTID(sysnum)	((sysnum) == __NR_clone2 ? 3 : 2)
# define SYD_CLONE_ARG_CTID(sysnum)	((sysnum) == __NR_clone2 ? 4 : 3)
# define SYD_CLONE_ARG_TLS(sysnum)	((sysnum) == __NR_clone2 ? 5 : 4)
#elif defined S390 || defined S390X
# define SYD_CLONE_ARG_STACK	0
# define SYD_CLONE_ARG_FLAGS	1
# define SYD_CLONE_ARG_PTID	2
# define SYD_CLONE_ARG_CTID	3
# define SYD_CLONE_ARG_TLS	4
#elif defined X86_64 || defined X32
/* x86 personality processes have the last two arguments flipped. */
# define SYD_CLONE_ARG_FLAGS	0
# define SYD_CLONE_ARG_STACK	1
# define SYD_CLONE_ARG_PTID	2
# define SYD_CLONE_ARG_CTID(arch)	((arch != SCMP_ARCH_X86) ? 3 : 4)
# define SYD_CLONE_ARG_TLS(arch)	((arch != SCMP_ARCH_X86) ? 4 : 3)
#elif defined ALPHA || defined TILE || defined OR1K || defined CSKY
# define SYD_CLONE_ARG_FLAGS	0
# define SYD_CLONE_ARG_STACK	1
# define SYD_CLONE_ARG_PTID	2
# define SYD_CLONE_ARG_CTID	3
# define SYD_CLONE_ARG_TLS	4
#else
# define SYD_CLONE_ARG_FLAGS	0
# define ARG_STACK	1
# define ARG_PTID	2
# define ARG_TLS	3
# define ARG_CTID	4
#endif

/* Configuration */
/*
#ifndef SYDBOX_PATH_MAX
# if defined(PATH_MAX)
#  define SYDBOX_PATH_MAX ((PATH_MAX*4)+1)
# elif defined(MAXPATHLEN)
#  define SYDBOX_PATH_MAX ((MAXPATHLEN*4)+1)
# else
#  define SYDBOX_PATH_MAX (4096+1)
# endif
#endif
*/
/* When you update these variables,
 * update the asprintf invocation in
 * path_make_absolute() too!
 */
#define SYDBOX_NAME_MAX 1025
#define SYDBOX_PATH_MAX (4096+1)
#define SYDBOX_NDIR_MAX (4096-SYDBOX_NAME_MAX+1)
#define SYDBOX_NAME_MAX_STR STRINGIFY(SYDBOX_NAME_MAX)
#define SYDBOX_PATH_MAX_STR STRINGIFY(SYDBOX_PATH_MAX)
#define SYDBOX_NDIR_MAX_STR STRINGIFY(SYDBOX_NDIR_MAX)
#define SYDBIX_PATH_LEN 4096
#define SYDBOX_NDIR_LEN 3072
#define SYDBOX_NAME_LEN 1024
#define SYDBOX_PATH_LEN_STR STRINGIFY(SYDBOX_PATH_LEN)
#define SYDBOX_NDIR_LEN_STR STRINGIFY(SYDBOX_NDIR_LEN)
#define SYDBOX_NAME_LEN_STR STRINGIFY(SYDBOX_NAME_LEN)

#ifndef SYDBOX_MAXSYMLINKS
# if defined(SYMLOOP_MAX)
#  define SYDBOX_MAXSYMLINKS SYMLOOP_MAX
# elif defined(MAXSYMLINKS)
#  define SYDBOX_MAXSYMLINKS MAXSYMLINKS
# else
#  define SYDBOX_MAXSYMLINKS 32
# endif
#endif

#ifndef SIGLOST
# define SIGLOST 29
#endif

#ifndef SYDBOX_FNAME_EXT
# define SYDBOX_FNAME_EXT "syd-"
#endif

#ifndef SYDBOX_API_EXT
# define SYDBOX_API_EXT SYDBOX_FNAME_EXT STRINGIFY(SYDBOX_API_VERSION)
#endif

#ifndef SYDBOX_PROFILE_CHAR
# define SYDBOX_PROFILE_CHAR '@'
#endif

#ifndef SYDBOX_CONFIG_ENV
# define SYDBOX_CONFIG_ENV "SYDBOX_CONFIG"
#endif

#ifndef SYDBOX_DUMP_ENV
# define SYDBOX_DUMP_ENV "SYDBOX_DUMP"
#endif

#ifndef SYDBOX_MAGIC_PREFIX
# define SYDBOX_MAGIC_PREFIX "/dev/sydbox"
#endif

#ifndef SYDBOX_MAGIC_SET_CHAR
# define SYDBOX_MAGIC_SET_CHAR ':'
#endif

#ifndef SYDBOX_MAGIC_QUERY_CHAR
# define SYDBOX_MAGIC_QUERY_CHAR '?'
#endif

#ifndef SYDBOX_MAGIC_APPEND_CHAR
# define SYDBOX_MAGIC_APPEND_CHAR '+'
#endif

#ifndef SYDBOX_MAGIC_REMOVE_CHAR
# define SYDBOX_MAGIC_REMOVE_CHAR '-'
#endif

#ifndef SYDBOX_MAGIC_EXEC_CHAR
# define SYDBOX_MAGIC_EXEC_CHAR '!'
#endif /* !SYDBOX_MAGIC_EXEC_CHAR */

#ifndef SYDBOX_NO_GETDENTS
# undef SYDBOX_NO_GETDENTS
#endif

#ifndef SYDBOX_NOEXEC_NAME
# define SYDBOX_NOEXEC_NAME "noexec"
#endif
#ifndef SYDBOX_NOEXEC_ENV
# define SYDBOX_NOEXEC_ENV "SYDBOX_NOEXEC"
#endif

#define SYD_TRACE_OPTS (PINK_TRACE_OPTION_SYSGOOD|PINK_TRACE_OPTION_FORK|\
			PINK_TRACE_OPTION_VFORK|PINK_TRACE_OPTION_CLONE|\
			PINK_TRACE_OPTION_EXEC)
#define SYD_REMOTE_MEM_ONE SYDBOX_PATH_MAX
#define SYD_REMOTE_MEM_MAX (SYD_REMOTE_MEM_ONE * 6)
#define syd_remote_addr(addr, idx) ((addr) + (SYD_REMOTE_MEM_ONE * idx))

#ifndef SYD_SECCOMP_NOTIFY_RECV_TIMEOUT
# define SYD_SECCOMP_NOTIFY_RECV_TIMEOUT 3
#endif
#ifndef SYD_SECCOMP_NOTIFY_RESP_TIMEOUT
# define SYD_SECCOMP_NOTIFY_RESP_TIMEOUT 3
#endif
#ifndef SYD_POLL_TIMEOUT /* poll timeout in milliseconds */
# define SYD_POLL_TIMEOUT 42
#endif
#ifndef SYD_EXEC_TIMEOUT
# define SYD_EXEC_TIMEOUT 3600
#endif
#ifndef SYD_EXEC_SLEEP_STEP_SEC
# define SYD_EXEC_SLEEP_STEP_SEC 1
#endif
#ifndef SYD_EXEC_SLEEP_STEP_NSEC
# define SYD_EXEC_SLEEP_STEP_NSEC 0
#endif


#define SYD_SECCOMP_ARCH_ARGV_SIZ 20
#include <errno.h>
# define syd_rule_ok(r) ((r) == 0 ||\
			 (r) == -EACCES ||\
			 (r) == -EEXIST ||\
			 (r) == -EINVAL)
#if defined(SYDBOX_DUMP) && SYDBOX_DUMP
# define syd_rule_add(ctx, ...) { \
	r = seccomp_rule_add(ctx, __VA_ARGS__); \
	if (r == -EBUSY || r == -EFAULT || r == -EINVAL) { abort(); } \
	sydbox->filter_count++;}
# define syd_rule_add_return(ctx, ...) { \
	r = seccomp_rule_add(ctx, __VA_ARGS__); \
	if (r < 0) { \
		errno = -r; \
		say_errno("oops"); \
	} \
	if ((r < 0) &&\
	    (r == -EACCES) &&\
	    (r == -EEXIST) &&\
	    (r == -EOPNOTSUPP)) { return 0; \
	} else if (r == -EBUSY || r == -EFAULT || r == -EINVAL) { abort(); } \
	sydbox->filter_count++; }
#else
# define syd_rule_add(ctx, ...) do { \
	r = seccomp_rule_add(ctx, __VA_ARGS__); \
	if (r == 0) { sydbox->filter_count++; }} while (0)
# define syd_rule_add_return(ctx, ...) do { \
	r = seccomp_rule_add(ctx, __VA_ARGS__); \
	if ((r < 0) &&\
	    (r != -EACCES) &&\
	    (r != -EEXIST) && \
	    (r != -EOPNOTSUPP)) \
		{ return r; } \
	sydbox->filter_count++; } while (0)
#endif

#endif
