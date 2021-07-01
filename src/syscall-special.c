/*
 * sydbox/syscall-special.c
 *
 * Special system call handlers
 *
 * Copyright (c) 2011, 2012, 2013, 2014, 2015, 2018, 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon strace which is:
 *   Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 *   Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 *   Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 *   Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "sydbox.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include "daemon.h"
#include "pink.h"
#include "path.h"
#include "pathdecode.h"
#include "proc.h"
#include "bsd-compat.h"
#include "sockmap.h"

#include <stdio.h>

#ifdef HAVE_LINUX_STAT_H
# include <linux/stat.h>
#endif
#ifdef HAVE_LINUX_UTSNAME_H
# include <linux/utsname.h>
#endif

#if defined(__x86_64__)
/* These might be macros. */
# ifdef st_atime
#  undef st_atime
#  define st_atime_was_a_macro
# endif
# ifdef st_mtime
#  undef st_mtime
#  define st_mtime_was_a_macro
# endif
# ifdef st_ctime
#  undef st_ctime
#  define st_ctime_was_a_macro
# endif
struct stat32 { /* for 32bit emulation */
	unsigned short st_dev;
	unsigned short st_ino;
	unsigned short st_mode;
	unsigned short st_nlink;
	unsigned short st_uid;
	unsigned short st_gid;
	unsigned short st_rdev;
	unsigned int st_size;
	unsigned int st_atime;
	unsigned int st_mtime;
	unsigned int st_ctime;
};
#elif !defined(__aarch64__) && ABIS_SUPPORTED > 1
# warning do not know the size of stat buffer for non-default ABIs
#endif

int sys_chdir(syd_process_t *current)
{
	int r;
	syscall_info_t info;

	current->update_cwd = true;
	if (sandbox_off_read(current))
		return 0;

	init_sysinfo(&info);
	info.deny_errno = EACCES;
	info.prefix = get_working_directory();

	r = box_check_path(current, &info);
	if (r != 0)
		current->update_cwd = false;
	return r;
}

int sys_fchdir(syd_process_t *current)
{
	int r;
	syscall_info_t info;

	current->update_cwd = true;
	if (sandbox_off_read(current))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = SYSCALL_ARG_MAX;
	info.deny_errno = EACCES;
	info.prefix = get_working_directory();

	r = box_check_path(current, &info);
	if (r != 0)
		current->update_cwd = false;
	return r;
}

int sysx_chdir(syd_process_t *current)
{
	char *newcwd;

	if (syd_proc_cwd(sydbox->pfd_cwd,
			 sydbox->config.use_toolong_hack,
			 &newcwd) < 0)
	{
		/* TODO: dump(DUMP_SYSCALL, current, "chdir", retval, "panic"); */
		return panic(current);
	}

	/* dump_syscall_2(current, "chdir", "OK", retval, P_CWD(current), newcwd); */

	if (magic_query_violation_raise_safe(current))
		//say("chdir done, updating current working directory of "
		//    "pid:%d to `%s', was `%s'",
		//    current->pid, newcwd, P_CWD(current));
		dump(DUMP_CHDIR, current->pid, newcwd, P_CWD(current));
	if (P_CWD(current))
		free(P_CWD(current));
	P_CWD(current) = newcwd;
	return 0;
}

int sys_getdents(syd_process_t *current)
{
	syscall_info_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = SYSCALL_ARG_MAX;
	info.deny_errno = ENOENT;
	// This is too much, e.g: shell can't open
	// /etc/bash/bashrc.d.
	// info.prefix = get_working_directory();

	return box_check_path(current, &info);
}

static int do_execve(syd_process_t *current, bool at_func)
{
	int r, flags = 0;
	bool badfd;
	char *path = NULL, *abspath = NULL, *prefix = NULL;

#if 0
# execve is unconditionally hooked for process/thread hierarchy tracking.
	if (sandbox_off_exec(current) &&
	    ACLQ_EMPTY(&sydbox->config.exec_kill_if_match))
		return 0;
#endif

	/* TODO: Avoid duplication with box_check_path */
	badfd = false;
	if (at_func) {
		r = path_prefix(current, 0, &prefix);
		if (r == -ESRCH) {
			return -ESRCH;
		} else if (r == -EBADF) {
			/* Using a bad directory for absolute paths is fine!
			 * System call will be denied after path_decode()
			 */
			badfd = true;
		} else if (r < 0) {
			r = deny(current, -r);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", current->sysname);
			return r;
		}

		flags = current->args[4];
	}

	if ((r = path_decode(current, at_func ? 1 : 0, &path)) < 0) {
		/*
		 * For EFAULT we assume path argument is NULL.
		 * If the flag AT_EMPTY_PATH is set, we assume this is fine.
		 */
		if (r == -ESRCH) {
			if (prefix)
				free(prefix);
			return r;
		} else if (!(r == -EFAULT && (flags & AT_EMPTY_PATH))) {
			r = deny(current, errno);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", current->sysname);
			if (prefix)
				free(prefix);
			return r;
		}
	} else { /* r == 0 */
		/* Careful, we may both have a bad fd and the path may be either
		 * NULL or empty string! */
		if (badfd && (!path || !*path || !path_is_absolute(path))) {
			/* Bad directory for non-absolute path! */
			r = deny(current, EBADF);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", current->sysname);
			if (prefix)
				free(prefix);
			if (path)
				free(path);
			return r;
		}
	}

	r = box_resolve_path(path,
			     prefix ? prefix : P_CWD(current),
			     current->pid,
			     (at_func && (flags & AT_SYMLINK_NOFOLLOW) ?
			      RPATH_NOFOLLOW :
			      0) | RPATH_EXIST,
			     &abspath);
	if (prefix)
		free(prefix);
	if (r < 0) {
		/* resolve_path failed, deny */
		r = deny(current, -r);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s(`%s')", current->sysname, path);
		if (path)
			free(path);
		return r;
	}
	if (path)
		free(path);

	/*
	 * Handling exec.kill_if_match and exec.resume_if_match:
	 *
	 * Resolve and save the path argument in current->abspath.
	 * When we receive a PINK_EVENT_EXEC which means execve() was
	 * successful, we'll check for kill_if_match and resume_if_match lists
	 * and kill or resume the process as necessary.
	 */
	if (abspath) {
		if (current->abspath)
			free(current->abspath);
		current->abspath = abspath;

		/*
		 * Calculate the SHA1 checksum of the pathname
		 * of the command to be executed by the process.
		 * This should be enabled with the magic command
		 * core/trace/program_checksum by setting it to
		 * 2 or higher.
		 */
		syd_proc_comm(sydbox->pfd, current->comm,
			      SYDBOX_PROC_MAX - 1);
		current->comm[SYDBOX_PROC_MAX-1] = '\0';
		if (magic_query_trace_program_checksum(NULL) > 1) {
			syd_proc_cmdline(sydbox->pfd, current->prog,
					 LINE_MAX-1);
			current->prog[LINE_MAX-1] = '\0';
			if ((r = path_to_hex(abspath)) < 0) {
				errno = -r;
				say_errno("can't calculate checksum of file "
					  "`%s'", abspath);
			} else {
				strlcpy(current->hash, sydbox->hash,
					SYD_SHA1_HEXSZ);
			}
		}
	}

	if (current->repr[0]) {
		free(current->repr[0]);
		current->repr[0] = NULL;
	}
	if (abspath)
		current->repr[0] = xstrdup(abspath);
	dump(DUMP_SYSENT, current);

	switch (P_BOX(current)->mode.sandbox_exec) {
	case SANDBOX_OFF:
		return 0;
	case SANDBOX_DENY:
		if (acl_match_path(ACL_ACTION_ALLOWLIST,
				   &P_BOX(current)->acl_exec,
				   abspath, NULL))
			return 0;
		break;
	case SANDBOX_ALLOW:
		if (!acl_match_path(ACL_ACTION_DENYLIST,
				    &P_BOX(current)->acl_exec,
				    abspath, NULL))
			return 0;
		break;
	default:
		assert_not_reached();
	}

	r = deny(current, EACCES);

	if (!acl_match_path(ACL_ACTION_NONE, &sydbox->config.filter_exec, abspath, NULL))
		violation(current, "%s(`%s')", current->sysname, abspath);

	free(abspath);
	current->abspath = NULL;

	return r;
}

int sys_execve(syd_process_t *current)
{
	return do_execve(current, false);
}

int sys_execveat(syd_process_t *current)
{
	return do_execve(current, true);
}

#define FAKE_MODE (S_IFCHR|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
/* /dev/null */
#define FAKE_RDEV_MAJOR 1
#define FAKE_RDEV_MINOR 3
#define FAKE_RDEV 259
#define FAKE_ATIME 505958400
#define FAKE_MTIME -842745600
#define FAKE_CTIME -2036448000

#define FAKE_SYSNAME "[01;36m☮[0m"
#define FAKE_NODENAME "sydb☮x"
#define FAKE_RELEASE VERSION
#define FAKE_VERSION "#"STRINGIFY(SYDBOX_API_VERSION)
#define FAKE_MACHINE "[0;1;31;91m♡[0m"
#define FAKE_DOMAINNAME "exherb☮.♡rg"

/* Write stat buffer */
static int write_stat(syd_process_t *current, unsigned int buf_index,
		      bool extended)
{
	int r;
	char *bufaddr = NULL;
	size_t bufsize;
	struct stat buf;
#ifdef HAVE_STRUCT_STATX
	struct statx bufx;
#endif

#if defined(__x86_64__)
	struct stat32 buf32;
	if (current->arch == SCMP_ARCH_X86) {
		if (extended) { /* TODO */
			say("statx system call for i386 abi, can not encode!");
			say("skipped stat() buffer write");
			return false;
		}
		memset(&buf32, 0, sizeof(struct stat32));
		buf32.st_mode = FAKE_MODE;
		buf32.st_rdev = FAKE_RDEV;
		buf32.st_atime = FAKE_ATIME;
		buf32.st_mtime = FAKE_MTIME;
		buf32.st_ctime = FAKE_CTIME;
		bufaddr = (char *)&buf32;
		bufsize = sizeof(struct stat32);
	}
#elif !defined(HAVE_STRUCT_STATX)
	if (extended) {
		say("struct statx undefined at build time, can not encode!");
		say("skipped statx() buffer write");
		return false;
	}
#elif defined(__i386__)
	if (extended) { /* TODO */
		say("statx system call on i386 abi, can not encode!");
		say("skipped statx() buffer write");
		return false;
	}
#elif defined(__arm__)
	if (extended) { /* TODO */
		say("statx system call on arm abi, can not encode!");
		say("skipped statx() buffer write");
		return false;
	}
#else
	if (current->arch != SCMP_ARCH_NATIVE) {
		say("don't know the size of stat buffer for ARCH %"PRIu32,
		    current->arch);
		say("skipped stat() buffer write.");
		return false;
	}
#endif

	if (extended) {
#ifdef HAVE_STRUCT_STATX
		memset(&bufx, 0, sizeof(struct statx));
		bufx.stx_mode = FAKE_MODE;
		bufx.stx_rdev_major = FAKE_RDEV_MAJOR;
		bufx.stx_rdev_minor = FAKE_RDEV_MINOR;
		bufx.stx_atime.tv_sec = FAKE_ATIME;
		bufx.stx_mtime.tv_sec = FAKE_MTIME;
		bufx.stx_ctime.tv_sec = FAKE_CTIME;
		bufaddr = (char *)&bufx;
		bufsize = sizeof(struct statx);
#else
		say("struct statx undefined at build time, can not encode!");
		say("skipped statx() buffer write");
		return 0;
#endif
	} else {
		memset(&buf, 0, sizeof(struct stat));
		buf.st_mode = FAKE_MODE;
		buf.st_rdev = FAKE_RDEV;
#ifdef st_atime_was_a_macro
# define st_atime st_atim.tv_sec
#endif
#ifdef st_mtime_was_a_macro
# define st_mtime st_mtim.tv_sec
#endif
#ifdef st_ctime_was_a_macro
# define st_ctime st_ctim.tv_sec
#endif
		buf.st_atime = FAKE_ATIME;
		buf.st_mtime = FAKE_MTIME;
		buf.st_ctime = FAKE_CTIME;
		bufaddr = (char *)&buf;
		bufsize = sizeof(struct stat);
	}

	long addr;
	addr = current->args[buf_index];
	if ((r = syd_write_data(current, addr, bufaddr, bufsize)) < 0) {
		errno = -r;
		say_errno("syd_write_stat");
	}
	(void)syd_write_vm_data(current, addr, bufaddr, bufsize);

	return true;
}

/* Write struct uname */
static int write_uname(syd_process_t *current, unsigned int buf_index)
{
	int r;
	struct new_utsname buf;

	strlcpy(buf.sysname, FAKE_SYSNAME, sizeof(FAKE_SYSNAME));
	strlcpy(buf.release, FAKE_RELEASE, sizeof(FAKE_RELEASE));
	strlcpy(buf.version, FAKE_VERSION, sizeof(FAKE_VERSION));
	strlcpy(buf.nodename, FAKE_NODENAME, sizeof(FAKE_NODENAME));
	strlcpy(buf.machine, FAKE_MACHINE, sizeof(FAKE_MACHINE));
#ifdef HAVE_STRUCT_NEW_UTSNAME_DOMAINNAME
	strlcpy(buf.domainname, FAKE_DOMAINNAME, sizeof(FAKE_DOMAINNAME));
#endif

	long addr = current->args[buf_index];
	char *bufaddr = (char *)&buf;
	size_t bufsize = sizeof(struct new_utsname);
	if ((r = syd_write_data(current, addr, bufaddr, bufsize)) < 0)
		return r;
	if (syd_write_vm_data(current, addr, bufaddr, bufsize) < 0)
		return -errno;

	return 0;
}

static int do_stat(syd_process_t *current, const char *path,
		   unsigned int buf_index, bool extended)
{
	int r = magic_cast_string(current, path, 1);
	if (r == MAGIC_RET_NOOP) {
		/* no magic */
		return 0;
	} else if (MAGIC_ERROR(r)) {
		if (r != MAGIC_RET_INVALID_KEY)
			say("failed to cast magic=`%s': %s", path,
			    magic_strerror(r));
		if (r == MAGIC_RET_PROCESS_TERMINATED) {
			r = -ESRCH;
		} else {
			switch (r) {
			case MAGIC_RET_NOT_SUPPORTED:
				errno = ENOTSUP;
				break;
			case MAGIC_RET_INVALID_KEY:
			case MAGIC_RET_INVALID_TYPE:
			case MAGIC_RET_INVALID_VALUE:
			case MAGIC_RET_INVALID_QUERY:
			case MAGIC_RET_INVALID_COMMAND:
			case MAGIC_RET_INVALID_OPERATION:
				errno = EINVAL;
				break;
			case MAGIC_RET_OOM:
				errno = ENOMEM;
				break;
			case MAGIC_RET_NOPERM:
			default:
				errno = EPERM;
				break;
			}
			r = deny(current, errno);
		}
	} else {
		write_stat(current, buf_index, extended);

		/* magic command accepted */
		if (r == MAGIC_RET_FALSE)
			errno = ENOENT;
		else
			errno = 0;

		enum violation_decision violation_decision;
		violation_decision = sydbox->config.violation_decision;
		if (violation_decision == VIOLATION_NOOP) {
			/* Special case for dry-run: intervention is OK for magic. */
			sydbox->config.violation_decision = VIOLATION_DENY;
			magic_set_sandbox_all("deny", current);
		}

		r = deny(current, 0);
		if (violation_decision == VIOLATION_NOOP) {
			sydbox->config.violation_decision = VIOLATION_NOOP;
			magic_set_sandbox_all("dump", current);
		}
	}

	/* r is one of:
	 * - return value of deny()
	 * - -ESRCH
	 */
	return r;
}

int sys_stat(syd_process_t *current)
{
	long addr;
	char path[SYDBOX_PATH_MAX];

	if (P_BOX(current)->magic_lock == LOCK_SET) {
		/* No magic allowed! */
		return 0;
	}
#if 0
	say("magic lock is %u<%s> for process:%u<%s,%s,ppid:%u,tgid:%u>, allowing magic...",
	    P_BOX(current)->magic_lock,
	    lock_state_to_string(P_BOX(current)->magic_lock),
	    current->pid, current->comm, current->hash,
	    current->ppid, current->tgid);
#endif

	addr = current->args[0];
	if (syd_read_string(current, addr, path, SYDBOX_PATH_MAX) < 0)
		return errno == EFAULT ? 0 : -errno;
	path[SYDBOX_PATH_MAX-1] = '\0';

	return do_stat(current, path, 1, false);
}

int sys_fstatat(syd_process_t *current)
{
	long addr;
	char path[SYDBOX_PATH_MAX];
	ssize_t count;

	if (P_BOX(current)->magic_lock == LOCK_SET) {
		/* No magic allowed! */
		return 0;
	}

	/* We intentionally disregard the first argument, aka `dirfd' here
	 * because the added complexity is not worth adding support for a
	 * usecase that's almost never possible, ie:
	 * cd /dev; fstatat(AT_FDCWD, sydbox/..., 0);
	 * does not work, however
	 * fstatat(AT_FDCWD, /dev/sydbox/..., 0);
	 * does.
	 */
	addr = current->args[1];
	if ((count = syd_read_string(current, addr, path, SYDBOX_PATH_MAX)) < 0)
		return errno == EFAULT ? 0 : -errno;
	else if (count == SYDBOX_PATH_MAX)
		path[count - 1] = '\0';
	else
		path[count] = '\0';

	return do_stat(current, path, 2, false);
}

int sys_statx(syd_process_t *current)
{
	long addr;
	char path[SYDBOX_PATH_MAX];
	ssize_t count;

	if (P_BOX(current)->magic_lock == LOCK_SET) {
		/* No magic allowed! */
		return 0;
	}

	/* See the note in sys_fstatat() on why we ignore AT_FDCWD. */
	addr = current->args[1];
	if ((count = syd_read_string(current, addr, path, SYDBOX_PATH_MAX)) < 0)
		return errno == EFAULT ? 0 : -errno;
	else if (count == SYDBOX_PATH_MAX)
		path[count - 1] = '\0';
	else
		path[count] = '\0';

	return do_stat(current, path, 4, true);
}

int filter_uname(uint32_t arch)
{
	int r;

	if (!magic_query_restrict_sysinfo(NULL))
		return 0;
	syd_rule_add_return(sydbox->ctx, SCMP_ACT_NOTIFY, SCMP_SYS(uname), 0);
	return 0;
}

int sys_uname(syd_process_t *current)
{
	int r;

	if (!magic_query_restrict_sysinfo(NULL))
		return 0;
	r = write_uname(current, 0);
	r = r < 0 ? EPERM : 0;
	if ((r = deny(current, r)) < 0)
		return r;

	return 0;
}
