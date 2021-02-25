/*
 * sydbox/syscall-special.c
 *
 * Special system call handlers
 *
 * Copyright (c) 2011, 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon strace which is:
 *   Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 *   Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 *   Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 *   Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * Released under the terms of the 3-clause BSD license
 */

#include "sydbox.h"
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sched.h>
#include "pink.h"
#include "pathdecode.h"
#include "proc.h"
#include "bsd-compat.h"
#include "sockmap.h"

#include <stdio.h>

#include <fcntl.h>
#include <sys/stat.h>
#if PINK_ARCH_X86_64
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
#elif PINK_ABIS_SUPPORTED > 1
# warning do not know the size of stat buffer for non-default ABIs
#endif

int sysx_chdir(syd_process_t *current)
{
	int r;
	long retval;
	char *newcwd;

	if ((r = syd_read_retval(current, &retval, NULL)) < 0)
		return r;

	if (retval < 0) {
		/* TODO: dump(DUMP_SYSCALL, current, "chdir", retval, "ignore"); */
		return 0;
	}

	if (proc_cwd(current->pid, sydbox->config.use_toolong_hack, &newcwd) < 0) {
		/* TODO: dump(DUMP_SYSCALL, current, "chdir", retval, "panic"); */
		return panic(current);
	}

	/* TODO: dump(DUMP_SYSCALL, current, "chdir", retval, "success", P_CWD(current), newcwd); */

	if (P_CWD(current))
		free(P_CWD(current));
	P_CWD(current) = newcwd;
	return 0;
}

int sys_execve(syd_process_t *current)
{
	int r;
	char *path = NULL, *abspath = NULL;

	if (sandbox_off_exec(current) &&
	    ACLQ_EMPTY(&sydbox->config.exec_kill_if_match) &&
	    ACLQ_EMPTY(&sydbox->config.exec_resume_if_match)) {
		return 0;
	}

	r = path_decode(current, 0, &path);
	if (r == -ESRCH)
		return r;
	else if (r < 0)
		return deny(current, errno);

	r = box_resolve_path(path, P_CWD(current), current->pid, RPATH_EXIST, &abspath);
	if (r < 0) {
		/* resolve_path failed, deny */
		r = deny(current, -r);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s(`%s')", current->sysname, path);
		free(path);
		return r;
	}
	free(path);

	/*
	 * Handling exec.kill_if_match and exec.resume_if_match:
	 *
	 * Resolve and save the path argument in current->abspath.
	 * When we receive a PINK_EVENT_EXEC which means execve() was
	 * successful, we'll check for kill_if_match and resume_if_match lists
	 * and kill or resume the process as necessary.
	 */
	if (current->abspath)
		free(current->abspath);
	current->abspath = abspath;

	switch (P_BOX(current)->sandbox_exec) {
	case SANDBOX_OFF:
		return 0;
	case SANDBOX_DENY:
		if (acl_match_path(ACL_ACTION_WHITELIST,
				   &P_BOX(current)->acl_exec,
				   abspath, NULL))
			return 0;
		break;
	case SANDBOX_ALLOW:
		if (acl_match_path(ACL_ACTION_BLACKLIST,
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

static int sys_stat_common(syd_process_t *current, const char *path,
			   unsigned int buf_index)
{
	int r;
	long addr;

	r = magic_cast_string(current, path, 1);
	if (r == MAGIC_RET_NOOP) {
		/* no magic */
		return 0;
	} else if (MAGIC_ERROR(r)) {
		say("failed to cast magic=`%s': %s", path, magic_strerror(r));
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
	} else if (r != MAGIC_RET_NOOP) {
		/* Write stat buffer */
		const char *bufaddr = NULL;
		size_t bufsize;
		struct stat buf;
#define FAKE_MODE (S_IFCHR|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
#define FAKE_RDEV 259 /* /dev/null */
#define FAKE_ATIME 505958400
#define FAKE_MTIME -842745600
#define FAKE_CTIME 558748800
#if PINK_ARCH_X86_64
		struct stat32 buf32;

		if (current->abi == PINK_ABI_I386) {
			memset(&buf32, 0, sizeof(struct stat32));
			buf32.st_mode = FAKE_MODE;
			buf32.st_rdev = FAKE_RDEV;
			buf32.st_atime = FAKE_ATIME;
			buf32.st_mtime = FAKE_MTIME;
			buf32.st_ctime = FAKE_CTIME;
			bufaddr = (char *)&buf32;
			bufsize = sizeof(struct stat32);
		}
#else
		if (current->abi != PINK_ABI_DEFAULT) {
			say("don't know the size of stat buffer for ABI %d", current->abi);
			say("skipped stat() buffer write");
			goto skip_write;
		}
#endif
		if (!bufaddr) {
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

		if (pink_read_argument(current->pid, current->regset, buf_index, &addr) == 0)
			pink_write_vm_data(current->pid, current->regset, addr, bufaddr, bufsize);
#if !PINK_ARCH_X86_64
skip_write:
#endif
		/* magic command accepted */
		if (r < 0)
			errno = -r;
		else if (r == MAGIC_RET_FALSE)
			errno = ENOENT;
		else
			errno = 0;
		r = deny(current, errno);
	}

	/* r is one of:
	 * - return value of deny()
	 * - -ESRCH
	 */
	return r;
}

int sys_stat(syd_process_t *current)
{
	int r;
	long addr;
	char path[SYDBOX_PATH_MAX];

	if (P_BOX(current)->magic_lock == LOCK_SET) {
		/* No magic allowed! */
		return 0;
	}

	if ((r = syd_read_argument(current, 0, &addr)) < 0)
		return r;
	if (syd_read_string(current, addr, path, SYDBOX_PATH_MAX) < 0)
		return errno == EFAULT ? 0 : -errno;

	return sys_stat_common(current, path, 1);
}

int sys_fstatat(syd_process_t *current)
{
	int r;
	long addr;
	char path[SYDBOX_PATH_MAX];

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
	if ((r = syd_read_argument(current, 1, &addr)) < 0)
		return r;
	if (syd_read_string(current, addr, path, SYDBOX_PATH_MAX) < 0)
		return errno == EFAULT ? 0 : -errno;

	return sys_stat_common(current, path, 2);
}

int sys_dup(syd_process_t *current)
{
	int r;
	long fd;

	current->args[0] = -1;

	if (sandbox_off_network(current) ||
	    !sydbox->config.whitelist_successful_bind)
		return 0;

	if ((r = syd_read_argument(current, 0, &fd)) < 0)
		return r;

	current->args[0] = fd;
	current->flags |= SYD_STOP_AT_SYSEXIT;
	return 0;
}

int sysx_dup(syd_process_t *current)
{
	int r;
	long retval;
	const struct sockinfo *oldinfo;

	if (sandbox_off_network(current) ||
	    !sydbox->config.whitelist_successful_bind ||
	    current->args[0] < 0)
		return 0;

	if ((r = syd_read_retval(current, &retval, NULL)) < 0)
		return r;

	if (retval < 0) {
		/* ignore failed system call */
		return 0;
	}

	if (!(oldinfo = sockmap_find(&P_SOCKMAP(current), current->args[0]))) {
		/* duplicated unknown file descriptor, ignore */
		return 0;
	}

	/* file descriptor duplicated */
	sockmap_add(&P_SOCKMAP(current), retval, sockinfo_xdup(oldinfo));
	return 0;
}

int sys_fcntl(syd_process_t *current)
{
	bool strict;
	int r, fd, cmd, arg0;

	current->args[0] = -1;
	strict = !sydbox->config.use_seccomp &&
		 sydbox->config.restrict_file_control;

	if (!strict && (sandbox_off_network(current) ||
			!sydbox->config.whitelist_successful_bind))
		return 0;

	if ((r = syd_read_argument_int(current, 1, &cmd)) < 0)
		return r;

	switch (cmd) {
	case F_DUPFD:
#ifdef F_DUPFD_CLOEXEC
	case F_DUPFD_CLOEXEC:
#endif /* F_DUPFD_CLOEXEC */
		break;
	case F_SETFL:
		if (!strict)
			return 0;
		if ((r = syd_read_argument_int(current, 0, &arg0)) < 0)
			return r;
		if (arg0 & (O_ASYNC|O_DIRECT))
			return deny(current, EINVAL);
		/* fall through */
	case F_GETFL:
	case F_SETOWN:
	case F_SETLK:
	case F_SETLKW:
#if defined(F_SETLK64) && F_SETLK != F_SETLK64
	case F_SETLK64:
#endif
#if defined(F_SETLKW64) && F_SETLKW != F_SETLKW64
	case F_SETLKW64:
#endif
	case F_GETFD:
	case F_SETFD:
		return 0;
	default:
		if (strict)
			return deny(current, EINVAL);
		return 0;
	}

	if (sandbox_off_network(current) ||
	     !sydbox->config.whitelist_successful_bind)
	    return 0;

	if ((r = syd_read_argument_int(current, 0, &fd)) < 0)
		return r;

	current->args[0] = fd;
	current->args[1] = cmd;
	current->flags |= SYD_STOP_AT_SYSEXIT;
	return 0;
}

int sysx_fcntl(syd_process_t *current)
{
	int r;
	long retval;
	const struct sockinfo *oldinfo;

	if (sandbox_off_network(current) ||
	    !sydbox->config.whitelist_successful_bind ||
	    current->args[0] < 0)
		return 0;

	if ((r = syd_read_retval(current, &retval, NULL)) < 0)
		return r;

	if (retval < 0) {
		/* ignore failed system call */
		return 0;
	}

	if (!(oldinfo = sockmap_find(&P_SOCKMAP(current), current->args[0]))) {
		/* unknown file descriptor duplicated, ignore */
		return 0;
	}

	/* file descriptor duplicated */
	sockmap_add(&P_SOCKMAP(current), retval, sockinfo_xdup(oldinfo));
	return 0;
}

static int set_clone_flags(syd_process_t *current, unsigned long flags)
{
	unsigned long clone_flags;

	current->new_clone_flags = 0;
	if (!flags) {
		int r = 0;
		if ((r = syd_read_argument(current, 0, (long *)&clone_flags)) < 0)
			return r;
		flags = clone_flags;
	}
	current->new_clone_flags = flags;
	return 0;
}

int sys_fork(syd_process_t *current)
{
	return set_clone_flags(current, SIGCHLD);
}

int sys_vfork(syd_process_t *current)
{
	return set_clone_flags(current, CLONE_VM|CLONE_VFORK|SIGCHLD);
}

int sys_clone(syd_process_t *current)
{
	int r;

	r = set_clone_flags(current, 0);
	if (current->new_clone_flags & CLONE_VFORK)
		return sys_vfork(current);
	else if ((current->new_clone_flags & CSIGNAL) == SIGCHLD)
		return sys_fork(current);

	return r;
}
