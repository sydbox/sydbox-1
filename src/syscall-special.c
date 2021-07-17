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

#include "syd-box.h"
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
	if (sandbox_not_read(current))
		return 0;

	init_sysinfo(&info);
	info.deny_errno = EACCES;
	info.prefix = P_CWD(current) ? P_CWD(current) : get_working_directory();
	info.safe = true;
	info.access_mode = sandbox_deny_read(current)
		? ACCESS_ALLOWLIST
		: ACCESS_DENYLIST;
	info.access_list = &P_BOX(current)->acl_read;
	info.access_filter = &sydbox->config.filter_read;

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
	if (sandbox_not_read(current))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 0;
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

	if (sydbox->pfd_cwd < 0 &&
	    sydbox->pid_valid == current->pid) {
		int fd;
		if ((fd = syd_proc_cwd_open(sydbox->pid_valid)) >= 0)
			sydbox->pfd_cwd = fd;
	}
	if (sydbox->pfd_cwd < 0)
		return 0;

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
		//    "pid:%d to »%s«, was »%s«",
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

	if (sandbox_not_read(current))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 0;
	info.deny_errno = ENOENT;
	info.prefix = P_CWD(current) ? P_CWD(current) : get_working_directory();
	info.safe = true;
	info.access_mode = sandbox_deny_read(current)
		? ACCESS_ALLOWLIST
		: ACCESS_DENYLIST;
	info.access_list = &P_BOX(current)->acl_read;
	info.access_filter = &sydbox->config.filter_read;

	return box_check_path(current, &info);
}

static int do_execve(syd_process_t *current, bool at_func)
{
	int r, flags = 0;
	bool badfd;
	char *path = NULL, *abspath = NULL, *prefix = NULL;

#if 0
# execve is unconditionally hooked for process/thread hierarchy tracking.
	if (sandbox_not_exec(current) &&
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
			violation(current, "%s(»%s«)", current->sysname, path);
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
		current->abspath = abspath;

		/* kill_if_match */
		r = 0;
		const char *match;
		if (acl_match_path(ACL_ACTION_NONE,
				   &sydbox->config.exec_kill_if_match,
				   current->abspath, &match)) {
			say("kill_if_match pattern=»%s« matches execve path=»%s«",
			    match, current->abspath);
			say("killing process");
			kill_one(current, SIGLOST);
			return -ESRCH;
		}
		/* execve path does not match if_match patterns */

		if (dump_enabled()) {
			//say("execve: %d executed »%s«", current->pid, current->abspath);
			dump(DUMP_EXEC, current->pid, current->abspath);
		}

		/*
		 * Calculate the XXH64 & SHA1 checksums of the pathname
		 * of the command to be executed by the process.
		 * This should be enabled with the magic command
		 * core/trace/program_checksum by setting it to
		 * 1 or higher for XXH64, and
		 * 2 or higher for SHA1.
		 */
		syd_proc_comm(sydbox->pfd, current->comm,
			      SYDBOX_PROC_MAX - 1);
		current->comm[SYDBOX_PROC_MAX-1] = '\0';
		int csum = magic_query_trace_program_checksum(NULL);
		if (csum >= 1) {
			syd_proc_cmdline(sydbox->pfd, current->prog,
					 LINE_MAX-1);
			current->prog[LINE_MAX-1] = '\0';
		}
		if (csum >= 1) {
			if ((r = syd_path_to_xxh64_hex(abspath, &current->xxh,
						       NULL)) < 0) {
				errno = -r;
				say_errno("Can't calculate checksum of file "
					  "»%s«", abspath);
			} else {
				sayv("Calculated XXH hash %"PRIu64" of file "
				    "»%s«", current->xxh, abspath);
			}
		}
		if (csum > 2) {
			if ((r = syd_path_to_sha1_hex(abspath, sydbox->hash)) < 0) {
				errno = -r;
				say_errno("Can't calculate checksum of file "
					  "»%s«", abspath);
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
	current->abspath = abspath;
	dump(DUMP_SYSENT, current);
 
	if (sandbox_not_exec(current)) {
		r = 0;
		goto out;
	}

	syscall_info_t info;

	init_sysinfo(&info);
	info.deny_errno = EACCES;
	info.cache_abspath = abspath;
	info.access_mode = sandbox_deny_exec(current)
		? ACCESS_ALLOWLIST
		: ACCESS_DENYLIST;
	info.access_list = &P_BOX(current)->acl_exec;
	info.access_filter = &sydbox->config.filter_exec;

	r = box_check_path(current, &info);
out:
	if (prefix)
		free(prefix);
	free(abspath);
	current->abspath = NULL;

	return r;
}

int sys_execve(syd_process_t *current)
{
	int r;

	r = do_execve(current, false);

#if 0
# TODO: breaks some processes, figure out!
	if (!r && current->abspath) {
		int rr;
		long addr;
		char *comm = process_comm(current, current->abspath);

		if ((rr = syd_read_vm_data(current, current->args[1],
					   (char *)&addr,
					   sizeof(long))) < 0) {
			errno = -rr;
			say_errno("syd_read_comm");
		}
		if ((rr = syd_write_vm_data(current, addr, comm, strlen(comm)+1)) < 0) {
			errno = -rr;
			say_errno("syd_write_comm");
		}
	}
#endif

	return r;
}

int sys_execveat(syd_process_t *current)
{
	int r;

	r = do_execve(current, true);
#if 0
# TODO: see comment in sys_execve
	if (!r && current->abspath) {
		char *comm = process_comm(current, current->abspath);
		if ((r = syd_write_data(current, current->args[2], comm, 16)) < 0) {
			errno = -r;
			say_errno("syd_write_data");
		}
	}
#endif

	return r;
}

/* /dev/null */
#define FAKE_RDEV_MAJOR 1
#define FAKE_RDEV_MINOR 3
#define FAKE_RDEV 259
#define FAKE_ATIME 505958400
#define FAKE_MTIME (int64_t)-842745600
#define FAKE_CTIME (int64_t)-2036448000
#define FAKE_UID 42
#define FAKE_GID 1984

#define FAKE_SYSNAME "[01;36m☮[0m"
#define FAKE_NODENAME "sydb☮x"
#define FAKE_RELEASE VERSION
#define FAKE_VERSION "#"STRINGIFY(SYDBOX_API_VERSION)
#define FAKE_MACHINE "[0;1;31;91m♡[0m"
#define FAKE_DOMAINNAME "exherb☮.♡rg"

/* Write stat buffer */
SYD_GCC_ATTR((nonnull(1)))
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

	time_t mtime = current->xxh ? current->xxh : FAKE_MTIME;

#if 0
#define FAKE_MODE (S_IFCHR|S_IXUSR|S_IXGRP|S_IXOTH)
#endif
	mode_t mode = S_IFCHR;
	sandbox_t *box = box_current(current);

	switch (box->mode.sandbox_exec) {
	case SANDBOX_OFF:
		break;
	case SANDBOX_BPF:
		mode |= S_IXUSR;
		break;
	case SANDBOX_DENY:
		mode |= (S_IXUSR|S_IXGRP);
		break;
	case SANDBOX_ALLOW:
		mode |= (S_IXUSR|S_IXGRP|S_IXOTH);
		break;
	}
	switch (box->mode.sandbox_read) {
	case SANDBOX_OFF:
		break;
	case SANDBOX_BPF:
		mode |= S_IRUSR;
		break;
	case SANDBOX_DENY:
		mode |= (S_IRUSR|S_IRGRP);
		break;
	case SANDBOX_ALLOW:
		mode |= (S_IRUSR|S_IRGRP|S_IROTH);
		break;
	}
	switch (box->mode.sandbox_write) {
	case SANDBOX_OFF:
		break;
	case SANDBOX_BPF:
		mode |= S_IWUSR;
		break;
	case SANDBOX_DENY:
		mode |= (S_IWUSR|S_IWGRP);
		break;
	case SANDBOX_ALLOW:
		mode |= (S_IWUSR|S_IWGRP|S_IWOTH);
		break;
	}
	switch (box->mode.sandbox_network) {
	case SANDBOX_OFF:
		break;
	case SANDBOX_BPF:
		mode |= S_ISUID;
		break;
	case SANDBOX_DENY:
		mode |= (S_ISUID|S_ISGID);
		break;
	case SANDBOX_ALLOW:
		mode |= (S_ISUID|S_ISGID|S_ISVTX);
		break;
	}

#if defined(__x86_64__)
	struct stat32 buf32;
	if (current->arch == SCMP_ARCH_X86) {
		if (extended) { /* TODO */
			say("statx system call for i386 abi, can not encode!");
			say("skipped stat() buffer write");
			return false;
		}
		memset(&buf32, 0, sizeof(struct stat32));
		buf32.st_mode = mode;
		buf32.st_rdev = FAKE_RDEV;
		buf32.st_atime = FAKE_ATIME;
		buf32.st_mtime = mtime;
		buf32.st_ctime = FAKE_CTIME;
		buf32.st_uid = FAKE_UID;
		buf32.st_gid = FAKE_GID;
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
		bufx.stx_mode = mode;
		bufx.stx_uid = FAKE_UID;
		bufx.stx_gid = FAKE_GID;
		bufx.stx_rdev_major = FAKE_RDEV_MAJOR;
		bufx.stx_rdev_minor = FAKE_RDEV_MINOR;
		bufx.stx_atime.tv_sec = FAKE_ATIME;
		bufx.stx_mtime.tv_sec = mtime;
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
		buf.st_mode = mode;
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
		buf.st_mtime = mtime;
		buf.st_ctime = FAKE_CTIME;
		buf.st_uid = FAKE_UID;
		buf.st_gid = FAKE_GID;
		bufaddr = (char *)&buf;
		bufsize = sizeof(struct stat);
	}

	long addr_path;
	if (endswith(current->sysname, "stat"))
		addr_path = current->args[0];
	else if (streq(current->sysname, "newfstatat"))
		addr_path = current->args[1];
	else
		assert_not_reached();
	if ((r = syd_write_vm_data(current, addr_path, current->hash, SYD_SHA1_HEXSZ+1)) < 0) {
		errno = -r;
		say_errno("syd_write_stat");
	}

	long addr;
	addr = current->args[buf_index];
	if ((r = syd_write_vm_data(current, addr, bufaddr, bufsize)) < 0) {
		errno = -r;
		say_errno("syd_write_stat");
	}

	return true;
}

/* Write struct uname */
static int write_uname(syd_process_t *current, unsigned int buf_index)
{
	int r;
	struct new_utsname buf;

	if (os_release <= KERNEL_VERSION(2,4,0)) {
		strlcpy(buf.release, FAKE_RELEASE,
			sizeof(FAKE_RELEASE));
	} else if (os_release <= KERNEL_VERSION(2,6,0)) {
		strlcpy(buf.release, "2.6."FAKE_RELEASE,
			sizeof("2.6."FAKE_RELEASE));
	} else if (os_release <= KERNEL_VERSION(3,0,0)) {
		strlcpy(buf.release, "3.5."FAKE_RELEASE,
			sizeof("3.5."FAKE_RELEASE));
	} else if (os_release <= KERNEL_VERSION(4,0,0)) {
		strlcpy(buf.release, "4.0."FAKE_RELEASE,
			sizeof("4.0."FAKE_RELEASE));
	} else if (os_release <= KERNEL_VERSION(5,0,0)) {
		strlcpy(buf.release, "5.0."FAKE_RELEASE,
			sizeof("5.1."FAKE_RELEASE));
	} else if (os_release <= KERNEL_VERSION(5,4,0)) {
		strlcpy(buf.release, "5.4."FAKE_RELEASE,
			sizeof("5.4."FAKE_RELEASE));
	} else if (os_release <= KERNEL_VERSION(6,0,0)) {
		strlcpy(buf.release, "5.42."FAKE_RELEASE,
			sizeof("5.42."FAKE_RELEASE));
	} else {
		strlcpy(buf.release, "7.42."FAKE_RELEASE,
			sizeof("7.42."FAKE_RELEASE));
	}

	strlcpy(buf.sysname, FAKE_SYSNAME, sizeof(FAKE_SYSNAME));
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
	int r;

	bool locked = !!(P_BOX(current) && P_BOX(current)->magic_lock == LOCK_SET);
	if (locked) {
		/* No magic allowed! */
		if (!streq(path, SYDBOX_MAGIC_PREFIX))
			return 0;
		r = MAGIC_RET_OK;
	} else {
		r = magic_cast_string(current, path, 1);
	}
	if (r == MAGIC_RET_NOOP) {
		/* no magic */
		return 0;
	} else if (MAGIC_ERROR(r)) {
		if (r != MAGIC_RET_INVALID_KEY)
			say("failed to cast magic=»%s«: %s", path,
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
		return r;
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
	char path[SYDBOX_PATH_MAX] = {0};

	addr = current->args[0];
	if (syd_read_string(current, addr, path, SYDBOX_PATH_MAX) < 0)
		return errno == EFAULT ? 0 : -errno;
	path[SYDBOX_PATH_MAX-1] = '\0';

	return do_stat(current, path, 1, false);
}

inline int sys_lstat(syd_process_t *current)
{
	return sys_stat(current);
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

	/* Step 1: Check the dirfd */
	bool badfd = false;
	char *prefix = NULL;
	int r = path_prefix(current, 0, &prefix);
	if (r == -ESRCH) {
		return -ESRCH;
	} else if (r == -EBADF) {
		/* Using a bad directory for absolute paths is fine!
		 */
		badfd = true;
	} else if (r < 0) {
		r = deny(current, -r);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s()", current->sysname);
		return r;
	}

	/* Step 2: Check the second argument */
	addr = current->args[1];
	if ((count = syd_read_string(current, addr, path, SYDBOX_PATH_MAX)) < 0)
		return errno == EFAULT ? 0 : -errno;
	else if (count == SYDBOX_PATH_MAX)
		path[count - 1] = '\0';
	else
		path[count] = '\0';

	/* Careful, we may both have a bad fd and the path may be either
	 * NULL or empty string! */
	if (badfd && (!*path || !path_is_absolute(path))) {
		/* Bad directory for non-absolute path! */
		r = deny(current, EBADF);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s()", current->sysname);
		if (prefix)
			free(prefix);
		return r;
	}

	char *abspath = NULL;
	unsigned rmode = 0;
	if (current->args[3] & AT_SYMLINK_NOFOLLOW)
		rmode |= RPATH_NOFOLLOW;
	if ((r = box_resolve_path(path, prefix ? prefix : P_CWD(current),
				  sydbox->pid_valid, rmode, &abspath)) < 0) {
		r = deny(current, -r);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s(»%s«)",
				  current->sysname,
				  path);
		goto out;
	}

	r = do_stat(current, abspath ? abspath : path, 2, false);
out:
	if (prefix)
		free(prefix);
	if (abspath)
		free(abspath);
	return r;
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

	/* Step 1: Check the dirfd */
	bool badfd = false;
	char *prefix = NULL;
	int r = path_prefix(current, 0, &prefix);
	if (r == -ESRCH) {
		return -ESRCH;
	} else if (r == -EBADF) {
		/* Using a bad directory for absolute paths is fine!
		 */
		badfd = true;
	} else if (r < 0) {
		r = deny(current, -r);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s()", current->sysname);
		return r;
	}

	/* Step 2: Check the second argument */
	addr = current->args[1];
	if ((count = syd_read_string(current, addr, path, SYDBOX_PATH_MAX)) < 0)
		return errno == EFAULT ? 0 : -errno;
	else if (count == SYDBOX_PATH_MAX)
		path[count - 1] = '\0';
	else
		path[count] = '\0';

	/* Careful, we may both have a bad fd and the path may be either
	 * NULL or empty string! */
	if (badfd && (!*path || !path_is_absolute(path))) {
		/* Bad directory for non-absolute path! */
		r = deny(current, EBADF);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s()", current->sysname);
		if (prefix)
			free(prefix);
		return r;
	}

	char *abspath = NULL;
	unsigned rmode = 0;
	if (current->args[2] & AT_SYMLINK_NOFOLLOW)
		rmode |= RPATH_NOFOLLOW;
	if ((r = box_resolve_path(path, prefix ? prefix : P_CWD(current),
				  sydbox->pid_valid, rmode, &abspath)) < 0) {
		r = deny(current, -r);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s(»%s«)",
				  current->sysname,
				  path);
		goto out;
	}

	r = do_stat(current, abspath, 4, true);
out:
	if (prefix)
		free(prefix);
	if (abspath)
		free(abspath);
	return r;
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
