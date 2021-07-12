/*
 * sydbox/syscall-system.c
 *
 * System calls which are checked against the system denylist.
 *
 * Copyright (c) 2011, 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "syd-box.h"
#include "syd-sys.h"
#include <inttypes.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h> /* TODO: check in configure.ac */
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_LINUX_VERSION_H
# include <linux/version.h>
#else
# ifdef KERNEL_VERSION
#  undef KERNEL_VERSION
# endif
# define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif
#include "pink.h"
#include "bsd-compat.h"
#include "errno2name.h"
#include "sockmap.h"
#include "wildmatch.h"

#if defined(HAVE_LINUX_OPENAT2_H) && defined(HAVE_STRUCT_OPEN_HOW)
# include <linux/openat2.h>
#else
struct open_how {
	unsigned long flags;
	unsigned long mode;
	unsigned long resolve;
};
#define RESOLVE_NO_MAGICLINKS	0x02
#define RESOLVE_NO_SYMLINKS	0x04
#define RESOLVE_BENEATH		0x08
#endif

struct open_info {
	bool may_read;
	bool may_write;
	short rmode;
	enum syd_stat syd_mode;
};

void oops(syd_process_t *current,
	  const char *needle, const char *denymatch)
{
	sandbox_t *box = box_current(current);

	say(ANSI_DARK_RED"💀 !!!ALERT!! 💀"
	    ANSI_DARK_GREEN" »"
	    ANSI_DARK_CYAN"%s"
	    ANSI_DARK_GREEN"« matches system denylist pattern »"
	    ANSI_DARK_YELLOW"%s"ANSI_DARK_GREEN"«!",
	    needle, denymatch);
	say(ANSI_DARK_RED"CⒶll: »"ANSI_DARK_CYAN
	    "%s(%ld,%ld,%ld,%ld,%ld,%ld)"
	    SYD_WARN"«",
	    current->sysname,
	    current->args[0], current->args[1], current->args[2],
	    current->args[3], current->args[4], current->args[5]);
	say(ANSI_DARK_RED"C☮mm: »"ANSI_DARK_CYAN"%s"SYD_WARN"«",
	    current->comm);
	say(ANSI_DARK_RED"Pr☮g: »"ANSI_DARK_CYAN"%s"SYD_WARN"«",
	    current->prog);
	say(ANSI_DARK_RED"Sb☮x: »"ANSI_DARK_GREEN"%c%c%c%c"SYD_WARN"«",
	    sandbox_mode_toc(box->mode.sandbox_read),
	    sandbox_mode_toc(box->mode.sandbox_write),
	    sandbox_mode_toc(box->mode.sandbox_exec),
	    sandbox_mode_toc(box->mode.sandbox_network));
	say(ANSI_DARK_RED"Ⓐrch: »"ANSI_DARK_GREEN"%s"SYD_WARN"«",
	    syd_name_arch(current->arch));
	say(ANSI_DARK_RED"HⒶsh: »"ANSI_DARK_GREEN"%s"SYD_WARN"«", current->hash);
	say(ANSI_DARK_RED"Pr☮c: "ANSI_DARK_YELLOW"pid »%d« tgid »%d« "
	    "ppid »%d« exec »%d«"SYD_WARN,
	    current->pid,
	    current->tgid,
	    current->ppid,
	    sydbox->execve_pid);
}

SYD_GCC_ATTR((nonnull(1,2,3)))
int syd_system_breach_attempt(syd_process_t *current,
			      const char *abspath,
			      const char *pattern)
{
	/*
	 * Read program command line.
	 */
	if (current->prog[0] && current->prog[0] != '?')
		goto skip_proc_cmdline;
	syd_proc_cmdline(sydbox->pfd, current->prog, LINE_MAX-1);
skip_proc_cmdline:
	/*
	 * The SHA-1 hash of the binary may not have been calculated
	 * before due to configuration and here we really do want it.
	 */
	if (current->hash[0] && current->hash[0] != '?')
		goto skip_hash_calc;
	int fdexe = openat(sydbox->pfd, "exe", O_RDONLY|O_CLOEXEC|O_LARGEFILE);
	if (fdexe >= 0) {
		FILE *fexe = fdopen(fdexe, "r");
		if (fexe) {
			syd_file_to_sha1_hex(fexe, current->hash);
			fclose(fexe);
		}
		close(fdexe);
	}
skip_hash_calc:
	switch (sydbox->breach_attempts) {
	case 0:
		/* Send a small greeting and just deny
		 * the system call for one turn.
		 * This is good since we are going to deny
		 * the system call with the error number
		 * EOWNERDEAD to indicate what's awaiting the user...
		 */
		say("hejhej :) what's up? are Y☮u alright?");
		oops(current, abspath, pattern);
		++sydbox->breach_attempts;
		break;
	case 1:
		oops(current, abspath, pattern);
		warn("\t");
		warn("Terminating Process with id »%d«...", current->pid);
		kill_one(current, SIGINT);
		++sydbox->breach_attempts;
		break;
	case 2:
		oops(current, abspath, pattern);
		warn("\t");
		warn("Alright, I am _no longer_ going to be polite,");
		warn("and terminate the SydB☮x Execute Process");
		warn("next time an Attempted Security Breach happens.");
		warn("\t");
		warn("Please use the system responsibly.");
		warn("\n");
		warn("Thanks in advance,");
		fprintf(stderr, "-sydb☮x:");
		++sydbox->breach_attempts;
		break;
	case 3:
		oops(current, abspath, pattern);
		warn("S☮rry! Y☮u asked for it!");
		warn("Interrupting the Thread Gr☮up Leader...");
		kill(current->pid == current->tgid
		     ? current->ppid
		     : current->tgid, SIGINT);
		warn("WⒶit f☮r it.");
		/*sleep(7);*/
		say("When the revolution comes");
		say("Some of us will probably catch it on TV,");
		say("with chicken hanging from our mouths");
		say("You'll know it's revolution because");
		say("there won't be no commercials");
		say("When the revolution comes");
		say("Ⓐ!");
		say("G☮☮dbye...");
		warn("Terminating the SydB☮x Execute Process with id »%d«",
		     sydbox->execve_pid);
		/*sleep(3);*/
		kill(current->pid == current->tgid
		     ? current->ppid
		     : current->tgid, SIGKILL);
		/*sleep(1);*/
		kill(sydbox->execve_pid, SIGKILL);
		break;
	default:
		break;
	}
	/*
	 * This is the default action in
	 * all breach attempt counts...
	 * We are paranoid enough to assume
	 * SIGKILL somehow wouldn't work and
	 * seccomp will prevail.
	 */
	return deny(current, EOWNERDEAD);
}

SYD_GCC_ATTR((nonnull(1,2)))
static int syd_system_check(syd_process_t *current, const char *abspath)
{
	const char *pattern = NULL;

	/*
	 * Denylist for System Paths
	 * The denylist is hardcoded at compile time via
	 * syd-conf.h. The plan is to make it user-configurable
	 * via /etc/syd/system.syd-2 at some point when this is
	 * stable.
	 */
	for (size_t i = 0; syd_system_denylist[i] != NULL; i++) {
		pattern = syd_system_denylist[i];
		if (iwildmatch(pattern, abspath))
			return syd_system_breach_attempt(current, abspath,
							 pattern);
	}

	return 0;
}

static inline void sysinfo_read_access(syd_process_t *current, syscall_info_t *info)
{
	info->access_mode = sandbox_deny_read(current)
			    ? ACCESS_ALLOWLIST
			    : ACCESS_DENYLIST;
	info->access_list = &P_BOX(current)->acl_read;
	info->access_filter = &sydbox->config.filter_read;
}

/* TODO: Do we need to care about O_PATH? */
static void init_open_info(syd_process_t *current,
			   const struct open_how *how,
			   struct open_info *info)
{
	assert(current);
	assert(info);

	info->rmode = (how->flags & O_CREAT) ? RPATH_NOLAST : RPATH_EXIST;
	info->syd_mode = 0;
	if (how->flags & O_EXCL) {
		if (info->rmode == RPATH_EXIST) {
			/* Quoting open(2):
			 * In general, the behavior of O_EXCL is undefined if
			 * it is used without O_CREAT.  There is one exception:
			 * on Linux 2.6 and later, O_EXCL can be used without
			 * O_CREAT if pathname refers to a block device. If
			 * the block device is in use by the system (e.g.,
			 * mounted), open() fails.
			 */
			/* void */;
		} else {
			/* Two things to mention here:
			 * - If O_EXCL is specified in conjunction with
			 *   O_CREAT, and pathname already exists, then open()
			 *   will fail.
			 * - When both O_CREAT and O_EXCL are specified,
			 *   symbolic links are not followed.
			 */
			info->rmode |= RPATH_NOFOLLOW;
			info->syd_mode |= SYD_STAT_NOEXIST;
		}
	}

	if (how->flags & O_DIRECTORY)
		info->syd_mode |= SYD_STAT_ISDIR;
	if (how->flags & O_NOFOLLOW)
		info->syd_mode |= SYD_STAT_NOFOLLOW;
	/*
	 * TODO: We treat these three flags as identical for simplicity, however
	 * this is not exactly compliant with the way the syscall functions.
	 */
	if ((how->resolve & RESOLVE_BENEATH) ||
	    (how->resolve & RESOLVE_NO_SYMLINKS) ||
	    (how->resolve & RESOLVE_NO_MAGICLINKS))
		info->rmode |= RPATH_NOFOLLOW;
	/* TODO: Do we want to support RESOLVE_NO_XDEV and RESOLVE_IN_ROOT? */

	/* »unsafe« flag combinations:
	 * - O_RDONLY | O_CREAT
	 * - O_WRONLY
	 * - O_RDWR
	 */
	switch (how->flags & O_ACCMODE) {
	case O_RDONLY:
		info->may_read = true;
		if (how->flags & O_CREAT) {
			/* file creation is »write« */
			info->may_write = true;
		} else {
			info->may_write = false;
		}
		break;
	case O_WRONLY:
		info->may_read = false;
		info->may_write = true;
		break;
	case O_RDWR:
		info->may_read = info->may_write = true;
		break;
	default:
		info->may_read = info->may_write = false;
	}
}

static int check_open(syd_process_t *current, syscall_info_t *info,
		      const struct open_info *open_info)
{
	int r = 0;
	char *abspath = NULL;
	bool rd, wr;
	struct stat statbuf;

	rd = !sandbox_off_read(current) && open_info->may_read;
	wr = !sandbox_off_write(current) && open_info->may_write;

	if (wr && rd) {
		info->ret_abspath = &abspath;
		info->ret_statbuf = &statbuf;
	}
	if (wr) {
		r = box_check_path(current, info);
		if (r || sysdeny(current))
			goto out;
	}
	if (rd) {
		if (info->ret_abspath) {
			info->cache_abspath = *info->ret_abspath;
			info->ret_abspath = NULL;
		}
		if (info->ret_statbuf) {
			info->cache_statbuf = info->ret_statbuf;
			info->ret_statbuf = NULL;
		}
		sysinfo_read_access(current, info);
		r = box_check_path(current, info);
	}

out:
	if (abspath)
		free(abspath);
	return r;
}

static inline int restrict_open_flags(syd_process_t *current, unsigned long flags)
{
#if 0
	if (sydbox->config.restrict_fcntl &&
	    (flags & (O_ASYNC|O_DIRECT|O_SYNC)))
		return deny(current, EPERM);
#endif
	return 0;
}

int sys_open(syd_process_t *current)
{
	int r;
	struct open_how how;
	syscall_info_t info;
	struct open_info open_info;

	init_sysinfo(&info);

	/* Check for System Access */
	char *path = NULL;
	char *abspath = NULL;
	bool done, null;

	if ((r = box_vm_read_path(current, &info, false, &path, &null, &done)) < 0 &&
	    done)
		return r;
	if (null)
		path = NULL;
	if ((r = box_resolve_path(path, P_CWD(current),
				  current->pid, info.rmode, &abspath)) < 0) {
		/* Continue here if resolve fails,
		 * let the main checker handle it as necessary.
		 */
		;
	} else if ((r = syd_system_check(current, abspath)) < 0) {
		if (path)
			free(path);
		if (abspath)
			free(abspath);
		return r;
	}
	if (path)
		free(path);

	if (sandbox_off_read(current) && sandbox_off_write(current)) {
		if (abspath)
			free(abspath);
		return 0;
	}

	/* check flags first */
	how.flags = current->args[1];
	if ((r = restrict_open_flags(current, how.flags)) < 0) {
		if (abspath)
			free(abspath);
		return r;
	}

	how.mode = 0;
	how.resolve = 0;
	init_open_info(current, &how, &open_info);
	info.rmode = open_info.rmode;
	info.syd_mode = open_info.syd_mode;
	info.cache_abspath = abspath;

	return check_open(current, &info, &open_info);
}

int sys_openat(syd_process_t *current)
{
	int r;
	struct open_how how;
	syscall_info_t info;
	struct open_info open_info;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;

	/* Check for System Access */
	char *prefix = NULL;
	char *path = NULL;
	char *abspath = NULL;
	bool badfd, done, null;

	/* Step 1: resolve file descriptor for »at« suffixed functions */
	if ((r = box_resolve_dirfd(current, &info, &prefix, &badfd)) < 0)
		return r;

	/* Step 2: VM read path */
	if ((r = box_vm_read_path(current, &info, badfd, &path, &null, &done)) < 0 &&
	    done)
		return r;
	if (null)
		path = NULL;

	/* Step 3: resolve path */
	if ((r = box_resolve_path(path, prefix ? prefix : P_CWD(current),
				  current->pid, info.rmode, &abspath)) < 0) {
		/* Continue here if resolve fails,
		 * let the main checker handle it as necessary.
		 */
		;
	} else if ((r = syd_system_check(current, abspath)) < 0) {
		if (path)
			free(path);
		if (prefix)
			free(prefix);
		if (abspath)
			free(abspath);
		return r;
	}
	if (path)
		free(path);
	if (prefix)
		free(prefix);

	if (sandbox_off_read(current) && sandbox_off_write(current))
		return 0;

	/* check flags first */
	how.flags = current->args[2];
	if ((r = restrict_open_flags(current, how.flags)) < 0)
		return r;

	if (sandbox_off_read(current) && sandbox_off_write(current))
		return 0;

	how.mode = 0;
	how.resolve = 0;
	init_open_info(current, &how, &open_info);
	info.rmode = open_info.rmode;
	info.syd_mode = open_info.syd_mode;
	info.cache_abspath = abspath;

	return check_open(current, &info, &open_info);
}

#if defined(HAVE_LINUX_OPENAT2_H) && defined(HAVE_STRUCT_OPEN_HOW)
int sys_openat2(syd_process_t *current)
{
	int r;
	syscall_info_t info;
	struct open_info open_info;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;

	/* Check for System Access */
	char *prefix = NULL;
	char *path = NULL;
	char *abspath = NULL;
	bool badfd, done, null;

	/* Step 1: resolve file descriptor for »at« suffixed functions */
	if ((r = box_resolve_dirfd(current, &info, &prefix, &badfd)) < 0)
		return r;

	/* Step 2: VM read path */
	if ((r = box_vm_read_path(current, &info, badfd, &path, &null, &done)) < 0 &&
	    done)
		return r;
	if (null)
		path = NULL;

	/* Step 3: resolve path */
	if ((r = box_resolve_path(path, prefix ? prefix : P_CWD(current),
				  current->pid, info.rmode, &abspath)) < 0) {
		/* Continue here if resolve fails,
		 * let the main checker handle it as necessary.
		 */
		;
	} else if ((r = syd_system_check(current, abspath)) < 0) {
		if (path)
			free(path);
		if (prefix)
			free(prefix);
		if (abspath)
			free(abspath);
		return r;
	}
	if (path)
		free(path);
	if (prefix)
		free(prefix);

	if (sandbox_off_read(current) && sandbox_off_write(current)) {
		if (abspath)
			free(abspath);
		return 0;
	}

	enum { OPEN_HOW_MIN_SIZE = 24 };
	struct open_how how;
	long addr, size;

	addr = current->args[2];
	size = current->args[3];

	if (size < OPEN_HOW_MIN_SIZE) {
		how.flags = 0;
		how.mode = 0;
		how.resolve = 0;
	} else if ((r = syd_read_vm_data(current, addr, (char *)&how, size)) < 0) {
		if (abspath)
			free(abspath);
		return r;
	} else if ((r = restrict_open_flags(current, how.flags)) < 0) {
		if (abspath)
			free(abspath);
		return r;
	}

	init_open_info(current, &how, &open_info);
	info.rmode = open_info.rmode;
	info.syd_mode = open_info.syd_mode;
	info.cache_abspath = abspath;

	return check_open(current, &info, &open_info);
}
#else
int sys_openat2(syd_process_t *current)
{
	/*
	 * This can happen if buildhost did not have support for openat2.
	 */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,6,0)
# warning "No support for openat2()"
# warning "SydB☮x will deny the system call unconditionally."
# warning "This won't be an issue unless you run SydB☮x on a system"
# warning "running a Linux kernel 5.6 or newer."
# warning "If this is the case, please update your kernel and kernel headers,"
# warning "and rebuild SydB☮x!"
#endif
	return deny(current, ENOTSUP);
}
#endif
