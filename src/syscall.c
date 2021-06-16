/*
 * sydbox/syscall.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include "pink.h"
#include "macro.h"
#include "proc.h"

#include <seccomp.h>

static int rule_add_action(uint32_t action, int sysnum);

static int rule_add_access_rd(uint32_t action, int sysnum, int access_mode);
static int rule_add_access_wr(uint32_t action, int sysnum, int access_mode);
static int rule_add_access_ex(uint32_t action, int sysnum, int access_mode);
#define rule_add_access_rd_eperm(sysnum, access_mode) \
	(rule_add_access_rd(SCMP_ACT_ERRNO(EPERM), (sysnum), (access_mode)))
#define rule_add_access_wr_eperm(sysnum, access_mode) \
	(rule_add_access_wr(SCMP_ACT_ERRNO(EPERM), (sysnum), (access_mode)))
#define rule_add_access_ex_eperm(sysnum, access_mode) \
	(rule_add_access_ex(SCMP_ACT_ERRNO(EPERM), (sysnum), (access_mode)))
#define rule_add_access_rd_notify(sysnum, access_mode) \
	(rule_add_access_rd(SCMP_ACT_NOTIFY, (sysnum), (access_mode)))
#define rule_add_access_wr_notify(sysnum, access_mode) \
	(rule_add_access_wr(SCMP_ACT_NOTIFY, (sysnum), (access_mode)))
#define rule_add_access_ex_notify(sysnum, access_mode) \
	(rule_add_access_wr(SCMP_ACT_NOTIFY, (sysnum), (access_mode)))

static int rule_add_open_rd(uint32_t action, int sysnum, int open_flag);
static int rule_add_open_wr(uint32_t action, int sysnum, int open_flag);
#define rule_add_open_rd_eperm(sysnum, open_flag) \
	(rule_add_open_rd(SCMP_ACT_ERRNO(EPERM), (sysnum), (open_flag)))
#define rule_add_open_wr_eperm(sysnum, open_flag) \
	(rule_add_open_wr(SCMP_ACT_ERRNO(EPERM), (sysnum), (open_flag)))
#define rule_add_open_rd_notify(sysnum, open_flag) \
	(rule_add_open_rd(SCMP_ACT_NOTIFY, (sysnum), (open_flag)))
#define rule_add_open_wr_notify(sysnum, open_flag) \
	(rule_add_open_wr(SCMP_ACT_NOTIFY, (sysnum), (open_flag)))

/*
 * 1. Order matters! Put more hot system calls above.
 * 2. ".filter" is for simple seccomp-only rules. If a system call entry has a
 *    ".filter" member, ".enter" and ".exit" members are *only* used as a
 *    ptrace() based fallback if sydbox->config.use_seccomp is false.
 */
static const sysentry_t syscall_entries[] = {
	{
		.name = "mmap2",
		.filter = filter_mmap2,
	},
	{
		.name = "mmap",
		.filter = filter_mmap,
	},
	{
		.name = "mprotect",
		.filter = filter_mprotect,
	},
	{
		.name = "ioctl",
		.filter = filter_ioctl,
	},

	{
		.name = "stat",
		.notify = sys_stat,
		.magic_lock_off = true,
	},
	{
		.name = "lstat",
		.user_notif = true,
		.notify = sys_stat,
		.magic_lock_off = true,
	},
	{
		.name = "statx",
		.notify = sys_statx,
		.magic_lock_off = true,
	},
	{
		.name = "stat64",
		.notify = sys_stat,
		.magic_lock_off = true,
	},
	{
		.name = "lstat64",
		.notify = sys_stat,
		.magic_lock_off = true,
	},
	{
		.name = "newfstatat",
		.notify = sys_fstatat,
		.magic_lock_off = true,
	},

	{
		.name = "access",
		.notify = sys_access,
		.sandbox_read = true,
		.sandbox_write = true,
		.sandbox_exec = true,
		.access_mode = 1,
	},
	{
		.name = "faccessat",
		.notify = sys_faccessat,
		.sandbox_read = true,
		.sandbox_write = true,
		.sandbox_exec = true,
		.access_mode = 2,
	},
	{
		.name = "faccessat2",
		.notify = sys_faccessat2,
		.sandbox_read = true,
		.sandbox_write = true,
		.sandbox_exec = true,
		.access_mode = 2,
	},

	{
		.name = "open",
		.notify = sys_open,
		.open_flag = 1,
		.sandbox_read = true,
		.sandbox_write = true,
	},
	{
		.name = "openat",
		.notify = sys_openat,
		.open_flag = 2,
		.sandbox_read = true,
		.sandbox_write = true,
	},
#ifdef __NR_openat2
	{
		.name = "openat2",
		.notify = sys_openat2,
		.sandbox_read = true,
		.sandbox_write = true,
	},
#endif

	{
		.name = "creat",
		.notify = sys_creat,
		.sandbox_write = true,
	},

	{
		.name = "chmod",
		.notify = sys_chmod,
		.sandbox_write = true,
	},
	{
		.name = "fchmodat",
		.notify = sys_fchmodat,
		.sandbox_write = true,
	},

	{
		.name = "chown",
		.notify = sys_chown,
		.sandbox_write = true,
	},
	{
		.name = "chown32",
		.notify = sys_chown,
		.sandbox_write = true,
	},
	{
		.name = "lchown",
		.notify = sys_lchown,
		.sandbox_write = true,
	},
	{
		.name = "lchown32",
		.notify = sys_lchown,
		.sandbox_write = true,
	},
	{
		.name = "fchownat",
		.notify = sys_fchownat,
		.sandbox_write = true,
	},

	{
		.name = "mkdir",
		.notify = sys_mkdir,
		.sandbox_write = true,
	},
	{
		.name = "mkdirat",
		.notify = sys_mkdirat,
		.sandbox_write = true,
	},

	{
		.name = "mknod",
		.notify = sys_mknod,
		.sandbox_write = true,
	},
	{
		.name = "mknodat",
		.notify = sys_mknodat,
		.sandbox_write = true,
	},

	{
		.name = "rmdir",
		.notify = sys_rmdir,
		.sandbox_write = true,
	},

	{
		.name = "truncate",
		.notify = sys_truncate,
		.sandbox_write = true,
	},
	{
		.name = "truncate64",
		.notify = sys_truncate,
		.sandbox_write = true,
	},

	{
		.name = "utime",
		.notify = sys_utime,
		.sandbox_write = true,
	},
	{
		.name = "utimes",
		.notify = sys_utimes,
		.sandbox_write = true,
	},
	{
		.name = "utimensat",
		.notify = sys_utimensat,
		.sandbox_write = true,
	},
	{
		.name = "futimesat",
		.notify = sys_futimesat,
		.sandbox_write = true,
	},

	{
		.name = "unlink",
		.notify = sys_unlink,
		.sandbox_write = true,
	},
	{
		.name = "unlinkat",
		.notify = sys_unlinkat,
		.sandbox_write = true,
	},

	{
		.name = "link",
		.notify = sys_link,
		.sandbox_write = true,
	},
	{
		.name = "linkat",
		.notify = sys_linkat,
		.sandbox_write = true,
	},

	{
		.name = "rename",
		.notify = sys_rename,
		.sandbox_write = true,
	},
	{
		.name = "renameat",
		.notify = sys_renameat,
		.sandbox_write = true,
	},
	{
		.name = "renameat2",
		.notify = sys_renameat,
		.sandbox_write = true,
	},

	{
		.name = "symlink",
		.notify = sys_symlink,
		.sandbox_write = true,
	},
	{
		.name = "symlinkat",
		.notify = sys_symlinkat,
		.sandbox_write = true,
	},

	{
		.name = "execve",
		.notify = sys_execve,
		.sandbox_exec = true,
	},
	{
		.name = "execveat",
		.notify = sys_execveat,
		.sandbox_exec = true,
	},

	{
		.name = "socketcall",
		.notify = sys_socketcall,
		.sandbox_network = true,
	},
	{
		.name = "bind",
		.notify = sys_bind,
		.sandbox_network = true,
	},
	{
		.name = "connect",
		.notify = sys_connect,
		.sandbox_network = true,
	},
	{
		.name = "sendto",
		.notify = sys_sendto,
		.sandbox_network = true,
	},
	{
		.name = "listen",
		.notify = sys_listen,
		.sandbox_network = true,
	},
	{
		.name = "accept",
		.notify = sys_accept,
		.sandbox_network = true,
	},
	{
		.name = "accept4",
		.notify = sys_accept,
		.sandbox_network = true,
	},
	{
		.name = "getsockname",
		.notify = sys_getsockname,
		.sandbox_network = true,
	},
	{
		.name = "sendmsg",
		.notify = sys_sendmsg,
		.sandbox_network = true,
	},
	{
		.name = "recvmsg",
		.notify = sys_recvmsg,
		.sandbox_network = true,
	},

	{
		.name = "listxattr",
		.notify = sys_listxattr,
		.sandbox_read = true,
	},
	{
		.name = "llistxattr",
		.notify = sys_llistxattr,
		.sandbox_read = true,
	},
	{
		.name = "setxattr",
		.notify = sys_setxattr,
		.sandbox_write = true,
	},
	{
		.name = "lsetxattr",
		.notify = sys_lsetxattr,
		.sandbox_write = true,
	},
	{
		.name = "removexattr",
		.notify = sys_removexattr,
		.sandbox_write = true,
	},
	{
		.name = "lremovexattr",
		.notify = sys_lremovexattr,
		.sandbox_write = true,
	},

	{
		.name = "mount",
		.notify = sys_mount,
		.sandbox_write = true,
	},
	{
		.name = "umount",
		.notify = sys_umount,
		.sandbox_write = true,
	},
	{
		.name = "umount2",
		.notify = sys_umount2,
		.sandbox_write = true,
	},
};

size_t syscall_entries_max(void)
{
	return ELEMENTSOF(syscall_entries);
}

void sysinit(void)
{
	for (size_t i = 0; i < ELEMENTSOF(syscall_entries); i++) {
		if (syscall_entries[i].filter)
			continue;

		if (syscall_entries[i].name) {
			systable_add(syscall_entries[i].name,
				     syscall_entries[i].notify,
				     syscall_entries[i].exit);
		} else {
			for (size_t j = 0; j < ABIS_SUPPORTED; j++)
				systable_add_full(syscall_entries[i].no,
						  abi[j], NULL,
						  syscall_entries[i].notify,
						  syscall_entries[i].exit);
		}
	}
}

static int apply_simple_filter(const sysentry_t *entry)
{
	int r;

	assert(entry->filter);

	if ((r = entry->filter()) < 0)
		return r;
	return 0;
}

int parent_read_int(int *message) {
	if (!message)
		return -EINVAL;
	errno = 0;
	ssize_t count = atomic_read(sydbox->seccomp_fd, message, sizeof(int));
	if (!count && count != sizeof(int)) { /* count=0 is EOF */
		if (!errno)
			errno = EINVAL;
		return -errno;
	}
	return *message;
}

int parent_write_int(int message)
{
	ssize_t count;

	errno = 0;
	count = atomic_write(sydbox->seccomp_fd, &message, sizeof(int));
	if (count != sizeof(int)) {
		if (!errno)
			errno = EINVAL;
		die_errno("can't write int to pipe: %zu != %zu", count,
			  sizeof(int));
	}
	return 0;
}

int sysinit_seccomp_load(void)
{
	int r;
	uint32_t action;
	long sysnum;
	bool user_notified = false;

	if ((r = filter_general()) < 0)
		return r;
	for (size_t i = 0; i < ELEMENTSOF(syscall_entries); i++) {
		if (!syscall_entries[i].filter)
			continue;
		if ((r = apply_simple_filter(&syscall_entries[i])) < 0)
			return r;
	}

	sandbox_t *box = box_current(NULL);
	for (size_t i = 0; i < ELEMENTSOF(syscall_entries); i++) {
		if (syscall_entries[i].name)
			sysnum = seccomp_syscall_resolve_name(syscall_entries[i].name);
		else
			sysnum = syscall_entries[i].no;
		if (sysnum == __NR_SCMP_ERROR)
			die_errno("can't lookup system call name:%s",
				  syscall_entries[i].name);
		if (sysnum < 0) {
			/* say("unknown system call name:%s, continuing...",
			    syscall_entries[i].name); */
			continue;
		}

		int flag;
		bool is_open = false, is_access = false;
		if (syscall_entries[i].access_mode) {
			is_access = true;
			flag = syscall_entries[i].access_mode;
		} else if (syscall_entries[i].open_flag) {
			is_open = true;
			flag = syscall_entries[i].open_flag;
		}
		if (is_access) {
			enum sandbox_mode mode_r = box->mode.sandbox_read;
			enum sandbox_mode mode_w = box->mode.sandbox_write;
			enum sandbox_mode mode_x = box->mode.sandbox_exec;

			if (mode_r == SANDBOX_BPF &&
			    (r = rule_add_access_rd_eperm(sysnum,
							  flag)) < 0)
					return r;
			if (use_notify() &&
			    (mode_r == SANDBOX_ALLOW || mode_r == SANDBOX_DENY)) {
				r = rule_add_access_rd_notify(sysnum,
							      flag);
				if (r < 0)
					return r;
				user_notified = true;
			} else if (mode_r == SANDBOX_DENY &&
			    (r = rule_add_access_rd_eperm(sysnum,
							  flag)) < 0) {
					return r;
			}

			if (mode_w == SANDBOX_BPF &&
			    (r = rule_add_access_wr_eperm(sysnum,
							  flag)) < 0)
					return r;
			if (use_notify() &&
			    (mode_w == SANDBOX_ALLOW || mode_w == SANDBOX_DENY)) {
				r = rule_add_access_wr_notify(sysnum,
							      flag);
				if (r < 0)
					return r;
				user_notified = true;
			} else if (mode_w == SANDBOX_DENY &&
			    (r = rule_add_access_wr_eperm(sysnum,
							  flag)) < 0) {
					return r;
			}

			if (mode_x == SANDBOX_BPF &&
			    (r = rule_add_access_ex_eperm(sysnum,
							  flag)) < 0)
					return r;
			if (use_notify() &&
			    (mode_x == SANDBOX_ALLOW || mode_x == SANDBOX_DENY)) {
				r = rule_add_access_ex_notify(sysnum,
							      flag);
				if (r < 0)
					return r;
				user_notified = true;
			} else if (mode_x == SANDBOX_DENY &&
			    (r = rule_add_access_ex_eperm(sysnum,
							  flag)) < 0) {
					return r;
			}
		} else if (is_open) {
			enum sandbox_mode mode_r = box->mode.sandbox_read;
			enum sandbox_mode mode_w = box->mode.sandbox_write;

			if (mode_r == SANDBOX_BPF &&
			    (r = rule_add_open_rd_eperm(sysnum,
							flag)) < 0)
					return r;
			if (use_notify() &&
			    (mode_r == SANDBOX_ALLOW || mode_r == SANDBOX_DENY)) {
				r = rule_add_open_rd_notify(sysnum,
							    flag);
				if (r < 0)
					return r;
				user_notified = true;
			} else if (mode_r == SANDBOX_DENY &&
			    (r = rule_add_open_rd_eperm(sysnum,
							flag)) < 0) {
					return r;
			}

			if (mode_w == SANDBOX_BPF &&
			    (r = rule_add_open_wr_eperm(sysnum,
							flag)) < 0)
					return r;
			if (use_notify() &&
			    (mode_w == SANDBOX_ALLOW || mode_w == SANDBOX_DENY)) {
				r = rule_add_open_wr_notify(sysnum,
							    flag);
				if (r < 0)
					return r;
				user_notified = true;
			} else if (mode_w == SANDBOX_DENY &&
				   (r = rule_add_open_wr_eperm(sysnum,
							       flag)) < 0) {
				return r;
			}
		} else {
			int mode;
			enum lock_state lock = LOCK_UNSET;
			if (syscall_entries[i].sandbox_network) {
				mode = box->mode.sandbox_network;
			} else if (syscall_entries[i].sandbox_exec) {
				mode = box->mode.sandbox_exec;
			} else if (syscall_entries[i].sandbox_write) {
				mode = box->mode.sandbox_write;
			} else if (syscall_entries[i].sandbox_read) {
				mode = box->mode.sandbox_read;
			} else if (syscall_entries[i].magic_lock_off) {
				lock = sydbox->config.box_static.magic_lock;
				mode = -1;
			} else {
				continue;
			}

			if (syscall_entries[i].magic_lock_off && use_notify()) {
				if (lock == LOCK_SET)
					continue;
				action = SCMP_ACT_NOTIFY;
				user_notified = true;
			} else if (syscall_entries[i].magic_lock_off) {
				if (lock == LOCK_SET)
					continue;
				action = SCMP_ACT_ALLOW;
				if (action == sydbox->seccomp_action)
					continue;
			} else if (mode == SANDBOX_OFF) {
				if (!filter_includes(sysnum))
					continue;
				action = SCMP_ACT_ALLOW;
				if (action == sydbox->seccomp_action)
					continue;
			} else if (mode == SANDBOX_BPF) {
				action = SCMP_ACT_ERRNO(EPERM);
				if (action == sydbox->seccomp_action)
					continue;
			} else if ((mode == SANDBOX_ALLOW ||
				    mode == SANDBOX_DENY) && use_notify()) {
				action = SCMP_ACT_NOTIFY;
				user_notified = true;
			} else if (mode == SANDBOX_DENY) {
				action = SCMP_ACT_ERRNO(EPERM);
				if (action == sydbox->seccomp_action)
					continue;
			} else if (mode == SANDBOX_ALLOW) {
				if (!filter_includes(sysnum))
					continue;
				action = SCMP_ACT_ALLOW;
				if (action == sydbox->seccomp_action)
					continue;
			} else { /* if (mode == -1) */
				sysentry_t entry = syscall_entries[i];
				say("seccomp system call inconsistency "
				    "detected.");
				say("name:%s mode=%d bpf_only=%s "
				    "lock:%s use_notify=%s",
				    entry.name,
				    mode,
				    sydbox->bpf_only ? "t" : "f",
				    entry.magic_lock_off ? "t" : "f",
				    use_notify() ? "t" : "f");
				assert_not_reached();
			}

			if ((r = rule_add_action(action, sysnum)) < 0)
				return r;
		}
	}

	static const char *const calls[] = {
		"execve", "execveat",
		"clone", "fork", "vfork", "clone3",
		"chdir", "fchdir",
	};
	if (user_notified) {
		for (unsigned short i = 0; i < 8; i++) {
			if (i < 2 && box->mode.sandbox_exec != SANDBOX_OFF)
				continue; /* execve* already added */
			sysnum = seccomp_syscall_resolve_name(calls[i]);
			if (sysnum == __NR_SCMP_ERROR)
				die_errno("can't lookup system call name:%s",
					  calls[i]);
			else if (sysnum < 0) {
				/* say("unknown system call name:%s, continuing...",
				    calls[i]); */
				continue;
			}
			if ((r = rule_add_action(SCMP_ACT_NOTIFY, sysnum)) < 0) {
				errno = -r;
				say_errno("can't add notify for %s, continuing...",
					  calls[i]);
				continue;
			}
		}
	}

	// say("seccomp filter count: %d, no open filter count: %d", n, n - 4);
	// free(f);
	return 0;
}

int sysinit_seccomp(void)
{
	int r;

	if ((r = sysinit_seccomp_load()) < 0) {
		errno = -r;
		say_errno("sysinit_seccomp_load");
		return r;
	}
	switch (sydbox->export) {
	case SYDBOX_EXPORT_BPF:
		if (seccomp_export_bpf(sydbox->ctx, 2) < 0)
			say_errno("seccomp_export_bpf");
		break;
	case SYDBOX_EXPORT_PFC:
		if (seccomp_export_pfc(sydbox->ctx, 2) < 0)
			say_errno("seccomp_export_pfc");
		break;
	default:
		break;
	}
	if ((r = seccomp_load(sydbox->ctx)) < 0)
		return -r;
	if (use_notify()) {
		int fd;
		if ((fd = seccomp_notify_fd(sydbox->ctx)) < 0)
			return -errno;
		if (parent_write_int(fd))
			return -errno;
	}

	seccomp_release(sydbox->ctx);
	sydbox->ctx = NULL;

	/* Keep the seccomp_fd open to write the exit code.
	   close(sydbox->seccomp_fd);
	*/
	return 0;
}

int sysnotify(syd_process_t *current)
{
	int r;
	const sysentry_t *entry;

	assert(current);

	entry = NULL;
	for (unsigned i = 0; i < ELEMENTSOF(syscall_entries); i++) {
		if (!strcmp(current->sysname, syscall_entries[i].name)) {
			entry = &syscall_entries[i];
			break;
		}
	}
	if (!entry)
		return 0;
	r = 0;
	current->retval = 0;
	if (entry->notify)
		r = entry->notify(current);

	return r;
}

int sysexit(syd_process_t *current)
{
	int r;
	const sysentry_t *entry;

	assert(current);

#if !WRITE_RETVAL_ON_ENTRY
	if ((r = restore(current)) < 0)
		say("error writing syscall return value: %d (%s)",
		    -r, strerror(-r));
#endif

	entry = systable_lookup(current->sysnum, current->arch);
	r = (entry && entry->exit) ? entry->exit(current) : 0;

	reset_process(current);
	return r;
}

static int
rule_add_action(uint32_t action, int sysnum)
{
	return seccomp_rule_add(sydbox->ctx, action, sysnum, 0);
}

static int rule_add_access(uint32_t action, int sysnum,
			   int access_mode, int access_flag)
{
	int r;

	if (action == sydbox->seccomp_action)
		return 0;

	/*
	 * TODO: For simplicity we ignore bitwise OR'ed modes here,
	 * e.g: R_OK|W_OK
	 */
	if ((r = seccomp_rule_add(sydbox->ctx, action,
				  sysnum, 1,
				  SCMP_CMP( access_mode,
					    SCMP_CMP_EQ,
					    access_flag, access_flag ))) < 0)
		return r;

	return 0;
}

static int rule_add_access_rd(uint32_t action, int sysnum, int access_mode)
{
	int r;

	if ((r = rule_add_access(action, sysnum, access_mode, F_OK)) < 0 ||
	    (r = rule_add_access(action, sysnum, access_mode, R_OK)) < 0)
		return r;

	return 0;
}

static int rule_add_access_wr(uint32_t action, int sysnum, int access_mode)
{
	int r;

	if ((r = rule_add_access(action, sysnum, access_mode, W_OK)) < 0)
		return r;

	return 0;
}

static int rule_add_access_ex(uint32_t action, int sysnum, int access_mode)
{
	int r;

	if ((r = rule_add_access(action, sysnum, access_mode, X_OK)) < 0)
		return r;

	return 0;
}

static int
rule_add_open_rd(uint32_t action, int sysnum, int open_flag)
{
	if (action == sydbox->seccomp_action)
		return 0;

	/* FIXME: duplication with syscall-filter.c:filter_open_readonly() */
	for (unsigned i = 0; i < ELEMENTSOF(open_readonly_flags); i++) {
		int r;
		r = seccomp_rule_add(sydbox->ctx, action,
				     sysnum, 1,
				     SCMP_CMP( open_flag,
					       SCMP_CMP_EQ,
					       open_readonly_flags[i],
					       open_readonly_flags[i] ));
		if (r < 0)
			return r;
	}

	return 0;
}

static int
rule_add_open_wr(uint32_t action, int sysnum, int open_flag)
{
	if (action == sydbox->seccomp_action)
		return 0;

	const int flag[] = {
		O_WRONLY,
		O_RDWR,
		O_CREAT,
	};

	for (unsigned int i = 0; i < ELEMENTSOF(flag); i++) {
		int r;
		r = seccomp_rule_add(sydbox->ctx, action, sysnum,
				     1,
				     SCMP_CMP( open_flag, SCMP_CMP_MASKED_EQ,
					       flag[i], flag[i]));
		if (r < 0)
			return r;
	}

	return 0;
}
