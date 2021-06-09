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
#include <stdlib.h>
#include <string.h>
#include "pink.h"
#include "macro.h"
#include "proc.h"

#include <seccomp.h>

static int rule_add_action(uint32_t action, int sysnum);
static int rule_add_open_rd(int sysnum, int open_flag);
static int rule_add_open_wr(int sysnum, int open_flag);
static int rule_add_open_rd_eperm(int sysnum);
static int rule_add_openat_rd_eperm(int sysnum);
static int rule_add_open_wr_eperm(int sysnum);
static int rule_add_openat_wr_eperm(int sysnum);

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
		.sandbox_pseudo = true,
	},
	{
		.name = "lstat",
		.user_notif = true,
		.notify = sys_stat,
		.sandbox_pseudo = true,
	},
	{
		.name = "statx",
		.notify = sys_statx,
		.sandbox_pseudo = true,
	},
	{
		.name = "stat64",
		.notify = sys_stat,
		.sandbox_pseudo = true,
	},
	{
		.name = "lstat64",
		.notify = sys_stat,
		.sandbox_pseudo = true,
	},
	{
		.name = "newfstatat",
		.notify = sys_fstatat,
		.sandbox_pseudo = true,
	},

	{
		.name = "access",
		.notify = sys_access,
		.sandbox_read = true,
	},
	{
		.name = "faccessat",
		.notify = sys_faccessat,
		.sandbox_read = true,
	},
	{
		.name = "faccessat2",
		.notify = sys_faccessat,
		.sandbox_read = true,
	},

	{
		.name = "open",
		.filter = filter_open,
		.notify = sys_open,
		.open_flag = 1,
		.sandbox_read = true,
		.sandbox_write = true,
	},
	{
		.name = "openat",
		.filter = filter_openat,
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
		.name = "fcntl",
		.filter = filter_fcntl,
		.notify = sys_fcntl,
		.sandbox_read = true,
	},
	{
		.name = "fcntl64",
		.filter = filter_fcntl,
		.notify = sys_fcntl,
		.sandbox_read = true,
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
	for (unsigned i = 0; i < ELEMENTSOF(syscall_entries); i++) {
		if (syscall_entries[i].filter)
			continue;

		if (syscall_entries[i].name) {
			systable_add(syscall_entries[i].name,
				     syscall_entries[i].notify,
				     syscall_entries[i].exit);
		} else {
			for (int abi = 0; abi < PINK_ABIS_SUPPORTED; abi++)
				systable_add_full(syscall_entries[i].no,
						  abi, NULL,
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
		die_errno("failed to read int from pipe: %zu != %zu",
			  count, sizeof(int));
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

		sandbox_t *box = box_current(NULL);
		int open_flag = syscall_entries[i].open_flag;
		if (open_flag) {
			enum sandbox_mode mode_r = box->mode.sandbox_read;
			enum sandbox_mode mode_w = box->mode.sandbox_write;

			//struct sock_filter *item = NULL;
			if (mode_r == SANDBOX_BPF &&
			    mode_w == SANDBOX_BPF) {
				if ((r = rule_add_open_rd(sysnum,
							  open_flag)) < 0) {
					errno = -r;
					die_errno("rule_add_open_rd_eperm");
				}
				if ((r = rule_add_open_wr(sysnum,
							  open_flag)) < 0) {
					errno = -r;
					die_errno("rule_add_open_wr_eperm");
				}
			} else if (mode_r == SANDBOX_BPF &&
				   mode_w == SANDBOX_OFF) {
				if ((r = rule_add_open_rd(sysnum,
							  open_flag)) < 0) {
					errno = -r;
					die_errno("rule_add_open_rd_eperm");
				}
			} else if (mode_r == SANDBOX_OFF &&
				   mode_w == SANDBOX_BPF) {
				if ((r = rule_add_open_wr(sysnum,
							  open_flag)) < 0) {
					errno = -r;
					die_errno("rule_add_open_wr_eperm");
				}
			} else if (mode_r == SANDBOX_OFF &&
				   mode_w == SANDBOX_OFF) {
#if 0
				if (use_notify())
					action = SCMP_ACT_NOTIFY;
				else /* no need to do anything */
					continue;
				r = seccomp_rule_add(sydbox->ctx, action, sysnum, 0);
				if (r < 0)
					return r;
#endif
				;
			} else if ((mode_r == SANDBOX_OFF &&
				    mode_w == SANDBOX_ALLOW) ||
				   (mode_r == SANDBOX_ALLOW &&
				    mode_w == SANDBOX_OFF)) {
				if (use_notify()) {
					r = rule_add_action(SCMP_ACT_NOTIFY,
							    sysnum);
					if (r < 0)
						return r;
					user_notified = true;
				} /* else no need to do anything. */
			} else if (mode_r == SANDBOX_OFF &&
				   mode_w == SANDBOX_DENY) {
				if (use_notify()) {
					r = rule_add_action(SCMP_ACT_NOTIFY,
							    sysnum);
					user_notified = true;
				} else {
					r = rule_add_open_wr(sysnum, open_flag);
				}
				if (r < 0)
					return 0;
			} else if (mode_r == SANDBOX_OFF &&
				   mode_w == SANDBOX_ALLOW) {
				if (use_notify()) {
					r = rule_add_action(SCMP_ACT_NOTIFY,
							    sysnum);
					if (r < 0)
						return 0;
					user_notified = true;
				} /* else { ; } no need to do anything here. */
			} else if (mode_r == SANDBOX_ALLOW &&
				   mode_w == SANDBOX_ALLOW) {
				if (use_notify()) {
					r = rule_add_action(SCMP_ACT_NOTIFY,
							    sysnum);
					if (r < 0)
						return r;
					user_notified = true;
				} /* else { ; } no need to do anything here. */
			} else if (mode_r == SANDBOX_DENY &&
				   mode_w == SANDBOX_OFF) {
				if (use_notify()) {
					r = rule_add_action(SCMP_ACT_NOTIFY,
							    sysnum);
					user_notified = true;
				} else {
					r = rule_add_open_rd(sysnum, open_flag);
				}
				if (r < 0)
					return r;
			} else if (mode_r == SANDBOX_DENY &&
				   (mode_w == SANDBOX_BPF ||
				    mode_w == SANDBOX_DENY)) {
				if (use_notify()) {
					r = rule_add_action(SCMP_ACT_NOTIFY,
							    sysnum);
					user_notified = true;
				} else if (sydbox->seccomp_action != SCMP_ACT_ERRNO(EPERM)) {
					r = seccomp_rule_add(sydbox->ctx,
							     SCMP_ACT_ERRNO(EPERM),
							     sysnum, 0);
				} else {
					continue;
				}
				if (r < 0)
					return r;
			}
		} else {
			int mode;
			if (syscall_entries[i].sandbox_network) {
				mode = box->mode.sandbox_network;
			} else if (syscall_entries[i].sandbox_exec) {
				mode = box->mode.sandbox_exec;
			} else if (syscall_entries[i].sandbox_write) {
				mode = box->mode.sandbox_write;
			} else if (syscall_entries[i].sandbox_read) {
				mode = box->mode.sandbox_read;
			} else if (syscall_entries[i].sandbox_pseudo) {
				mode = -1;
			} else {
				continue;
			}

			if (syscall_entries[i].sandbox_pseudo && use_notify()) {
				action = SCMP_ACT_NOTIFY;
				user_notified = true;
			} else if (syscall_entries[i].sandbox_pseudo) {
				action = SCMP_ACT_ALLOW;
				if (action == sydbox->seccomp_action)
					continue;
			} else if (mode == SANDBOX_OFF) {
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
				action = SCMP_ACT_ALLOW;
				if (action == sydbox->seccomp_action)
					continue;
			} else { /* if (mode == -1) */
				sysentry_t entry = syscall_entries[i];
				say("seccomp system call inconsistency "
				    "detected.");
				say("name:%s mode=%d bpf_only=%s "
				    "pseudo:%s use_notify=%s",
				    entry.name,
				    mode,
				    sydbox->bpf_only ? "t" : "f",
				    entry.sandbox_pseudo ? "t" : "f",
				    use_notify() ? "t" : "f");
				assert_not_reached();
			}

			if ((r = rule_add_action(action, sysnum)) < 0)
				return r;
		}
	}

	if (user_notified) {
		sandbox_t *box = box_current(NULL);
		const char *calls[] = {
			"execve", "execveat",
			"clone", "fork", "vfork", "clone3",
			"chdir", "fchdir",
		};
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

	if ((r = sysinit_seccomp_load() < 0)) {
		errno = -r;
		say_errno("sysinit_seccomp_load");
		return r;
	}
	if (getenv("EXPORT") && (r = seccomp_export_pfc(sydbox->ctx, 2)) < 0)
		say("seccomp_export_pfc: %d %s", -r, strerror(-r));
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
	if (entry->exit)
		current->flags |= SYD_STOP_AT_SYSEXIT;

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

static int
rule_add_open_rd(int sysnum, int open_flag)
{
	switch (open_flag) {
	case 1:
		return rule_add_open_rd_eperm(sysnum);
	case 2:
		return rule_add_openat_rd_eperm(sysnum);
	default:
		return -EINVAL;
	}

	return 0;
}

static int
rule_add_open_wr(int sysnum, int open_flag)
{
	switch (open_flag) {
	case 1:
		return rule_add_open_wr_eperm(sysnum);
	case 2:
		return rule_add_openat_wr_eperm(sysnum);
	default:
		return -EINVAL;
	}
}

static int
rule_add_open_rd_eperm(int sysnum)
{
	int r;
	uint32_t action = SCMP_ACT_ERRNO(EPERM);

	if (action == sydbox->seccomp_action)
		return 0;

	/* O_RDONLY */
	r = seccomp_rule_add(sydbox->ctx, action, sysnum,
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ, O_RDONLY, O_RDONLY ));
	if (r < 0)
		return r;

	/* O_RDWR */
	r = seccomp_rule_add(sydbox->ctx, action, sysnum,
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR ));
	if (r < 0)
		return r;

	return 0;
}

static int
rule_add_open_wr_eperm(int sysnum)
{
	int r;
	uint32_t action = SCMP_ACT_ERRNO(EPERM);

	if (action == sydbox->seccomp_action)
		return 0;

	/* O_WRONLY */
	r = seccomp_rule_add(sydbox->ctx, action, sysnum,
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY ));
	if (r < 0)
		return r;

	/* O_RDWR */
	r = seccomp_rule_add(sydbox->ctx, action, sysnum,
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR ));
	if (r < 0)
		return r;

	/* O_CREAT */
	r = seccomp_rule_add(sydbox->ctx, action, sysnum,
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ, O_CREAT, O_CREAT ));
	if (r < 0)
		return r;

	return 0;
}

static int
rule_add_openat_rd_eperm(int sysnum)
{
	int r;
	uint32_t action = SCMP_ACT_ERRNO(EPERM);

	if (action == sydbox->seccomp_action)
		return 0;

	/* O_RDONLY */
	r = seccomp_rule_add(sydbox->ctx, action, sysnum,
			     1,
			     SCMP_A2( SCMP_CMP_MASKED_EQ, O_RDONLY, O_RDONLY ));
	if (r < 0)
		return r;

	/* O_RDWR */
	r = seccomp_rule_add(sydbox->ctx, action, sysnum,
			     1,
			     SCMP_A2( SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR ));
	if (r < 0)
		return r;

	return 0;
}

static int
rule_add_openat_wr_eperm(int sysnum)
{
	int r;
	uint32_t action = SCMP_ACT_ERRNO(EPERM);

	if (action == sydbox->seccomp_action)
		return 0;

	/* O_WRONLY */
	r = seccomp_rule_add(sydbox->ctx, action, sysnum,
			     1,
			     SCMP_A2( SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY ));
	if (r < 0)
		return r;

	/* O_RDWR */
	r = seccomp_rule_add(sydbox->ctx, action, sysnum,
			     1,
			     SCMP_A2( SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR ));
	if (r < 0)
		return r;

	/* O_CREAT */
	r = seccomp_rule_add(sydbox->ctx, action, sysnum,
			     1,
			     SCMP_A2( SCMP_CMP_MASKED_EQ, O_CREAT, O_CREAT ));
	if (r < 0)
		return r;

	return 0;
}
