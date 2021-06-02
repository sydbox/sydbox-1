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
#if SYDBOX_HAVE_SECCOMP
#include "seccomp.h"

static struct sock_filter footer_eperm[] = {
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(EPERM & SECCOMP_RET_DATA))
};
static struct sock_filter footer_allow[] = {
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
};
#endif

/*
 * 1. Order matters! Put more hot system calls above.
 * 2. ".filter" is for simple seccomp-only rules. If a system call entry has a
 *    ".filter" member, ".enter" and ".exit" members are *only* used as a
 *    ptrace() based fallback if sydbox->config.use_seccomp is false.
 */
static const sysentry_t syscall_entries[] = {
	{
		.name = "mmap2",
		.filter = filter_mmap,
		.enter = sys_fallback_mmap,
		.ptrace_fallback = true,
	},
	{
		.name = "mmap",
		.filter = filter_mmap,
		.enter = sys_fallback_mmap,
		.ptrace_fallback = true,
	},
	{
		.name = "old_mmap",
		.filter = filter_mmap,
		.enter = sys_fallback_mmap,
	},

	{
		.name = "stat",
		.enter = sys_stat,
#if PINK_ARCH_AARCH64 || PINK_ARCH_ARM
		.exit = sysx_stat,
#endif
	},
	{
		.name = "lstat",
		.enter = sys_stat,
#if PINK_ARCH_AARCH64 || PINK_ARCH_ARM
		.exit = sysx_stat,
#endif
	},
	{
		.name = "statx",
		.enter = sys_statx,
#if PINK_ARCH_AARCH64 || PINK_ARCH_ARM
		.exit = sysx_statx,
#endif
	},
	{
		.name = "stat64",
		.enter = sys_stat,
#if PINK_ARCH_AARCH64 || PINK_ARCH_ARM
		.exit = sysx_stat,
#endif
	},
	{
		.name = "lstat64",
		.enter = sys_stat,
#if PINK_ARCH_AARCH64 || PINK_ARCH_ARM
		.exit = sysx_stat,
#endif
	},
	{
		.name = "newfstatat",
		.enter = sys_fstatat,
#if PINK_ARCH_AARCH64 || PINK_ARCH_ARM
		.exit = sysx_fstatat,
#endif
	},
	/*
	 * TODO: This requires updates in the ABI & struct stat logic in
	 * sys_stat_common function. This system call is i386 only and is very
	 * rarely used so we leave it out for the time being.
	{
		.name = "fstatat64",
		.enter = sys_fstatat,
	}
	*/

	{
		.name = "access",
		.enter = sys_access,
		.sandbox_read = true,
	},
	{
		.name = "faccessat",
		.enter = sys_faccessat,
		.sandbox_read = true,
	},

	{
		.name = "open",
		.filter = filter_open,
		.enter = sys_open,
		.open_flag = 1,
		.sandbox_read = true,
		.sandbox_write = true,
	},
	{
		.name = "openat",
		.filter = filter_openat,
		.enter = sys_openat,
		.open_flag = 2,
		.sandbox_read = true,
		.sandbox_write = true,
	},
	{
		.name = "openat2",
		.enter = sys_openat2,
		.sandbox_read = true,
		.sandbox_write = true,
	},

	{
		.name = "creat",
		.enter = sys_creat,
		.sandbox_write = true,
	},

	{
		.name = "fcntl",
		.filter = filter_fcntl,
		.enter = sys_fcntl,
		.exit = sysx_fcntl,
		.sandbox_read = true,
	},
	{
		.name = "fcntl64",
		.filter = filter_fcntl,
		.enter = sys_fcntl,
		.exit = sysx_fcntl,
		.sandbox_read = true,
	},
	{
		.name = "dup",
		.enter = sys_dup,
		.exit = sysx_dup,
	},
	{
		.name = "dup2",
		.enter = sys_dup,
		.exit = sysx_dup,
	},
	{
		.name = "dup3",
		.enter = sys_dup,
		.exit = sysx_dup,
	},

	{
		.name = "chdir",
		.exit = sysx_chdir,
	},
	{
		.name = "fchdir",
		.exit = sysx_chdir,
	},

	{
		.name = "chmod",
		.enter = sys_chmod,
		.sandbox_write = true,
	},
	{
		.name = "fchmodat",
		.enter = sys_fchmodat,
		.sandbox_write = true,
	},

	{
		.name = "chown",
		.enter = sys_chown,
		.sandbox_write = true,
	},
	{
		.name = "chown32",
		.enter = sys_chown,
		.sandbox_write = true,
	},
	{
		.name = "lchown",
		.enter = sys_lchown,
		.sandbox_write = true,
	},
	{
		.name = "lchown32",
		.enter = sys_lchown,
		.sandbox_write = true,
	},
	{
		.name = "fchownat",
		.enter = sys_fchownat,
		.sandbox_write = true,
	},

	{
		.name = "mkdir",
		.enter = sys_mkdir,
		.sandbox_write = true,
	},
	{
		.name = "mkdirat",
		.enter = sys_mkdirat,
		.sandbox_write = true,
	},

	{
		.name = "mknod",
		.enter = sys_mknod,
		.sandbox_write = true,
	},
	{
		.name = "mknodat",
		.enter = sys_mknodat,
		.sandbox_write = true,
	},

	{
		.name = "rmdir",
		.enter = sys_rmdir,
		.sandbox_write = true,
	},

	{
		.name = "truncate",
		.enter = sys_truncate,
		.sandbox_write = true,
	},
	{
		.name = "truncate64",
		.enter = sys_truncate,
		.sandbox_write = true,
	},

	{
		.name = "utime",
		.enter = sys_utime,
		.sandbox_write = true,
	},
	{
		.name = "utimes",
		.enter = sys_utimes,
		.sandbox_write = true,
	},
	{
		.name = "utimensat",
		.enter = sys_utimensat,
		.sandbox_write = true,
	},
	{
		.name = "futimesat",
		.enter = sys_futimesat,
		.sandbox_write = true,
	},

	{
		.name = "unlink",
		.enter = sys_unlink,
		.sandbox_write = true,
	},
	{
		.name = "unlinkat",
		.enter = sys_unlinkat,
		.sandbox_write = true,
	},

	{
		.name = "link",
		.enter = sys_link,
		.sandbox_write = true,
	},
	{
		.name = "linkat",
		.enter = sys_linkat,
		.sandbox_write = true,
	},

	{
		.name = "rename",
		.enter = sys_rename,
		.sandbox_write = true,
	},
	{
		.name = "renameat",
		.enter = sys_renameat,
		.sandbox_write = true,
	},
	{
		.name = "renameat2",
		.enter = sys_renameat,
		.sandbox_write = true,
	},

	{
		.name = "symlink",
		.enter = sys_symlink,
		.sandbox_write = true,
	},
	{
		.name = "symlinkat",
		.enter = sys_symlinkat,
		.sandbox_write = true,
	},

	{
		.name = "fork",
		.enter = sys_fork,
	},
	{
		.name = "vfork",
		.enter = sys_vfork,
	},
	{
		.name = "clone",
		.enter = sys_clone,
	},
	/* TODO
	{
		.name = "clone3",
		.enter = sys_clone3,
	},
	*/

	{
		.name = "execve",
		.enter = sys_execve,
		.sandbox_exec = true,
	},
	{
		.name = "execve#64",
		.enter = sys_execve,
		.sandbox_exec = true,
	},
	{
		.name = "execveat",
		.enter = sys_execveat,
		.sandbox_exec = true,
	},
	{
		.name = "execveat#64",
		.enter = sys_execveat,
		.sandbox_exec = true,
	},

	{
		.name = "socketcall",
		.enter = sys_socketcall,
		.exit = sysx_socketcall,
		.sandbox_network = true,
	},
	{
		.name = "bind",
		.enter = sys_bind,
		.exit = sysx_bind,
		.sandbox_network = true,
	},
	{
		.name = "connect",
		.enter = sys_connect,
		.sandbox_network = true,
	},
	{
		.name = "sendto",
		.enter = sys_sendto,
		.sandbox_network = true,
	},
	{
		.name = "getsockname",
		.enter = sys_getsockname,
		.exit = sysx_getsockname,
	},

	{
		.name = "listxattr",
		.enter = sys_listxattr,
		.sandbox_read = true,
	},
	{
		.name = "llistxattr",
		.enter = sys_llistxattr,
		.sandbox_read = true,
	},
	{
		.name = "setxattr",
		.enter = sys_setxattr,
		.sandbox_write = true,
	},
	{
		.name = "lsetxattr",
		.enter = sys_lsetxattr,
		.sandbox_write = true,
	},
	{
		.name = "removexattr",
		.enter = sys_removexattr,
		.sandbox_write = true,
	},
	{
		.name = "lremovexattr",
		.enter = sys_lremovexattr,
		.sandbox_write = true,
	},

	{
		.name = "mount",
		.enter = sys_mount,
		.sandbox_write = true,
	},
	{
		.name = "umount",
		.enter = sys_umount,
		.sandbox_write = true,
	},
	{
		.name = "umount2",
		.enter = sys_umount2,
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
		if (sydbox->config.use_seccomp &&
		    syscall_entries[i].filter &&
		    syscall_entries[i].ptrace_fallback)
			continue;

		if (syscall_entries[i].name) {
			systable_add(syscall_entries[i].name,
				     syscall_entries[i].enter,
				     syscall_entries[i].exit);
		} else {
			for (int abi = 0; abi < PINK_ABIS_SUPPORTED; abi++)
				systable_add_full(syscall_entries[i].no,
						  abi, NULL,
						  syscall_entries[i].enter,
						  syscall_entries[i].exit);
		}
	}
}

#if SYDBOX_HAVE_SECCOMP
static int apply_simple_filter(const sysentry_t *entry, int arch, int abi)
{
	int r = 0;
	long sysnum;

	assert(entry->filter);

	if (entry->name)
		sysnum = pink_lookup_syscall(entry->name, abi);
	else
		sysnum = entry->no;

	if (sysnum == -1)
		return 0;

	if ((r = entry->filter(arch, sysnum)) < 0)
		return r;
	return 0;
}

int seccomp_init(void)
{
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		return -errno;
	return 0;
}

int seccomp_apply(int abi)
{
	unsigned arch;
	switch (abi) {
#if PINK_ARCH_X86_64
	case PINK_ABI_X86_64:
		arch = AUDIT_ARCH_X86_64;
		break;
#endif
#if PINK_ARCH_X86_64 || PINK_ARCH_I386
	case PINK_ABI_I386:
		arch = AUDIT_ARCH_I386;
		break;
#endif
#if PINK_ARCH_AARCH64
	case PINK_ABI_AARCH64:
		arch = AUDIT_ARCH_AARCH64;
		break;
#endif
#if PINK_ARCH_AARCH64 || PINK_ARCH_ARM
	case PINK_ABI_ARM:
		arch = AUDIT_ARCH_ARM;
		break;
#endif
	/* TODO: We do not support AUDIT_ARCH_ARMEB yet. */
	default:
		errno = EINVAL;
		return -EINVAL;
	}

	const struct sock_filter header[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, arch, 1, 0),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
	};
	const struct sock_filter footer[] = {
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
	};

	unsigned n = ELEMENTSOF(header);
	size_t idx = n;
	struct sock_fprog prog;

	/*
	 * We avoid malloc here because it's tedious but this means we have to
	 * do a bit of bookkeeping:
	 * i386: sydbox: seccomp filter count: 127, no open filter count: 123
	 * x86_64: sydbox: seccomp filter count: 141, no open filter count: 137
	 * struct sock_filter f = xmalloc(sizeof(struct sock_filter) * n);
         */
#define SYDBOX_SECCOMP_MAX 200 /* which is a reasonably large number */
	struct sock_filter f[SYDBOX_SECCOMP_MAX];
	memcpy(f, header, sizeof(header));

	for (size_t i = 0; i < ELEMENTSOF(syscall_entries); i++) {
		long sysnum;
		if (syscall_entries[i].name) {
			sysnum = pink_lookup_syscall(syscall_entries[i].name,
						    abi);
		} else {
			sysnum = syscall_entries[i].no;
		}
		if (sysnum == -1)
			continue;

		const struct sock_filter footer_trace[] = {
			BPF_STMT(BPF_RET+BPF_K,
				 SECCOMP_RET_TRACE|(sysnum & SECCOMP_RET_DATA))
		};
		const struct sock_filter syscall_check[] = {
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, sysnum, 0, 1)
		};

		sandbox_t *box = box_current(NULL);
		int open_flag = syscall_entries[i].open_flag;
		//f = xrealloc(f, sizeof(struct sock_filter) * n);
		if (open_flag) {
			struct sock_filter item_trace[] = {
				BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, sysnum, 0, 1),
				BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE|(sysnum & SECCOMP_RET_DATA))
			};
			struct sock_filter item_allow[] = {
				BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, sysnum, 0, 1),
				BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
			};
			struct sock_filter item_deny[] = {
				BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, sysnum, 0, 1),
				BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(EPERM & SECCOMP_RET_DATA)),
			};
			struct sock_filter item_errno_write[] = {
				BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, sysnum, 0, 4),
				BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_arg(open_flag)),
				BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, (O_WRONLY|O_RDWR|O_CREAT), 0, 1),
				BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(EPERM & SECCOMP_RET_DATA)),
				BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
				BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
			};
			struct sock_filter item_errno_read[] = {
				BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, sysnum, 0, 4),
				BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_arg(open_flag)),
				BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, O_WRONLY, 1, 0),
				BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(EPERM & SECCOMP_RET_DATA)),
				BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
				BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
			};

			enum sandbox_mode mode_r = box->mode.sandbox_read;
			enum sandbox_mode mode_w = box->mode.sandbox_write;
			int j = 0;
			struct sock_filter *item = NULL;
			if (mode_r == SANDBOX_OFF && mode_w == SANDBOX_OFF) {
				if (tracing()) {
					item = item_trace;
					j += 2;
				} else {
					item = item_allow;
					j += 2;
				}
			} else if ((mode_r == SANDBOX_OFF && mode_w == SANDBOX_ALLOW) ||
				   (mode_r == SANDBOX_ALLOW && mode_w == SANDBOX_OFF)) {
				if (tracing()) {
					item = item_trace;
					j += 2;
				} /* else no need to do anything. */
			} else if ((mode_r == SANDBOX_OFF || mode_r == SANDBOX_ALLOW) &&
				   mode_w == SANDBOX_DENY) {
				if (tracing()) {
					item = item_trace;
					j += 2;
				} else {
					item = item_errno_write;
					j += 6;
				}
			} else if (mode_r == SANDBOX_ALLOW && mode_w == SANDBOX_ALLOW) {
				; /* no need to do anything */
			} else if (mode_r == SANDBOX_DENY &&
				   (mode_w == SANDBOX_OFF || mode_w == SANDBOX_ALLOW)) {
				if (tracing()) {
					item = item_trace;
					j += 2;
				} else {
					item = item_errno_read;
					j += 6;
				}
			} else if (mode_r == SANDBOX_DENY && mode_w == SANDBOX_DENY) {
				if (tracing()) {
					item = item_trace;
					j += 2;
				} else {
					item = item_deny;
					j += 2;
				}
			}

			if (item) {
				n += j;
				for (int k = 0; k < j; k++)
					f[idx++] = item[k];
			}
		} else {
			int mode;
			if (syscall_entries[i].sandbox_network)
				mode = box->mode.sandbox_network;
			else if (syscall_entries[i].sandbox_exec)
				mode = box->mode.sandbox_exec;
			else if (syscall_entries[i].sandbox_write)
				mode = box->mode.sandbox_write;
			else if (syscall_entries[i].sandbox_read)
				mode = box->mode.sandbox_read;
			else
				mode = -1;

			n += 2;
			f[idx++] = syscall_check[0];
			if (tracing())
				f[idx++] = footer_trace[0];
			else if (mode == SANDBOX_DENY)
				f[idx++] = footer_eperm[0];
			else /* if (mode == -1 || mode == SANDBOX_ALLOW) */
				f[idx++] = footer_allow[0];

		}
	}
	n += ELEMENTSOF(footer);
	//f = xrealloc(f, sizeof(struct sock_filter) * n);
	memcpy(f + idx, footer, sizeof(footer));

	memset(&prog, 0, sizeof(prog));
	prog.len = n;
	prog.filter = f;
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
		// int save_errno = errno;
		// free(f);
		// return -save_errno;
		return -errno;
	}

	// say("seccomp filter count: %d, no open filter count: %d", n, n - 4);
	// free(f);
	return 0;
}

int sysinit_seccomp(void)
{
	int r;
#if defined(__arm64__) || defined(__aarch64__)
	int abi[2] = { PINK_ABI_AARCH64, PINK_ABI_ARM };
	int arch[2] = { AUDIT_ARCH_AARCH64, AUDIT_ARCH_ARM };
#elif defined(__arm__)
	int abi[2] = { PINK_ABI_DEFAULT, -1};
	int arch[2] = { AUDIT_ARCH_ARM, -1};
#elif defined(__x86_64__)
	int abi[2] = { PINK_ABI_X86_64, PINK_ABI_I386 };
	int arch[2] = { AUDIT_ARCH_X86_64, AUDIT_ARCH_I386 };
#elif defined(__i386__)
	int abi[2] = { PINK_ABI_DEFAULT, -1};
	int arch[2] = { AUDIT_ARCH_I386, -1};
#else
#error "Platform does not support seccomp filter yet"
#endif

	for (size_t i = 0; i < ELEMENTSOF(syscall_entries); i++) {
		if (!syscall_entries[i].filter)
			continue;
		for (size_t j = 0; j < 2 && abi[j] != -1; j++)
			if ((r = apply_simple_filter(&syscall_entries[i],
						     arch[j], abi[j])) < 0)
				return r;
	}

	for (size_t j = 0; j < 2 && abi[j] != -1; j++)
		if ((r = seccomp_apply(abi[j])) < 0)
			return r;

	return 0;
}
#else
int sysinit_seccomp(void)
{
	return 0;
}

int seccomp_init(void)
{
	return -ENOTSUP;
}

int seccomp_apply(int abi)
{
	return -ENOTSUP;
}
#endif

int sysenter(syd_process_t *current)
{
	int r;
	long sysnum;
	const sysentry_t *entry;

	assert(current);

	if ((r = syd_read_syscall(current, &sysnum)) < 0)
		return r;

	r = 0;
	entry = systable_lookup(sysnum, current->abi);
	if (entry) {
		current->retval = 0;
		current->sysnum = sysnum;
		current->sysname = entry->name;
		if (entry->enter) {
			r = entry->enter(current);
			if (entry->enter == sys_clone ||
			    entry->enter == sys_fork ||
			    entry->enter == sys_vfork)
				current->flags |= SYD_IN_CLONE;
			else if (entry->enter == sys_execve)
				current->flags |= SYD_IN_EXECVE;
		}
		if (entry->exit)
			current->flags |= SYD_STOP_AT_SYSEXIT;
	}

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

	entry = systable_lookup(current->sysnum, current->abi);
	r = (entry && entry->exit) ? entry->exit(current) : 0;

	reset_process(current);
	return r;
}
