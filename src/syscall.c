/*
 * sydbox/syscall.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
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
	},
	{
		.name = "lstat",
		.enter = sys_stat,
	},
	{
		.name = "stat64",
		.enter = sys_stat,
	},
	{
		.name = "lstat64",
		.enter = sys_stat,
	},
	{
		.name = "newfstatat",
		.enter = sys_fstatat,
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
	},
	{
		.name = "faccessat",
		.enter = sys_faccessat,
	},

	{
		.name = "open",
		.filter = filter_open,
		.enter = sys_open,
	},
	{
		.name = "openat",
		.filter = filter_openat,
		.enter = sys_openat,
	},
	{
		.name = "openat2",
		.enter = sys_openat2,
	},

	{
		.name = "creat",
		.enter = sys_creat,
	},

	{
		.name = "fcntl",
		.filter = filter_fcntl,
		.enter = sys_fcntl,
		.exit = sysx_fcntl,
	},
	{
		.name = "fcntl64",
		.filter = filter_fcntl,
		.enter = sys_fcntl,
		.exit = sysx_fcntl,
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
	},
	{
		.name = "fchmodat",
		.enter = sys_fchmodat,
	},

	{
		.name = "chown",
		.enter = sys_chown,
	},
	{
		.name = "chown32",
		.enter = sys_chown,
	},
	{
		.name = "lchown",
		.enter = sys_lchown,
	},
	{
		.name = "lchown32",
		.enter = sys_lchown,
	},
	{
		.name = "fchownat",
		.enter = sys_fchownat,
	},

	{
		.name = "mkdir",
		.enter = sys_mkdir,
	},
	{
		.name = "mkdirat",
		.enter = sys_mkdirat,
	},

	{
		.name = "mknod",
		.enter = sys_mknod,
	},
	{
		.name = "mknodat",
		.enter = sys_mknodat,
	},

	{
		.name = "rmdir",
		.enter = sys_rmdir,
	},

	{
		.name = "truncate",
		.enter = sys_truncate,
	},
	{
		.name = "truncate64",
		.enter = sys_truncate,
	},

	{
		.name = "utime",
		.enter = sys_utime,
	},
	{
		.name = "utimes",
		.enter = sys_utimes,
	},
	{
		.name = "utimensat",
		.enter = sys_utimensat,
	},
	{
		.name = "futimesat",
		.enter = sys_futimesat,
	},

	{
		.name = "unlink",
		.enter = sys_unlink,
	},
	{
		.name = "unlinkat",
		.enter = sys_unlinkat,
	},

	{
		.name = "link",
		.enter = sys_link,
	},
	{
		.name = "linkat",
		.enter = sys_linkat,
	},

	{
		.name = "rename",
		.enter = sys_rename,
	},
	{
		.name = "renameat",
		.enter = sys_renameat,
	},
	{
		.name = "renameat2",
		.enter = sys_renameat,
	},

	{
		.name = "symlink",
		.enter = sys_symlink,
	},
	{
		.name = "symlinkat",
		.enter = sys_symlinkat,
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

	{
		.name = "execve",
		.enter = sys_execve,
	},

	{
		.name = "socketcall",
		.enter = sys_socketcall,
		.exit = sysx_socketcall,
	},
	{
		.name = "bind",
		.enter = sys_bind,
		.exit = sysx_bind,
	},
	{
		.name = "connect",
		.enter = sys_connect,
	},
	{
		.name = "sendto",
		.enter = sys_sendto,
	},
	{
		.name = "getsockname",
		.enter = sys_getsockname,
		.exit = sysx_getsockname,
	},

	{
		.name = "listxattr",
		.enter = sys_listxattr,
	},
	{
		.name = "llistxattr",
		.enter = sys_llistxattr,
	},
	{
		.name = "setxattr",
		.enter = sys_setxattr,
	},
	{
		.name = "lsetxattr",
		.enter = sys_lsetxattr,
	},
	{
		.name = "removexattr",
		.enter = sys_removexattr,
	},
	{
		.name = "lremovexattr",
		.enter = sys_lremovexattr,
	},

	{
		.name = "mount",
		.enter = sys_mount,
	},
	{
		.name = "umount",
		.enter = sys_umount,
	},
	{
		.name = "umount2",
		.enter = sys_umount2,
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

static size_t make_seccomp_filter(int abi, uint32_t **syscalls)
{
	size_t i, j;
	long sysnum;
	uint32_t *list;

	list = xmalloc(sizeof(uint32_t) * ELEMENTSOF(syscall_entries));
	for (i = 0, j = 0; i < ELEMENTSOF(syscall_entries); i++) {
		if (syscall_entries[i].name)
			sysnum = pink_lookup_syscall(syscall_entries[i].name,
						    abi);
		else
			sysnum = syscall_entries[i].no;
		if (sysnum != -1)
			list[j++] = (uint32_t)sysnum;
	}

	*syscalls = list;
	return j;
}

int sysinit_seccomp(void)
{
	int r, count;
	size_t i;
	uint32_t *syscalls;

#if defined(__i386__)
	for (i = 0; i < ELEMENTSOF(syscall_entries); i++) {
		if (!syscall_entries[i].filter)
			continue;
		if ((r = apply_simple_filter(&syscall_entries[i],
					     AUDIT_ARCH_I386,
					     PINK_ABI_DEFAULT)) < 0)
			return r;
	}
	count = make_seccomp_filter(PINK_ABI_DEFAULT, &syscalls);
	r = seccomp_apply(AUDIT_ARCH_I386, syscalls, count);

	free(syscalls);
#elif defined(__x86_64__)
	for (i = 0; i < ELEMENTSOF(syscall_entries); i++) {
		if (!syscall_entries[i].filter)
			continue;
		if ((r = apply_simple_filter(&syscall_entries[i],
					     AUDIT_ARCH_X86_64,
					     PINK_ABI_X86_64)) < 0)
			return r;
		if ((r = apply_simple_filter(&syscall_entries[i],
					     AUDIT_ARCH_I386,
					     PINK_ABI_I386)) < 0)
			return r;
	}

	count = make_seccomp_filter(PINK_ABI_X86_64, &syscalls);
	r = seccomp_apply(AUDIT_ARCH_X86_64, syscalls, count);
	free(syscalls);
	if (r < 0)
		return r;

	count = make_seccomp_filter(PINK_ABI_I386, &syscalls);
	r = seccomp_apply(AUDIT_ARCH_I386, syscalls, count);
	free(syscalls);
#else
#error "Platform does not support seccomp filter yet"
#endif

	return r;
}
#else
int sysinit_seccomp(void)
{
	return 0;
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

	entry = systable_lookup(current->sysnum, current->abi);
	r = (entry && entry->exit) ? entry->exit(current) : 0;

	reset_process(current);
	return r;
}
