/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 *
 * This file is part of Sydbox. sydbox is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2, as published by the Free Software Foundation.
 *
 * sydbox is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "sydbox-defs.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "macro.h"
#include "proc.h"
#ifdef WANT_SECCOMP
#include "seccomp.h"
#endif

static const sysentry_t syscall_entries[] = {
	{"chdir", NULL, sysx_chdir},
	{"fchdir", NULL, sysx_chdir},

	{"stat", sys_stat, NULL},
	{"stat64", sys_stat, NULL},
	{"lstat", sys_stat, NULL},
	{"lstat64", sys_stat, NULL},

	{"access", sys_access, NULL},
	{"faccessat", sys_faccessat, NULL},

	{"dup", sys_dup, sysx_dup},
	{"dup2", sys_dup, sysx_dup},
	{"dup3", sys_dup, sysx_dup},
	{"fcntl", sys_fcntl, sysx_fcntl},
	{"fcntl64", sys_fcntl, sysx_fcntl},

	{"execve", sys_execve, NULL},

	{"chmod", sys_chmod, NULL},
	{"fchmodat", sys_fchmodat, NULL},

	{"chown", sys_chown, NULL},
	{"chown32", sys_chown, NULL},
	{"lchown", sys_lchown, NULL},
	{"lchown32", sys_lchown, NULL},
	{"fchownat", sys_fchownat, NULL},

	{"open", sys_open, NULL},
	{"openat", sys_openat, NULL},
	{"creat", sys_creat, NULL},

	{"mkdir", sys_mkdir, NULL},
	{"mkdirat", sys_mkdirat, NULL},

	{"mknod", sys_mknod, NULL},
	{"mknodat", sys_mknodat, NULL},

	{"rmdir", sys_rmdir, NULL},

	{"truncate", sys_truncate, NULL},
	{"truncate64", sys_truncate, NULL},

	{"mount", sys_mount, NULL},
	{"umount", sys_umount, NULL},
	{"umount2", sys_umount2, NULL},

	{"utime", sys_utime, NULL},
	{"utimes", sys_utimes, NULL},
	{"utimensat", sys_utimensat, NULL},
	{"futimesat", sys_futimesat, NULL},

	{"unlink", sys_unlink, NULL},
	{"unlinkat", sys_unlinkat, NULL},

	{"link", sys_link, NULL},
	{"linkat", sys_linkat, NULL},

	{"rename", sys_rename, NULL},
	{"renameat", sys_renameat, NULL},

	{"symlink", sys_symlink, NULL},
	{"symlinkat", sys_symlinkat, NULL},

	{"setxattr", sys_setxattr, NULL},
	{"lsetxattr", sys_lsetxattr, NULL},
	{"removexattr", sys_removexattr, NULL},
	{"lremovexattr", sys_lremovexattr, NULL},

	{"socketcall", sys_socketcall, sysx_socketcall},
	{"bind", sys_bind, sysx_bind},
	{"connect", sys_connect, NULL},
	{"sendto", sys_sendto, NULL},
	{"recvfrom", sys_recvfrom, NULL},
	{"getsockname", sys_getsockname, sysx_getsockname},
};

void sysinit(void)
{
	unsigned i;

	for (i = 0; i < ELEMENTSOF(syscall_entries); i++)
		systable_add(syscall_entries[i].name, syscall_entries[i].enter, syscall_entries[i].exit);
}

#ifdef WANT_SECCOMP
int sysinit_seccomp(void)
{
	int r;
	unsigned i, j;
	long sysno;
	uint32_t *sysarray;

	sysarray = xmalloc(sizeof(uint32_t) * ELEMENTSOF(syscall_entries));
	for (i = 0, j = 0; i < ELEMENTSOF(syscall_entries); i++) {
		sysno = pink_syscall_lookup(syscall_entries[i].name, PINK_ABI_DEFAULT);
		if (sysno != -1)
			sysarray[j++] = (uint32_t)sysno;
	}
	sysarray[j] = SYSCALL_FILTER_SENTINEL;

	r = seccomp_apply(sysarray);
	free(sysarray);
	return r;
}
#else
int sysinit_seccomp(void)
{
	return 0;
}
#endif

int sysenter(struct pink_easy_process *current)
{
	long no;
	const char *name;
	pid_t tid;
	enum pink_abi abi;
	proc_data_t *data;
	const sysentry_t *entry;

	tid = pink_easy_process_get_tid(current);
	abi = pink_easy_process_get_abi(current);
	data = pink_easy_process_get_userdata(current);

	if (!pink_read_syscall(tid, abi, &data->regs, &no)) {
		if (errno != ESRCH) {
			warning("pink_read_syscall(%lu, %d) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	data->sno = no;
	entry = systable_lookup(no, abi);
	if (entry)
		debug("process:%lu is entering system call \"%s\"",
				(unsigned long)tid,
				entry->name);
	else {
		name = pink_syscall_name(no, abi);
		trace("process:%lu is entering system call \"%s\"",
				(unsigned long)tid,
				name ? name : "???");
	}

	return (entry && entry->enter) ? entry->enter(current, entry->name) : 0;
}

int sysexit(struct pink_easy_process *current)
{
	int r;
	const sysentry_t *entry;
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (data->deny) {
		r = restore(current);
		goto end;
	}

	entry = systable_lookup(data->sno, abi);
	r = (entry && entry->exit) ? entry->exit(current, entry->name) : 0;
end:
	clear_proc(data);
	return r;
}
