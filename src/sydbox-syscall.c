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

#include "proc.h"

void sysinit(void)
{
	systable_add("chdir", NULL, sysx_chdir);
	systable_add("fchdir", NULL, sysx_chdir);

	systable_add("stat", sys_stat, NULL);
	systable_add("stat64", sys_stat, NULL);
	systable_add("lstat", sys_stat, NULL);
	systable_add("lstat64", sys_stat, NULL);

	systable_add("access", sys_access, NULL);
	systable_add("faccessat", sys_faccessat, NULL);

	systable_add("dup", sys_dup, sysx_dup);
	systable_add("dup2", sys_dup, sysx_dup);
	systable_add("dup3", sys_dup, sysx_dup);
	systable_add("fcntl", sys_fcntl, sysx_fcntl);
	systable_add("fcntl64", sys_fcntl, sysx_fcntl);

	systable_add("execve", sys_execve, NULL);

	systable_add("chmod", sys_chmod, NULL);
	systable_add("fchmodat", sys_fchmodat, NULL);

	systable_add("chown", sys_chown, NULL);
	systable_add("chown32", sys_chown, NULL);
	systable_add("lchown", sys_lchown, NULL);
	systable_add("lchown32", sys_lchown, NULL);
	systable_add("fchownat", sys_fchownat, NULL);

	systable_add("open", sys_open, NULL);
	systable_add("openat", sys_openat, NULL);
	systable_add("creat", sys_creat, NULL);

	systable_add("mkdir", sys_mkdir, NULL);
	systable_add("mkdirat", sys_mkdirat, NULL);

	systable_add("mknod", sys_mknod, NULL);
	systable_add("mknodat", sys_mknodat, NULL);

	systable_add("rmdir", sys_rmdir, NULL);

	systable_add("truncate", sys_truncate, NULL);
	systable_add("truncate64", sys_truncate, NULL);

	systable_add("mount", sys_mount, NULL);
	systable_add("umount", sys_umount, NULL);
	systable_add("umount2", sys_umount2, NULL);

	systable_add("utime", sys_utime, NULL);
	systable_add("utimes", sys_utimes, NULL);
	systable_add("utimensat", sys_utimensat, NULL);
	systable_add("futimesat", sys_futimesat, NULL);

	systable_add("unlink", sys_unlink, NULL);
	systable_add("unlinkat", sys_unlinkat, NULL);

	systable_add("link", sys_link, NULL);
	systable_add("linkat", sys_linkat, NULL);

	systable_add("rename", sys_rename, NULL);
	systable_add("renameat", sys_renameat, NULL);

	systable_add("symlink", sys_symlink, NULL);
	systable_add("symlinkat", sys_symlinkat, NULL);

	systable_add("setxattr", sys_setxattr, NULL);
	systable_add("lsetxattr", sys_lsetxattr, NULL);
	systable_add("removexattr", sys_removexattr, NULL);
	systable_add("lremovexattr", sys_lremovexattr, NULL);

	systable_add("socketcall", sys_socketcall, sysx_socketcall);
	systable_add("bind", sys_bind, sysx_bind);
	systable_add("connect", sys_connect, NULL);
	systable_add("sendto", sys_sendto, NULL);
	systable_add("recvfrom", sys_recvfrom, NULL);
	systable_add("getsockname", sys_getsockname, sysx_getsockname);
}

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

	if (!pink_read_syscall(tid, abi, data->regs, &no)) {
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