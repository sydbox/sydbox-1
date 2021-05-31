/*
 * sydbox/syscall-filter.c
 *
 * Simple seccomp based system call filters
 *
 * Copyright (c) 2013, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"

#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>

#if SYDBOX_HAVE_SECCOMP
# include "seccomp.h"
#endif

static int filter_open_index(int arch, uint32_t sysnum, unsigned flag_index)
{
#if SYDBOX_HAVE_SECCOMP
	if (!sydbox->config.restrict_file_control)
		return 0;

	struct sock_filter open_filter[] = {
		/* check for arch & syscall_nr */
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, arch, 1, 0),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
		/* check for O_ASYNC|O_DIRECT|O_SYNC */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, sysnum, 0, 3/*jump to allow*/),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_arg(flag_index)),
		BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, (O_ASYNC|O_DIRECT|O_SYNC), 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(EPERM & SECCOMP_RET_DATA)),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
	};
	struct sock_fprog prog;

	memset(&prog, 0, sizeof(prog));
	prog.filter = open_filter;
	prog.len = ELEMENTSOF(open_filter);

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0)
		return -errno;
#endif
	return 0;
}

int filter_open(int arch, uint32_t sysnum)
{
	return filter_open_index(arch, sysnum, 1);
}

int filter_openat(int arch, uint32_t sysnum)
{
	return filter_open_index(arch, sysnum, 2);
}

int filter_fcntl(int arch, uint32_t sysnum)
{
#if SYDBOX_HAVE_SECCOMP
	if (!sydbox->config.restrict_file_control)
		return 0;

	struct sock_filter fcntl_filter[] = {
		/* check for arch & syscall_nr */
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, arch, 1, 0),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, sysnum, 0, 16),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_arg(1)), /* cmd */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, F_GETFL, 13, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, F_SETFL, 12, 0), /* check arg0 */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, F_SETOWN, 11, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, F_SETLK, 10, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, F_SETLKW, 9, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, F_SETLK64, 8, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, F_SETLKW64, 7, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, F_GETFD, 6, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, F_SETFD, 5, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, F_DUPFD, 4, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, F_DUPFD_CLOEXEC, 3, 0),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(EPERM & SECCOMP_RET_DATA)),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_arg(2)),
		BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, (O_ASYNC|O_DIRECT), 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(EPERM & SECCOMP_RET_DATA)),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
	};
	struct sock_fprog prog;

	memset(&prog, 0, sizeof(prog));
	prog.filter = fcntl_filter;
	prog.len = ELEMENTSOF(fcntl_filter);

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0)
		return -errno;
#endif
	return 0;
}

int filter_mmap(int arch, uint32_t sysnum)
{
#if SYDBOX_HAVE_SECCOMP
	if (!sydbox->config.restrict_shared_memory_writable)
		return 0;

	struct sock_filter mmap_filter[] = {
		/* check for arch & syscall_nr */
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, arch, 1, 0),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
		/* check for PROT_WRITE & MAP_SHARED */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, sysnum, 0, 5),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_arg(2)), /* prot */
		BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, PROT_WRITE, 0, 3),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_arg(3)), /* flags */
		BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, MAP_SHARED, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(EPERM & SECCOMP_RET_DATA)),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
	};
	struct sock_fprog prog;

	memset(&prog, 0, sizeof(prog));
	prog.filter = mmap_filter;
	prog.len = ELEMENTSOF(mmap_filter);

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0)
		return -errno;
#endif
	return 0;
}

int sys_fallback_mmap(syd_process_t *current)
{
	int r;
	int prot, flags;

	if (!sydbox->config.restrict_shared_memory_writable)
		return 0;

	if ((r = syd_read_argument_int(current, 2, &prot)) < 0)
		return r;
	if ((r = syd_read_argument_int(current, 3, &flags)) < 0)
		return r;

	r = 0;
	if (prot & PROT_WRITE && flags & MAP_SHARED)
		r = deny(current, EPERM);
	return r;
}
