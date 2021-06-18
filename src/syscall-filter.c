/*
 * sydbox/syscall-filter.c
 *
 * Simple seccomp based system call filters
 *
 * Copyright (c) 2013, 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon Tor's sandbox which is
 *   Copyright (c) 2001 Matej Pfajfar.
 *   Copyright (c) 2001-2004, Roger Dingledine.
 *   Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 *   Copyright (c) 2007-2021, The Tor Project, Inc.
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/kd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/vt.h>

static const int filter_gen_level1[] = {
	SCMP_SYS(close),
	SCMP_SYS(dup),
#ifdef __NR_dup2
	SCMP_SYS(dup2),
#endif
	SCMP_SYS(exit),
	SCMP_SYS(exit_group),
	SCMP_SYS(execve),
#ifdef __NR_execveat
	SCMP_SYS(execveat),
#endif
	SCMP_SYS(arch_prctl),
	SCMP_SYS(getpid),
	SCMP_SYS(set_tid_address),
	SCMP_SYS(pause),
	SCMP_SYS(read),
#ifdef __NR_readv
	SCMP_SYS(readv),
#endif
#ifdef __NR_preadv
	SCMP_SYS(preadv),
#endif
#ifdef __NR_preadv2
	SCMP_SYS(preadv2),
#endif
	SCMP_SYS(write),
#ifdef __NR_writev
	SCMP_SYS(writev),
#endif
#ifdef __NR_pwritev
	SCMP_SYS(pwritev),
#endif
#ifdef __NR_pwritev2
	SCMP_SYS(pwritev2),
#endif
	SCMP_SYS(sigreturn),
	SCMP_SYS(stat),
#ifdef __NR_stat64
	SCMP_SYS(stat64),
#endif
	SCMP_SYS(fstat),
#ifdef __NR_fstat64
	SCMP_SYS(fstat64),
#endif
	SCMP_SYS(lstat),
#ifdef __NR_newfstatat
	SCMP_SYS(newfstatat),
#endif
	SCMP_SYS(brk),
#ifdef __NR_mmap
	SCMP_SYS(mmap),
#endif
#ifdef __NR_mmap2
	SCMP_SYS(mmap2),
#endif
#ifdef __NR_munmap
	SCMP_SYS(munmap),
#endif
};

static const int filter_gen_level2[] = {
	SCMP_SYS(arch_prctl),
	SCMP_SYS(access),
	SCMP_SYS(brk),
	SCMP_SYS(clock_gettime),
	SCMP_SYS(close),
	SCMP_SYS(clone),
	SCMP_SYS(dup),
#ifdef __NR_dup2
	SCMP_SYS(dup2),
#endif
	SCMP_SYS(epoll_create),
	SCMP_SYS(epoll_wait),
#ifdef __NR_epoll_pwait
	SCMP_SYS(epoll_pwait),
#endif
	SCMP_SYS(execve),
#ifdef __NR_execveat
	SCMP_SYS(execveat),
#endif
	SCMP_SYS(exit),
	SCMP_SYS(exit_group),
	SCMP_SYS(fork),
	SCMP_SYS(vfork),
	SCMP_SYS(clone),
#ifdef __NR_clone3
	SCMP_SYS(clone3),
#endif
#ifdef __NR_eventfd2
	SCMP_SYS(eventfd2),
#endif
#ifdef __NR_pipe2
	SCMP_SYS(pipe2),
#endif
#ifdef __NR_pipe
	SCMP_SYS(pipe),
#endif
	SCMP_SYS(fcntl),
	SCMP_SYS(fstat),
#ifdef __NR_fstat64
	SCMP_SYS(fstat64),
#endif
	SCMP_SYS(fsync),
	SCMP_SYS(futex),
	SCMP_SYS(getdents),
	SCMP_SYS(getdents64),
	SCMP_SYS(getegid),
#ifdef __NR_getegid32
	SCMP_SYS(getegid32),
#endif
	SCMP_SYS(geteuid),
#ifdef __NR_geteuid32
	SCMP_SYS(geteuid32),
#endif
	SCMP_SYS(getgid),
#ifdef __NR_getgid32
	SCMP_SYS(getgid32),
#endif
	SCMP_SYS(getpgrp),
	SCMP_SYS(getpid),
	SCMP_SYS(getppid),
	SCMP_SYS(getpgid),
#ifdef __NR_getrlimit
	SCMP_SYS(getrlimit),
#endif
	SCMP_SYS(gettimeofday),
	SCMP_SYS(gettid),
	SCMP_SYS(getuid),
#ifdef __NR_getuid32
	SCMP_SYS(getuid32),
#endif
	SCMP_SYS(lseek),
#ifdef __NR__llseek
	SCMP_SYS(_llseek),
#endif
	// glob uses this..
	SCMP_SYS(lstat),
	SCMP_SYS(mlockall),
#ifdef __NR_mmap
	SCMP_SYS(mmap),
#endif
#ifdef __NR_mmap2
	SCMP_SYS(mmap2),
#endif
#ifdef __NR_munmap
	SCMP_SYS(munmap),
#endif
#ifdef __NR_nanosleep
	SCMP_SYS(nanosleep),
#endif
	SCMP_SYS(open),
	SCMP_SYS(openat),
/*
 * TODO: This does not work with libseccomp-2.5.1
#ifdef __NR_openat2
	SCMP_SYS(openat2),
#endif
*/
	SCMP_SYS(pause),
#ifdef __NR_preadv
	SCMP_SYS(preadv),
#endif
#ifdef __NR_preadv2
	SCMP_SYS(preadv2),
#endif
#ifdef __NR_prlimit
	SCMP_SYS(prlimit),
#endif
#ifdef __NR_prlimit64
	SCMP_SYS(prlimit64),
#endif
	SCMP_SYS(pselect6),
	SCMP_SYS(read),
	SCMP_SYS(pause),
#ifdef __NR_readv
	SCMP_SYS(readv),
#endif
	SCMP_SYS(rt_sigaction),
	SCMP_SYS(rt_sigprocmask),
	SCMP_SYS(rt_sigreturn),
	SCMP_SYS(sched_getaffinity),
#ifdef __NR_sched_yield
	SCMP_SYS(sched_yield),
#endif
	SCMP_SYS(sendmsg),
	SCMP_SYS(set_robust_list),
	SCMP_SYS(setpgid),
#ifdef __NR_setrlimit
	SCMP_SYS(setrlimit),
#endif
	SCMP_SYS(shutdown),
#ifdef __NR_sigaltstack
	SCMP_SYS(sigaltstack),
#endif
#ifdef __NR_sigreturn
	SCMP_SYS(sigreturn),
#endif
	SCMP_SYS(stat),
	SCMP_SYS(uname),
	SCMP_SYS(wait4),
	SCMP_SYS(write),
#ifdef __NR_writev
	SCMP_SYS(writev),
#endif
#ifdef __NR_pwritev
	SCMP_SYS(pwritev),
#endif
#ifdef __NR_pwritev2
	SCMP_SYS(pwritev2),
#endif
	SCMP_SYS(exit_group),
	SCMP_SYS(exit),

	SCMP_SYS(madvise),
	SCMP_SYS(membarrier),
	SCMP_SYS(set_tid_address),
	SCMP_SYS(stat),
#ifdef __NR_stat64
	// getaddrinfo uses this..
	SCMP_SYS(stat64),
#endif

#ifdef __NR_getrandom
	SCMP_SYS(getrandom),
#endif

#ifdef __NR_sysinfo
// qsort uses this..
	SCMP_SYS(sysinfo),
#endif
/*
* These socket syscalls are not required on x86_64 and not supported with
* some libseccomp versions (eg: 1.0.1)
*/
#if defined(__i386)
	SCMP_SYS(recv),
	SCMP_SYS(send),
#endif
	// socket syscalls
	SCMP_SYS(bind),
	SCMP_SYS(listen),
	SCMP_SYS(connect),
	SCMP_SYS(getsockname),
#ifdef __NR_getpeername
	SCMP_SYS(getpeername),
#endif
	SCMP_SYS(recvmsg),
	SCMP_SYS(recvfrom),
	SCMP_SYS(sendto),
#ifdef __NR_readlink
	SCMP_SYS(readlink),
#endif
#ifdef __NR_readlinkat
	SCMP_SYS(readlinkat),
#endif
	SCMP_SYS(unlink),
#ifdef __NR_unlinkat
	SCMP_SYS(unlinkat),
#endif
	SCMP_SYS(select),
#ifdef __NR_pselect6
	SCMP_SYS(pselect6),
#endif
	SCMP_SYS(poll),
#ifdef __NR_readlink
	SCMP_SYS(readlink),
#endif
#ifdef __NR_readlinkat
	SCMP_SYS(readlinkat),
#endif
};

static const int filter_gen_level3[] = {
	SCMP_SYS(arch_prctl),
	SCMP_SYS(access),
	SCMP_SYS(brk),
	SCMP_SYS(clock_gettime),
	SCMP_SYS(close),
	SCMP_SYS(clone),
	SCMP_SYS(dup),
#ifdef __NR_dup2
	SCMP_SYS(dup2),
#endif
	SCMP_SYS(epoll_create),
	SCMP_SYS(epoll_wait),
#ifdef __NR_epoll_pwait
	SCMP_SYS(epoll_pwait),
#endif
	SCMP_SYS(execve),
#ifdef __NR_execveat
	SCMP_SYS(execveat),
#endif
	SCMP_SYS(exit),
	SCMP_SYS(exit_group),
	SCMP_SYS(fork),
	SCMP_SYS(vfork),
	SCMP_SYS(clone),
#ifdef __NR_clone3
	SCMP_SYS(clone3),
#endif
#ifdef __NR_eventfd2
	SCMP_SYS(eventfd2),
#endif
#ifdef __NR_pipe2
	SCMP_SYS(pipe2),
#endif
#ifdef __NR_pipe
	SCMP_SYS(pipe),
#endif
	SCMP_SYS(fcntl),
	SCMP_SYS(fstat),
#ifdef __NR_fstat64
	SCMP_SYS(fstat64),
#endif
	SCMP_SYS(fsync),
	SCMP_SYS(futex),
	SCMP_SYS(getdents),
	SCMP_SYS(getdents64),
	SCMP_SYS(getegid),
#ifdef __NR_getegid32
	SCMP_SYS(getegid32),
#endif
	SCMP_SYS(geteuid),
#ifdef __NR_geteuid32
	SCMP_SYS(geteuid32),
#endif
	SCMP_SYS(getgid),
#ifdef __NR_getgid32
	SCMP_SYS(getgid32),
#endif
	SCMP_SYS(getpgrp),
	SCMP_SYS(getpid),
	SCMP_SYS(getppid),
	SCMP_SYS(getpgid),
#ifdef __NR_getrlimit
	SCMP_SYS(getrlimit),
#endif
	SCMP_SYS(gettimeofday),
	SCMP_SYS(gettid),
	SCMP_SYS(getuid),
#ifdef __NR_getuid32
	SCMP_SYS(getuid32),
#endif
	SCMP_SYS(lseek),
#ifdef __NR__llseek
	SCMP_SYS(_llseek),
#endif
	// glob uses this..
	SCMP_SYS(lstat),
	SCMP_SYS(mlockall),
#ifdef __NR_mmap
	SCMP_SYS(mmap),
#endif
#ifdef __NR_mmap2
	SCMP_SYS(mmap2),
#endif
#ifdef __NR_munmap
	SCMP_SYS(munmap),
#endif
#ifdef __NR_nanosleep
	SCMP_SYS(nanosleep),
#endif
	SCMP_SYS(open),
	SCMP_SYS(openat),
#ifdef __NR_preadv
	SCMP_SYS(preadv),
#endif
#ifdef __NR_preadv2
	SCMP_SYS(preadv2),
#endif
#ifdef __NR_prlimit
	SCMP_SYS(prlimit),
#endif
#ifdef __NR_prlimit64
	SCMP_SYS(prlimit64),
#endif
	SCMP_SYS(pselect6),
	SCMP_SYS(read),
#ifdef __NR_readv
	SCMP_SYS(readv),
#endif
	SCMP_SYS(rt_sigaction),
	SCMP_SYS(rt_sigprocmask),
	SCMP_SYS(rt_sigreturn),
	SCMP_SYS(sched_getaffinity),
#ifdef __NR_sched_yield
	SCMP_SYS(sched_yield),
#endif
	SCMP_SYS(sendmsg),
	SCMP_SYS(set_robust_list),
	SCMP_SYS(setpgid),
#ifdef __NR_setrlimit
	SCMP_SYS(setrlimit),
#endif
	SCMP_SYS(shutdown),
#ifdef __NR_sigaltstack
	SCMP_SYS(sigaltstack),
#endif
#ifdef __NR_sigreturn
	SCMP_SYS(sigreturn),
#endif
	SCMP_SYS(stat),
	SCMP_SYS(uname),
	SCMP_SYS(wait4),
	SCMP_SYS(write),
#ifdef __NR_writev
	SCMP_SYS(writev),
#endif
#ifdef __NR_pwritev
	SCMP_SYS(pwritev),
#endif
#ifdef __NR_pwritev2
	SCMP_SYS(pwritev2),
#endif
	SCMP_SYS(exit_group),
	SCMP_SYS(exit),

	SCMP_SYS(madvise),
	SCMP_SYS(membarrier),
	SCMP_SYS(set_tid_address),
	SCMP_SYS(stat),
#ifdef __NR_stat64
	// getaddrinfo uses this..
	SCMP_SYS(stat64),
#endif

#ifdef __NR_getrandom
	SCMP_SYS(getrandom),
#endif

#ifdef __NR_sysinfo
// qsort uses this..
	SCMP_SYS(sysinfo),
#endif
/*
* These socket syscalls are not required on x86_64 and not supported with
* some libseccomp versions (eg: 1.0.1)
*/
#if defined(__i386)
	SCMP_SYS(recv),
	SCMP_SYS(send),
#endif
	// socket syscalls
	SCMP_SYS(bind),
	SCMP_SYS(listen),
	SCMP_SYS(connect),
	SCMP_SYS(getsockname),
#ifdef __NR_getpeername
	SCMP_SYS(getpeername),
#endif
	SCMP_SYS(recvmsg),
	SCMP_SYS(recvfrom),
	SCMP_SYS(sendto),
#ifdef __NR_readlink
	SCMP_SYS(readlink),
#endif
#ifdef __NR_readlinkat
	SCMP_SYS(readlinkat),
#endif
	SCMP_SYS(unlink),
#ifdef __NR_unlinkat
	SCMP_SYS(unlinkat),
#endif
	SCMP_SYS(select),
#ifdef __NR_pselect6
	SCMP_SYS(pselect6),
#endif
	SCMP_SYS(poll),
#ifdef __NR_readlink
	SCMP_SYS(readlink),
#endif
#ifdef __NR_readlinkat
	SCMP_SYS(readlinkat),
#endif
	/* Level 3 additions */
	SCMP_SYS(chmod),
#ifdef __NR_fchmod
	SCMP_SYS(fchmod),
#endif
#ifdef __NR_fchmodat
	SCMP_SYS(fchmodat),
#endif
	SCMP_SYS(chown),
#ifdef __NR_chown32
	SCMP_SYS(chown32),
#endif
	SCMP_SYS(lchown),
#ifdef __NR_lchown32
	SCMP_SYS(lchown32),
#endif
#ifdef __NR_fchownat
	SCMP_SYS(fchownat),
#endif
	SCMP_SYS(creat),
	SCMP_SYS(mkdir),
	SCMP_SYS(mkdirat),
	SCMP_SYS(mknod),
	SCMP_SYS(mknodat),
	SCMP_SYS(rmdir),
	SCMP_SYS(truncate),
#ifdef __NR_truncate64
	SCMP_SYS(truncate64),
#endif
	SCMP_SYS(link),
	SCMP_SYS(linkat),
	SCMP_SYS(unlink),
	SCMP_SYS(unlinkat),
	SCMP_SYS(rename),
	SCMP_SYS(renameat),
#ifdef __NR_renameat2
	SCMP_SYS(renameat2),
#endif
	SCMP_SYS(symlink),
	SCMP_SYS(symlinkat),
	SCMP_SYS(utime),
	SCMP_SYS(utimes),
#ifdef __NR_utimensat
	SCMP_SYS(utimensat),
#endif
#ifdef __NR_futimesat
	SCMP_SYS(futimesat),
#endif
	SCMP_SYS(setxattr),
	SCMP_SYS(lsetxattr),
	SCMP_SYS(removexattr),
	SCMP_SYS(lremovexattr),
/*
 * TODO: This does not work with libseccomp-2.5.1
#ifdef __NR_openat2
	SCMP_SYS(openat2),
#endif
*/
};

bool filter_includes(int sysnum)
{
	size_t max;
	const int *filter;
	switch (sydbox->config.restrict_general) {
	case 0:
		return false;
	case 1:
		filter = filter_gen_level1;
		max = ELEMENTSOF(filter_gen_level1);
		break;
	case 2:
		filter = filter_gen_level2;
		max = ELEMENTSOF(filter_gen_level2);
		break;
	case 3:
		filter = filter_gen_level3;
		max = ELEMENTSOF(filter_gen_level3);
		break;
	default:
		assert_not_reached();
	}

	for (size_t i = 0; i < max; i++)
		if (sysnum == filter[i])
			return true;
	return false;
}

static int filter_open_readonly()
{
	uint32_t action;
	enum sandbox_mode mode;

	mode = sydbox->config.box_static.mode.sandbox_read;
	switch (mode) {
	case SANDBOX_OFF:
	case SANDBOX_ALLOW:
		action = SCMP_ACT_ALLOW;
		break;
	case SANDBOX_BPF:
	case SANDBOX_DENY:
		action = SCMP_ACT_ERRNO(EPERM);
		break;
	default:
		assert_not_reached();
	}

	if (action == sydbox->seccomp_action)
		return 0;

	for (unsigned i = 0; i < ELEMENTSOF(open_readonly_flags); i++) {
		syd_rule_add_return(sydbox->ctx, action,
				    SCMP_SYS(open), 1,
				    SCMP_A1( SCMP_CMP_EQ,
					     open_readonly_flags[i],
					     open_readonly_flags[i] ));
		syd_rule_add_return(sydbox->ctx, action,
				    SCMP_SYS(openat), 1,
				    SCMP_A2( SCMP_CMP_EQ,
					     open_readonly_flags[i],
					     open_readonly_flags[i] ));
	}

	return 0;
}

static int filter_time(void)
{
	uint32_t action = SCMP_ACT_ALLOW;

	if (action == sydbox->seccomp_action)
		return 0;

	syd_rule_add_return(sydbox->ctx, SCMP_ACT_ALLOW,
			    SCMP_SYS(time), 1,
			    SCMP_CMP(0, SCMP_CMP_EQ, 0))

	return 0;
}

static int filter_rt_sigaction(void)
{
	int param[] = { SIGINT, SIGTERM, SIGPIPE, SIGUSR1, SIGUSR2, SIGHUP,
		SIGCHLD, SIGSEGV, SIGILL, SIGFPE, SIGBUS, SIGSYS, SIGIO,
#ifdef SIGXFSZ
		SIGXFSZ
#endif
	};
	uint32_t action = SCMP_ACT_ALLOW;

	if (action == sydbox->seccomp_action)
		return 0;

	for (unsigned short i = 0; i < ELEMENTSOF(param); i++) {
		syd_rule_add_return(sydbox->ctx, action,
				    SCMP_SYS(rt_sigaction), 1,
				    SCMP_CMP(0, SCMP_CMP_EQ, param[i]));
	}

	return 0;
}

static int filter_general_level_1(void)
{
	int r;

	for (unsigned i = 0; i < ELEMENTSOF(filter_gen_level1); i++) {
		if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ALLOW,
					  filter_gen_level1[i], 0)) &&
		    r != -EEXIST) {
			char *name;
			name = seccomp_syscall_resolve_num_arch(filter_gen_level1[i],
								SCMP_ARCH_NATIVE);
			errno = -r;
			say_errno("Sandbox failed to add syscall index %d (NR=%d) "
				  "name \"%s\", received libseccomp error",
				  i, filter_gen_level1[i],
				  name ? name : "?");
			if (name)
				free(name);
			return r;
		}
	}

	if ((r = filter_open_readonly()) < 0)
		return r;

	return 0;
}

static int filter_general_level_2(void)
{
	int r;

	for (unsigned i = 0; i < ELEMENTSOF(filter_gen_level2); i++) {
		if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ALLOW,
					  filter_gen_level2[i], 0)) &&
		    r != -EEXIST) {
			char *name;
			name = seccomp_syscall_resolve_num_arch(filter_gen_level2[i],
								SCMP_ARCH_NATIVE);
			errno = -r;
			say_errno("Sandbox failed to add syscall index %d (NR=%d) "
				  "name \"%s\", received libseccomp error",
				  i, filter_gen_level2[i],
				  name ? name : "?");
			if (name)
				free(name);
			return r;
		}
	}

#ifdef __NR_newfstatat
	// Libc 2.33 uses this syscall to implement both fstat() and stat().
	//
	// The trouble is that to implement fstat(fd, &st), it calls:
	//     newfstatat(fs, "", &st, AT_EMPTY_PATH)
	// We can't detect this usage in particular, because "" is a pointer
	// we don't control.  And we can't just look for AT_EMPTY_PATH, since
	// AT_EMPTY_PATH only has effect when the path string is empty.
	//
	// So our only solution seems to be allowing all fstatat calls, which
	// means that an attacker can stat() anything on the filesystem. That's
	// not a great solution, but I can't find a better one.
	syd_rule_add_return(sydbox->ctx, SCMP_ACT_ALLOW,
			    SCMP_SYS(newfstatat), 0);
#endif

	if ((r = filter_time()) < 0)
		return r;
	if ((r = filter_rt_sigaction()) < 0)
		return r;

	return 0;
}

static int filter_general_level_3(void)
{
	int r;

	for (unsigned i = 0; i < ELEMENTSOF(filter_gen_level3); i++) {
		if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ALLOW,
					  filter_gen_level3[i], 0)) &&
		    r != -EEXIST) {
			char *name;
			name = seccomp_syscall_resolve_num_arch(filter_gen_level3[i],
								SCMP_ARCH_NATIVE);
			errno = -r;
			say_errno("Sandbox failed to add syscall index %d (NR=%d) "
				  "name \"%s\", received libseccomp error",
				  i, filter_gen_level3[i],
				  name ? name : "?");
			if (name)
				free(name);
			return r;
		}
	}

#ifdef __NR_newfstatat
	// Libc 2.33 uses this syscall to implement both fstat() and stat().
	//
	// The trouble is that to implement fstat(fd, &st), it calls:
	//     newfstatat(fs, "", &st, AT_EMPTY_PATH)
	// We can't detect this usage in particular, because "" is a pointer
	// we don't control.  And we can't just look for AT_EMPTY_PATH, since
	// AT_EMPTY_PATH only has effect when the path string is empty.
	//
	// So our only solution seems to be allowing all fstatat calls, which
	// means that an attacker can stat() anything on the filesystem. That's
	// not a great solution, but I can't find a better one.
	syd_rule_add_return(sydbox->ctx, SCMP_ACT_ALLOW,
			    SCMP_SYS(newfstatat), 0);
#endif

	if ((r = filter_open_readonly()) < 0)
		return r;
	if ((r = filter_time()) < 0)
		return r;
	if ((r = filter_rt_sigaction()) < 0)
		return r;

	return 0;
}

int filter_general(void)
{
	static const int allow_calls[] = {
		SCMP_SYS(exit),
		SCMP_SYS(exit_group),
		SCMP_SYS(arch_prctl),
		SCMP_SYS(membarrier),
		SCMP_SYS(set_tid_address),
		SCMP_SYS(rt_sigprocmask),
	};

	if (sydbox->seccomp_action != SCMP_ACT_ALLOW) {
		for (unsigned int i = 0; i < ELEMENTSOF(allow_calls); i++)
			syd_rule_add_return(sydbox->ctx, SCMP_ACT_ALLOW,
					    allow_calls[i], 0);
	}

	switch (sydbox->config.restrict_general) {
	case 0:
		return 0;
	case 1:
		return filter_general_level_1();
	case 2:
		return filter_general_level_2();
	case 3:
		return filter_general_level_3();
	default:
		return -EINVAL;
	}
}

static int filter_mmap_restrict_shared(int sys_mmap)
{
	syd_rule_add_return(sydbox->ctx, SCMP_ACT_ERRNO(EPERM),
			    sys_mmap, 2,
			    SCMP_A2( SCMP_CMP_MASKED_EQ,
				     PROT_WRITE, PROT_WRITE ),
			    SCMP_A3( SCMP_CMP_MASKED_EQ,
				     MAP_SHARED, MAP_SHARED ));
	return 0;
}

static int filter_mmap_restrict(int sys_mmap)
{
	uint32_t action = SCMP_ACT_ALLOW;

	if (action == sydbox->seccomp_action)
		return 0;

	syd_rule_add_return(sydbox->ctx, action,
			    sys_mmap, 2,
			    SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ),
			    SCMP_CMP(3, SCMP_CMP_EQ, MAP_PRIVATE));
	syd_rule_add_return(sydbox->ctx, action,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ, PROT_NONE),
				  SCMP_CMP(3, SCMP_CMP_EQ,
					   MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE))
	syd_rule_add_return(sydbox->ctx, action,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ,
					   PROT_READ|PROT_WRITE),
				  SCMP_CMP(3, SCMP_CMP_EQ, MAP_PRIVATE|MAP_ANONYMOUS));
	syd_rule_add_return(sydbox->ctx, action,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ,
					   PROT_READ|PROT_WRITE),
				  SCMP_CMP(3, SCMP_CMP_EQ,MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK));
	syd_rule_add_return(sydbox->ctx, action,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ|PROT_WRITE),
				  SCMP_CMP(3, SCMP_CMP_EQ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE));
	syd_rule_add_return(sydbox->ctx, action,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ,
					   PROT_READ|PROT_WRITE),
				  SCMP_CMP(3, SCMP_CMP_EQ,
					   MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS));
	syd_rule_add_return(sydbox->ctx, action,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ|PROT_EXEC),
				  SCMP_CMP(3, SCMP_CMP_EQ,
					   MAP_PRIVATE|MAP_DENYWRITE));
	if (sydbox->seccomp_action != SCMP_ACT_ERRNO(EPERM))
		syd_rule_add_return(sydbox->ctx, SCMP_ACT_ERRNO(EPERM),
				    sys_mmap, 0);
	return 0;
}

int filter_mmap(void)
{
	if (sydbox->config.restrict_shm_wr)
		return filter_mmap_restrict_shared(SCMP_SYS(mmap));
	else if (sydbox->config.restrict_mmap)
		return filter_mmap_restrict(SCMP_SYS(mmap));
	else
		return 0;
}

int filter_mmap2(void)
{
	if (sydbox->config.restrict_shm_wr)
		return filter_mmap_restrict_shared(SCMP_SYS(mmap2));
	else if (sydbox->config.restrict_mmap)
		return filter_mmap_restrict(SCMP_SYS(mmap2));
	else
		return 0;
}

int filter_mprotect(void)
{
	int r;
	uint32_t action;

	action = SCMP_ACT_ALLOW;
	if (action == sydbox->seccomp_action)
		return 0;

	if (sydbox->config.restrict_mmap) {
		r = seccomp_rule_add(sydbox->ctx, action,
				     SCMP_SYS(mprotect), 1,
				     SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ));
		if (!r) {
			r = seccomp_rule_add(sydbox->ctx, action,
					     SCMP_SYS(mprotect), 1,
					     SCMP_CMP(2, SCMP_CMP_EQ,
						      PROT_READ|PROT_WRITE));
		}
	} else {
		r = seccomp_rule_add(sydbox->ctx, action,
				     SCMP_SYS(mprotect), 0);
	}
	return r == -EEXIST ? 0 : r;
}

int filter_ioctl(void)
{
	static const unsigned long request[] = {
		TCGETS,
		TIOCGLCKTRMIOS,
		TIOCGWINSZ,
		TIOCSWINSZ,
		FIONREAD,
		TIOCINQ,
		TIOCOUTQ,
		TCFLSH,
		TIOCSTI,
		TIOCSCTTY,
		TIOCNOTTY,
		TIOCGPGRP,
		TIOCSPGRP,
		TIOCGSID,
		TIOCEXCL,
		TIOCGEXCL,
		TIOCNXCL,
		TIOCGETD,
		TIOCSETD,
		TIOCPKT,
		TIOCGPKT,
		TIOCSPTLCK,
		TIOCGPTLCK,
		TIOCGPTPEER,
		TIOCGSOFTCAR,
		TIOCSSOFTCAR,
		KDGETLED,
		KDSETLED,
		KDGKBLED,
		KDSKBLED,
		KDGKBTYPE,
		KDGETMODE,
		KDSETMODE,
		KDMKTONE,
		KIOCSOUND,
		GIO_CMAP,
		PIO_CMAP,
		GIO_FONT,
		PIO_FONT,
		GIO_FONTX,
		PIO_FONTX,
		PIO_FONTRESET,
		GIO_SCRNMAP,
		PIO_SCRNMAP,
		GIO_UNISCRNMAP,
		PIO_UNISCRNMAP,
		GIO_UNIMAP,
		PIO_UNIMAP,
		PIO_UNIMAPCLR,
		KDGKBMODE,
		KDSKBMODE,
		KDGKBMETA,
		KDSKBMETA,
		KDGKBENT,
		KDSKBENT,
		KDGKBSENT,
		KDSKBSENT,
		KDGKBDIACR,
		KDGETKEYCODE,
		KDSETKEYCODE,
		KDSIGACCEPT,
		VT_OPENQRY,
		VT_GETMODE,
		VT_SETMODE,
		VT_GETSTATE,
		VT_RELDISP,
		VT_ACTIVATE,
		VT_WAITACTIVE,
		VT_DISALLOCATE,
		VT_RESIZE,
		VT_RESIZEX,
	};

	if (sydbox->seccomp_action != SCMP_ACT_ALLOW)
		for (unsigned short i = 0; i < ELEMENTSOF(request); i++)
			syd_rule_add_return(sydbox->ctx, SCMP_ACT_ALLOW,
						  SCMP_SYS(ioctl), 1,
						  SCMP_CMP(1, SCMP_CMP_EQ,
							   request[i]));
	if (sydbox->config.restrict_ioctl &&
	    sydbox->seccomp_action != SCMP_ACT_ERRNO(EPERM))
		syd_rule_add_return(sydbox->ctx,
				    SCMP_ACT_ERRNO(EPERM),
				    SCMP_SYS(ioctl), 0);
	return 0;
}

const int open_readonly_flags[OPEN_READONLY_FLAG_MAX] = {
	O_RDONLY, /* 0 */
	O_CLOEXEC,
	O_DIRECTORY,
	O_LARGEFILE,
	O_NONBLOCK,
	O_PATH,
	O_SYNC,
	O_ASYNC,
	O_NOCTTY,
	O_NOATIME,
	O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY,
	O_CLOEXEC|O_LARGEFILE,
	O_CLOEXEC|O_NONBLOCK,
	O_CLOEXEC|O_PATH,
	O_CLOEXEC|O_SYNC,
	O_CLOEXEC|O_ASYNC,
	O_CLOEXEC|O_NOCTTY,
	O_CLOEXEC|O_NOATIME,
	O_CLOEXEC|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE,
	O_DIRECTORY|O_NONBLOCK,
	O_DIRECTORY|O_PATH,
	O_DIRECTORY|O_SYNC,
	O_DIRECTORY|O_ASYNC,
	O_DIRECTORY|O_NOCTTY,
	O_DIRECTORY|O_NOATIME,
	O_DIRECTORY|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK,
	O_LARGEFILE|O_PATH,
	O_LARGEFILE|O_SYNC,
	O_LARGEFILE|O_ASYNC,
	O_LARGEFILE|O_NOCTTY,
	O_LARGEFILE|O_NOATIME,
	O_LARGEFILE|O_NOFOLLOW,
	O_NONBLOCK|O_PATH,
	O_NONBLOCK|O_SYNC,
	O_NONBLOCK|O_ASYNC,
	O_NONBLOCK|O_NOCTTY,
	O_NONBLOCK|O_NOATIME,
	O_NONBLOCK|O_NOFOLLOW,
	O_PATH|O_SYNC,
	O_PATH|O_ASYNC,
	O_PATH|O_NOCTTY,
	O_PATH|O_NOATIME,
	O_PATH|O_NOFOLLOW,
	O_SYNC|O_ASYNC,
	O_SYNC|O_NOCTTY,
	O_SYNC|O_NOATIME,
	O_SYNC|O_NOFOLLOW,
	O_ASYNC|O_NOCTTY,
	O_ASYNC|O_NOATIME,
	O_ASYNC|O_NOFOLLOW,
	O_NOCTTY|O_NOATIME,
	O_NOCTTY|O_NOFOLLOW,
	O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK,
	O_CLOEXEC|O_DIRECTORY|O_PATH,
	O_CLOEXEC|O_DIRECTORY|O_SYNC,
	O_CLOEXEC|O_DIRECTORY|O_ASYNC,
	O_CLOEXEC|O_DIRECTORY|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK,
	O_CLOEXEC|O_LARGEFILE|O_PATH,
	O_CLOEXEC|O_LARGEFILE|O_SYNC,
	O_CLOEXEC|O_LARGEFILE|O_ASYNC,
	O_CLOEXEC|O_LARGEFILE|O_NOCTTY,
	O_CLOEXEC|O_LARGEFILE|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_PATH,
	O_CLOEXEC|O_NONBLOCK|O_SYNC,
	O_CLOEXEC|O_NONBLOCK|O_ASYNC,
	O_CLOEXEC|O_NONBLOCK|O_NOCTTY,
	O_CLOEXEC|O_NONBLOCK|O_NOATIME,
	O_CLOEXEC|O_NONBLOCK|O_NOFOLLOW,
	O_CLOEXEC|O_PATH|O_SYNC,
	O_CLOEXEC|O_PATH|O_ASYNC,
	O_CLOEXEC|O_PATH|O_NOCTTY,
	O_CLOEXEC|O_PATH|O_NOATIME,
	O_CLOEXEC|O_PATH|O_NOFOLLOW,
	O_CLOEXEC|O_SYNC|O_ASYNC,
	O_CLOEXEC|O_SYNC|O_NOCTTY,
	O_CLOEXEC|O_SYNC|O_NOATIME,
	O_CLOEXEC|O_SYNC|O_NOFOLLOW,
	O_CLOEXEC|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK,
	O_DIRECTORY|O_LARGEFILE|O_PATH,
	O_DIRECTORY|O_LARGEFILE|O_SYNC,
	O_DIRECTORY|O_LARGEFILE|O_ASYNC,
	O_DIRECTORY|O_LARGEFILE|O_NOCTTY,
	O_DIRECTORY|O_LARGEFILE|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_PATH,
	O_DIRECTORY|O_NONBLOCK|O_SYNC,
	O_DIRECTORY|O_NONBLOCK|O_ASYNC,
	O_DIRECTORY|O_NONBLOCK|O_NOCTTY,
	O_DIRECTORY|O_NONBLOCK|O_NOATIME,
	O_DIRECTORY|O_NONBLOCK|O_NOFOLLOW,
	O_DIRECTORY|O_PATH|O_SYNC,
	O_DIRECTORY|O_PATH|O_ASYNC,
	O_DIRECTORY|O_PATH|O_NOCTTY,
	O_DIRECTORY|O_PATH|O_NOATIME,
	O_DIRECTORY|O_PATH|O_NOFOLLOW,
	O_DIRECTORY|O_SYNC|O_ASYNC,
	O_DIRECTORY|O_SYNC|O_NOCTTY,
	O_DIRECTORY|O_SYNC|O_NOATIME,
	O_DIRECTORY|O_SYNC|O_NOFOLLOW,
	O_DIRECTORY|O_ASYNC|O_NOCTTY,
	O_DIRECTORY|O_ASYNC|O_NOATIME,
	O_DIRECTORY|O_ASYNC|O_NOFOLLOW,
	O_DIRECTORY|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_PATH,
	O_LARGEFILE|O_NONBLOCK|O_SYNC,
	O_LARGEFILE|O_NONBLOCK|O_ASYNC,
	O_LARGEFILE|O_NONBLOCK|O_NOCTTY,
	O_LARGEFILE|O_NONBLOCK|O_NOATIME,
	O_LARGEFILE|O_NONBLOCK|O_NOFOLLOW,
	O_LARGEFILE|O_PATH|O_SYNC,
	O_LARGEFILE|O_PATH|O_ASYNC,
	O_LARGEFILE|O_PATH|O_NOCTTY,
	O_LARGEFILE|O_PATH|O_NOATIME,
	O_LARGEFILE|O_PATH|O_NOFOLLOW,
	O_LARGEFILE|O_SYNC|O_ASYNC,
	O_LARGEFILE|O_SYNC|O_NOCTTY,
	O_LARGEFILE|O_SYNC|O_NOATIME,
	O_LARGEFILE|O_SYNC|O_NOFOLLOW,
	O_LARGEFILE|O_ASYNC|O_NOCTTY,
	O_LARGEFILE|O_ASYNC|O_NOATIME,
	O_LARGEFILE|O_ASYNC|O_NOFOLLOW,
	O_LARGEFILE|O_NOCTTY|O_NOATIME,
	O_LARGEFILE|O_NOCTTY|O_NOFOLLOW,
	O_LARGEFILE|O_NOATIME|O_NOFOLLOW,
	O_NONBLOCK|O_PATH|O_SYNC,
	O_NONBLOCK|O_PATH|O_ASYNC,
	O_NONBLOCK|O_PATH|O_NOCTTY,
	O_NONBLOCK|O_PATH|O_NOATIME,
	O_NONBLOCK|O_PATH|O_NOFOLLOW,
	O_NONBLOCK|O_SYNC|O_ASYNC,
	O_NONBLOCK|O_SYNC|O_NOCTTY,
	O_NONBLOCK|O_SYNC|O_NOATIME,
	O_NONBLOCK|O_SYNC|O_NOFOLLOW,
	O_NONBLOCK|O_ASYNC|O_NOCTTY,
	O_NONBLOCK|O_ASYNC|O_NOATIME,
	O_NONBLOCK|O_ASYNC|O_NOFOLLOW,
	O_NONBLOCK|O_NOCTTY|O_NOATIME,
	O_NONBLOCK|O_NOCTTY|O_NOFOLLOW,
	O_NONBLOCK|O_NOATIME|O_NOFOLLOW,
	O_PATH|O_SYNC|O_ASYNC,
	O_PATH|O_SYNC|O_NOCTTY,
	O_PATH|O_SYNC|O_NOATIME,
	O_PATH|O_SYNC|O_NOFOLLOW,
	O_PATH|O_ASYNC|O_NOCTTY,
	O_PATH|O_ASYNC|O_NOATIME,
	O_PATH|O_ASYNC|O_NOFOLLOW,
	O_PATH|O_NOCTTY|O_NOATIME,
	O_PATH|O_NOCTTY|O_NOFOLLOW,
	O_PATH|O_NOATIME|O_NOFOLLOW,
	O_SYNC|O_ASYNC|O_NOCTTY,
	O_SYNC|O_ASYNC|O_NOATIME,
	O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_SYNC|O_NOCTTY|O_NOATIME,
	O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_ASYNC|O_NOCTTY|O_NOATIME,
	O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_SYNC,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_ASYNC,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_SYNC,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_ASYNC,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_SYNC,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_ASYNC,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_SYNC|O_ASYNC,
	O_CLOEXEC|O_DIRECTORY|O_SYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_SYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_SYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_SYNC,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_ASYNC,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_NOCTTY,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_SYNC,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_ASYNC,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_NOCTTY,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_SYNC|O_ASYNC,
	O_CLOEXEC|O_LARGEFILE|O_SYNC|O_NOCTTY,
	O_CLOEXEC|O_LARGEFILE|O_SYNC|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_SYNC|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_LARGEFILE|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_SYNC,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_ASYNC,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_NOCTTY,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_NOATIME,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_SYNC|O_ASYNC,
	O_CLOEXEC|O_NONBLOCK|O_SYNC|O_NOCTTY,
	O_CLOEXEC|O_NONBLOCK|O_SYNC|O_NOATIME,
	O_CLOEXEC|O_NONBLOCK|O_SYNC|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_NONBLOCK|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_NONBLOCK|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_NONBLOCK|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_PATH|O_SYNC|O_ASYNC,
	O_CLOEXEC|O_PATH|O_SYNC|O_NOCTTY,
	O_CLOEXEC|O_PATH|O_SYNC|O_NOATIME,
	O_CLOEXEC|O_PATH|O_SYNC|O_NOFOLLOW,
	O_CLOEXEC|O_PATH|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_PATH|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_PATH|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_PATH|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_PATH|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_PATH|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_SYNC|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_SYNC|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_SYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_ASYNC,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_NOCTTY,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_ASYNC,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_NOCTTY,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_SYNC|O_ASYNC,
	O_DIRECTORY|O_LARGEFILE|O_SYNC|O_NOCTTY,
	O_DIRECTORY|O_LARGEFILE|O_SYNC|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_SYNC|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_ASYNC|O_NOCTTY,
	O_DIRECTORY|O_LARGEFILE|O_ASYNC|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_ASYNC|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_ASYNC,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_NOCTTY,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_NOATIME,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_SYNC|O_ASYNC,
	O_DIRECTORY|O_NONBLOCK|O_SYNC|O_NOCTTY,
	O_DIRECTORY|O_NONBLOCK|O_SYNC|O_NOATIME,
	O_DIRECTORY|O_NONBLOCK|O_SYNC|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_ASYNC|O_NOCTTY,
	O_DIRECTORY|O_NONBLOCK|O_ASYNC|O_NOATIME,
	O_DIRECTORY|O_NONBLOCK|O_ASYNC|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_NONBLOCK|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_PATH|O_SYNC|O_ASYNC,
	O_DIRECTORY|O_PATH|O_SYNC|O_NOCTTY,
	O_DIRECTORY|O_PATH|O_SYNC|O_NOATIME,
	O_DIRECTORY|O_PATH|O_SYNC|O_NOFOLLOW,
	O_DIRECTORY|O_PATH|O_ASYNC|O_NOCTTY,
	O_DIRECTORY|O_PATH|O_ASYNC|O_NOATIME,
	O_DIRECTORY|O_PATH|O_ASYNC|O_NOFOLLOW,
	O_DIRECTORY|O_PATH|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_PATH|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_PATH|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_SYNC|O_ASYNC|O_NOCTTY,
	O_DIRECTORY|O_SYNC|O_ASYNC|O_NOATIME,
	O_DIRECTORY|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_DIRECTORY|O_SYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOCTTY,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOATIME,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC,
	O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOCTTY,
	O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOATIME,
	O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOCTTY,
	O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOATIME,
	O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_NOCTTY|O_NOATIME,
	O_LARGEFILE|O_NONBLOCK|O_NOCTTY|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC,
	O_LARGEFILE|O_PATH|O_SYNC|O_NOCTTY,
	O_LARGEFILE|O_PATH|O_SYNC|O_NOATIME,
	O_LARGEFILE|O_PATH|O_SYNC|O_NOFOLLOW,
	O_LARGEFILE|O_PATH|O_ASYNC|O_NOCTTY,
	O_LARGEFILE|O_PATH|O_ASYNC|O_NOATIME,
	O_LARGEFILE|O_PATH|O_ASYNC|O_NOFOLLOW,
	O_LARGEFILE|O_PATH|O_NOCTTY|O_NOATIME,
	O_LARGEFILE|O_PATH|O_NOCTTY|O_NOFOLLOW,
	O_LARGEFILE|O_PATH|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_SYNC|O_ASYNC|O_NOCTTY,
	O_LARGEFILE|O_SYNC|O_ASYNC|O_NOATIME,
	O_LARGEFILE|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_LARGEFILE|O_SYNC|O_NOCTTY|O_NOATIME,
	O_LARGEFILE|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_LARGEFILE|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_LARGEFILE|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_LARGEFILE|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC,
	O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY,
	O_NONBLOCK|O_PATH|O_SYNC|O_NOATIME,
	O_NONBLOCK|O_PATH|O_SYNC|O_NOFOLLOW,
	O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY,
	O_NONBLOCK|O_PATH|O_ASYNC|O_NOATIME,
	O_NONBLOCK|O_PATH|O_ASYNC|O_NOFOLLOW,
	O_NONBLOCK|O_PATH|O_NOCTTY|O_NOATIME,
	O_NONBLOCK|O_PATH|O_NOCTTY|O_NOFOLLOW,
	O_NONBLOCK|O_PATH|O_NOATIME|O_NOFOLLOW,
	O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY,
	O_NONBLOCK|O_SYNC|O_ASYNC|O_NOATIME,
	O_NONBLOCK|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOATIME,
	O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_NONBLOCK|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_NONBLOCK|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_NONBLOCK|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_PATH|O_SYNC|O_ASYNC|O_NOCTTY,
	O_PATH|O_SYNC|O_ASYNC|O_NOATIME,
	O_PATH|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_PATH|O_SYNC|O_NOCTTY|O_NOATIME,
	O_PATH|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_PATH|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_PATH|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_PATH|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_PATH|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_ASYNC,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_ASYNC,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_SYNC|O_ASYNC,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_SYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_SYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_SYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_ASYNC,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_SYNC|O_ASYNC,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_SYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_SYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_SYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_SYNC|O_ASYNC,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_SYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_SYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_SYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_SYNC|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_SYNC|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_SYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOCTTY,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOCTTY,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_SYNC|O_NOCTTY,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_SYNC|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_SYNC|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_SYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_SYNC|O_NOATIME,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_SYNC|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_PATH|O_SYNC|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_PATH|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_PATH|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_PATH|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_PATH|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_PATH|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_PATH|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOCTTY,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOCTTY,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOCTTY,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_NOCTTY,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_ASYNC|O_NOCTTY,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_ASYNC|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_ASYNC|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOCTTY,
	O_DIRECTORY|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_SYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_NOATIME,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_ASYNC|O_NOATIME,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_ASYNC|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY,
	O_DIRECTORY|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOATIME,
	O_DIRECTORY|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY,
	O_DIRECTORY|O_PATH|O_SYNC|O_ASYNC|O_NOATIME,
	O_DIRECTORY|O_PATH|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_DIRECTORY|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_PATH|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_PATH|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_PATH|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_PATH|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_PATH|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOATIME,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOATIME,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOATIME,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY,
	O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOATIME,
	O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOATIME,
	O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY,
	O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOATIME,
	O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_LARGEFILE|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME,
	O_LARGEFILE|O_PATH|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_LARGEFILE|O_PATH|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_LARGEFILE|O_PATH|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_LARGEFILE|O_PATH|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_PATH|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_LARGEFILE|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_LARGEFILE|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY,
	O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOATIME,
	O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME,
	O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_NONBLOCK|O_PATH|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_NONBLOCK|O_PATH|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_NONBLOCK|O_PATH|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_NONBLOCK|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_PATH|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_PATH|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_SYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_SYNC|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_PATH|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOATIME,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_PATH|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOATIME,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
	O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_NOCTTY|O_NOATIME|O_NOFOLLOW,
};
