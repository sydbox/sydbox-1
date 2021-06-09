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
#include <stdint.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#if SYDBOX_HAVE_SECCOMP
# include "seccomp_old.h"
#endif

static int filter_gen_level1[] = {
	SCMP_SYS(read),
	SCMP_SYS(write),
	SCMP_SYS(exit),
	SCMP_SYS(exit_group),
	SCMP_SYS(sigreturn),
	SCMP_SYS(stat),
	SCMP_SYS(lstat),
#ifdef __NR_newfstatat
	SCMP_SYS(newfstatat),
#endif
	SCMP_SYS(execve),
#ifdef __NR_execveat
	SCMP_SYS(execveat),
#endif
	SCMP_SYS(arch_prctl),
	SCMP_SYS(set_tid_address),
};

static int filter_gen_level2[] = {
	SCMP_SYS(arch_prctl),
	SCMP_SYS(access),
	SCMP_SYS(brk),
	SCMP_SYS(clock_gettime),
	SCMP_SYS(close),
	SCMP_SYS(clone),
	SCMP_SYS(dup),
	SCMP_SYS(epoll_create),
	SCMP_SYS(epoll_wait),
#ifdef __NR_epoll_pwait
	SCMP_SYS(epoll_pwait),
#endif
	SCMP_SYS(execve),
#ifdef __NR_execveat
	SCMP_SYS(execveat),
	SCMP_SYS(exit),
	SCMP_SYS(exit_group),
#endif
#ifdef HAVE_EVENTFD
	SCMP_SYS(eventfd2),
#endif
#ifdef HAVE_PIPE2
	SCMP_SYS(pipe2),
#endif
#ifdef HAVE_PIPE
	SCMP_SYS(pipe),
#endif
#ifdef __NR_fchmod
	SCMP_SYS(fchmod),
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
	SCMP_SYS(mkdir),
	SCMP_SYS(mlockall),
#ifdef __NR_mmap
	SCMP_SYS(mmap),
#endif
	SCMP_SYS(munmap),
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
#ifdef __NR_prlimit
	SCMP_SYS(prlimit),
#endif
#ifdef __NR_prlimit64
	SCMP_SYS(prlimit64),
#endif
	SCMP_SYS(pselect6),
	SCMP_SYS(read),
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
	SCMP_SYS(writev),
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
	SCMP_SYS(unlink),
#ifdef __NR_unlinkat
	SCMP_SYS(unlinkat),
#endif
	SCMP_SYS(poll)
};

static int filter_gen_level3[] = {
	SCMP_SYS(arch_prctl),
	SCMP_SYS(access),
	SCMP_SYS(brk),
	SCMP_SYS(clock_gettime),
	SCMP_SYS(close),
	SCMP_SYS(clone),
	SCMP_SYS(dup),
	SCMP_SYS(epoll_create),
	SCMP_SYS(epoll_wait),
#ifdef __NR_epoll_pwait
	SCMP_SYS(epoll_pwait),
#endif
	SCMP_SYS(execve),
#ifdef __NR_execveat
	SCMP_SYS(execveat),
	SCMP_SYS(exit),
	SCMP_SYS(exit_group),
#endif
#ifdef HAVE_EVENTFD
	SCMP_SYS(eventfd2),
#endif
#ifdef HAVE_PIPE2
	SCMP_SYS(pipe2),
#endif
#ifdef HAVE_PIPE
	SCMP_SYS(pipe),
#endif
#ifdef __NR_fchmod
	SCMP_SYS(fchmod),
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
	SCMP_SYS(mkdir),
	SCMP_SYS(mlockall),
#ifdef __NR_mmap
	SCMP_SYS(mmap),
#endif
	SCMP_SYS(munmap),
#ifdef __NR_nanosleep
	SCMP_SYS(nanosleep),
#endif
#ifdef __NR_prlimit
	SCMP_SYS(prlimit),
#endif
#ifdef __NR_prlimit64
	SCMP_SYS(prlimit64),
#endif
	SCMP_SYS(pselect6),
	SCMP_SYS(read),
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
	SCMP_SYS(writev),
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
	SCMP_SYS(unlink),
#ifdef __NR_unlinkat
	SCMP_SYS(unlinkat),
#endif
	SCMP_SYS(poll)
};

const int open_readonly_flags[OPEN_READONLY_FLAG_MAX] = {
	O_RDONLY,
	O_CLOEXEC,
	O_DIRECTORY,
	O_LARGEFILE,
	O_NONBLOCK,
	O_PATH,
	O_SYNC,
	O_ASYNC,
	O_DIRECT,

	O_RDONLY|O_CLOEXEC,
	O_RDONLY|O_DIRECTORY,
	O_RDONLY|O_LARGEFILE,
	O_RDONLY|O_NONBLOCK,
	O_RDONLY|O_PATH,
	O_RDONLY|O_SYNC,
	O_RDONLY|O_ASYNC,
	O_RDONLY|O_DIRECT,

	O_RDONLY|O_CLOEXEC|O_DIRECTORY,
	O_RDONLY|O_CLOEXEC|O_LARGEFILE,
	O_RDONLY|O_CLOEXEC|O_NONBLOCK,
	O_RDONLY|O_CLOEXEC|O_PATH,
	O_RDONLY|O_CLOEXEC|O_SYNC,
	O_RDONLY|O_CLOEXEC|O_ASYNC,
	O_RDONLY|O_CLOEXEC|O_DIRECT,

	O_RDONLY|O_DIRECTORY|O_LARGEFILE,
	O_RDONLY|O_DIRECTORY|O_NONBLOCK,
	O_RDONLY|O_DIRECTORY|O_PATH,
	O_RDONLY|O_DIRECTORY|O_SYNC,
	O_RDONLY|O_DIRECTORY|O_ASYNC,
	O_RDONLY|O_DIRECTORY|O_DIRECT,

	O_RDONLY|O_LARGEFILE|O_NONBLOCK,
	O_RDONLY|O_LARGEFILE|O_PATH,
	O_RDONLY|O_LARGEFILE|O_SYNC,
	O_RDONLY|O_LARGEFILE|O_ASYNC,
	O_RDONLY|O_LARGEFILE|O_DIRECT,

	O_RDONLY|O_NONBLOCK|O_PATH,
	O_RDONLY|O_NONBLOCK|O_SYNC,
	O_RDONLY|O_NONBLOCK|O_ASYNC,
	O_RDONLY|O_NONBLOCK|O_DIRECT,

	O_RDONLY|O_PATH|O_SYNC,
	O_RDONLY|O_PATH|O_ASYNC,
	O_RDONLY|O_PATH|O_DIRECT,

	O_RDONLY|O_SYNC|O_ASYNC,
	O_RDONLY|O_SYNC|O_DIRECT,

	O_RDONLY|O_ASYNC|O_DIRECT,

	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_LARGEFILE,
	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NONBLOCK,
	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_PATH,
	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_SYNC,
	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_ASYNC,
	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_DIRECT,

	O_RDONLY|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK,
	O_RDONLY|O_DIRECTORY|O_LARGEFILE|O_PATH,
	O_RDONLY|O_DIRECTORY|O_LARGEFILE|O_SYNC,
	O_RDONLY|O_DIRECTORY|O_LARGEFILE|O_ASYNC,
	O_RDONLY|O_DIRECTORY|O_LARGEFILE|O_DIRECT,

	O_RDONLY|O_LARGEFILE|O_PATH|O_NONBLOCK,
	O_RDONLY|O_LARGEFILE|O_PATH|O_SYNC,
	O_RDONLY|O_LARGEFILE|O_PATH|O_ASYNC,
	O_RDONLY|O_LARGEFILE|O_PATH|O_DIRECT,

	O_RDONLY|O_PATH|O_NONBLOCK|O_SYNC,
	O_RDONLY|O_PATH|O_NONBLOCK|O_ASYNC,
	O_RDONLY|O_PATH|O_NONBLOCK|O_DIRECT,

	O_RDONLY|O_PATH|O_ASYNC|O_SYNC,
	O_RDONLY|O_PATH|O_ASYNC|O_DIRECT,

	O_RDONLY|O_ASYNC|O_SYNC|O_DIRECT,

	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK,
	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH,
	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_SYNC,
	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_ASYNC,
	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_DIRECT,

	O_RDONLY|O_DIRECTORY|O_LARGEFILE|O_PATH|O_NONBLOCK,
	O_RDONLY|O_DIRECTORY|O_LARGEFILE|O_PATH|O_SYNC,
	O_RDONLY|O_DIRECTORY|O_LARGEFILE|O_PATH|O_ASYNC,
	O_RDONLY|O_DIRECTORY|O_LARGEFILE|O_PATH|O_DIRECT,

	O_RDONLY|O_LARGEFILE|O_PATH|O_NONBLOCK|O_SYNC,
	O_RDONLY|O_LARGEFILE|O_PATH|O_NONBLOCK|O_ASYNC,
	O_RDONLY|O_LARGEFILE|O_PATH|O_NONBLOCK|O_DIRECT,

	O_RDONLY|O_PATH|O_NONBLOCK|O_SYNC|O_ASYNC,
	O_RDONLY|O_PATH|O_NONBLOCK|O_SYNC|O_DIRECT,

	O_RDONLY|O_NONBLOCK|O_SYNC|O_ASYNC|O_DIRECT,

	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH,
	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_SYNC,
	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_ASYNC,
	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_DIRECT,

	O_RDONLY|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC,
	O_RDONLY|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC,
	O_RDONLY|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_DIRECT,

	O_RDONLY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC,
	O_RDONLY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_DIRECT,

	O_RDONLY|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC|O_DIRECT,

	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC,
	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_ASYNC,
	O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_DIRECT,

	O_RDONLY|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_ASYNC,
	O_RDONLY|O_DIRECTORY|O_LARGEFILE|O_NONBLOCK|O_PATH|O_SYNC|O_DIRECT,
};

static int filter_open_readonly()
{
	int r;
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
		r = seccomp_rule_add(sydbox->ctx, action,
				     SCMP_SYS(open), 1,
				     SCMP_A1( SCMP_CMP_EQ,
					      open_readonly_flags[i],
					      open_readonly_flags[i] ));
		if (r < 0)
			return r;
		r = seccomp_rule_add(sydbox->ctx, action,
				     SCMP_SYS(openat), 1,
				     SCMP_A2( SCMP_CMP_EQ,
					      open_readonly_flags[i],
					      open_readonly_flags[i] ));
		if (r < 0)
			return r;
	}

	return 0;
}

static int filter_time(void)
{
	int r;
	uint32_t action = SCMP_ACT_ALLOW;

	if (action == sydbox->seccomp_action)
		return 0;

	if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ALLOW,
				  SCMP_SYS(time), 1,
				  SCMP_CMP(0, SCMP_CMP_EQ, 0))) < 0)
		return r;

	return 0;
}

static int filter_rt_sigaction(void)
{
	int r;
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
		if ((r = seccomp_rule_add(sydbox->ctx, action,
					  SCMP_SYS(rt_sigaction), 1,
					  SCMP_CMP(0, SCMP_CMP_EQ, param[i]))) < 0)
			return r;
	}

	return 0;
}

static int filter_general_level_1(void)
{
	int r;

	for (unsigned i = 0; i < ELEMENTSOF(filter_gen_level1); i++) {
		if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ALLOW,
					  filter_gen_level1[i], 0))) {
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
					  filter_gen_level2[i], 0))) {
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
	if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ALLOW,
				  SCMP_SYS(newfstatat), 0)))
		return r;
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
					  filter_gen_level3[i], 0))) {
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
	if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ALLOW,
				  SCMP_SYS(newfstatat), 0)))
		return r;
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
	int r;
	if (sydbox->seccomp_action != SCMP_ACT_ALLOW) {
		int allow_calls[] = {
			SCMP_SYS(exit),
			SCMP_SYS(exit_group),
			SCMP_SYS(arch_prctl),
			SCMP_SYS(membarrier),
			SCMP_SYS(set_tid_address),
			SCMP_SYS(rt_sigprocmask),
		};
		for (unsigned int i = 0; i < ELEMENTSOF(allow_calls); i++)
			if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ALLOW,
						  allow_calls[i], 0)) < 0)
				return r;
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

int filter_open(void)
{
	int r;
	uint32_t action;

	if (!sydbox->config.restrict_fcntl)
		return 0;

	action = SCMP_ACT_ERRNO(EPERM);
	if (action == sydbox->seccomp_action)
		return 0;

	/* O_ASYNC */
	r = seccomp_rule_add(sydbox->ctx, action, SCMP_SYS(open),
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ, O_ASYNC, O_ASYNC ));
	if (r < 0)
		return r;

	/* O_DIRECT */
	r = seccomp_rule_add(sydbox->ctx, action, SCMP_SYS(open),
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ, O_DIRECT, O_DIRECT ));
	if (r < 0)
		return r;

	/* O_SYNC */
	r = seccomp_rule_add(sydbox->ctx, action, SCMP_SYS(open),
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ, O_SYNC, O_SYNC ));
	if (r < 0)
		return r;

	return 0;
}

int filter_openat(void)
{
	int r;

	if (!sydbox->config.restrict_fcntl)
		return 0;

	/* O_ASYNC */
	r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EINVAL), SCMP_SYS(openat),
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ, O_ASYNC, O_ASYNC ));
	if (r < 0)
		return r;

	/* O_DIRECT */
	r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EINVAL), SCMP_SYS(openat),
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ, O_DIRECT, O_DIRECT ));
	if (r < 0)
		return r;

	/* O_SYNC */
	r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EINVAL), SCMP_SYS(openat),
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ, O_SYNC, O_SYNC ));
	if (r < 0)
		return r;

	return 0;
}

int filter_fcntl(void)
{
	int r;

	if (!sydbox->config.restrict_fcntl)
		return 0;

	r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fcntl),
			     2,
			     SCMP_A1( SCMP_CMP_EQ, F_SETFL, F_SETFL),
			     SCMP_A2( SCMP_CMP_MASKED_EQ, O_ASYNC, O_ASYNC));
	if (r < 0)
		return r;
	r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fcntl),
			     2,
			     SCMP_A1( SCMP_CMP_EQ, F_SETFL, F_SETFL),
			     SCMP_A2( SCMP_CMP_MASKED_EQ, O_DIRECT, O_DIRECT));
	if (r < 0)
		return r;

#if 0
#define FCNTL_OK_MAX 11
	int ok[FCNTL_OK_MAX] = { F_GETFL, F_SETFL, F_SETOWN, F_SETLK, F_SETLKW,
		F_SETLK64, F_SETLKW64, F_GETFD, F_SETFD, F_DUPFD, F_DUPFD_CLOEXEC };
	r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fcntl),
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ,
	for (unsigned short i = 0; i < FCNTL_OK_MAX; i++) {
		if (r < 0)
			return r;
	}
#endif
	return 0;
}

static int filter_mmap_restrict_shared(int sys_mmap)
{
	int r;

	if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM),
				  sys_mmap, 2,
				  SCMP_A2( SCMP_CMP_MASKED_EQ,
					   PROT_WRITE, PROT_WRITE ),
				  SCMP_A3( SCMP_CMP_MASKED_EQ,
					   MAP_SHARED, MAP_SHARED ))))
		return r;

	return 0;
}

static int filter_mmap_restrict(int sys_mmap)
{
	int r;
	uint32_t action = SCMP_ACT_ALLOW;

	if (action == sydbox->seccomp_action)
		return 0;

	if ((r = seccomp_rule_add(sydbox->ctx, action,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ),
				  SCMP_CMP(3, SCMP_CMP_EQ, MAP_PRIVATE))))
		return r;
	if ((r = seccomp_rule_add(sydbox->ctx, action,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ, PROT_NONE),
				  SCMP_CMP(3, SCMP_CMP_EQ, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE))))
		return r;
	if ((r = seccomp_rule_add(sydbox->ctx, action,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ,
					   PROT_READ|PROT_WRITE),
				  SCMP_CMP(3, SCMP_CMP_EQ, MAP_PRIVATE|MAP_ANONYMOUS))))
		return r;
	if ((r = seccomp_rule_add(sydbox->ctx, action,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ,
					   PROT_READ|PROT_WRITE),
				  SCMP_CMP(3, SCMP_CMP_EQ,MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK))))
		return r;
	if ((r = seccomp_rule_add(sydbox->ctx, action,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ|PROT_WRITE),
				  SCMP_CMP(3, SCMP_CMP_EQ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE))))
		return r;
	if ((r = seccomp_rule_add(sydbox->ctx, action,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ,
					   PROT_READ|PROT_WRITE),
				  SCMP_CMP(3, SCMP_CMP_EQ,
					   MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS))))
		return r;
	if ((r = seccomp_rule_add(sydbox->ctx, action,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ|PROT_EXEC),
				  SCMP_CMP(3, SCMP_CMP_EQ,
					   MAP_PRIVATE|MAP_DENYWRITE))))
		return r;
	if (sydbox->seccomp_action != SCMP_ACT_ERRNO(EPERM))
		if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM),
					  sys_mmap, 0)))
			return r;
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
		return filter_mmap_restrict_shared(SCMP_SYS(mmap));
	else if (sydbox->config.restrict_mmap)
		return filter_mmap_restrict(SCMP_SYS(mmap));
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
	return r;
}

int filter_ioctl(void)
{
	int r;
	uint32_t action;

	if (!sydbox->config.restrict_ioctl)
		return 0;

	action = SCMP_ACT_ALLOW;
	if (action == sydbox->seccomp_action)
		return 0;

	unsigned long request[] = {
		TCGETS,
		TIOCGWINSZ,
		TIOCGPGRP,
		TIOCSPGRP,
	};
	for (unsigned short i = 0; i < ELEMENTSOF(request); i++)
		if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ALLOW,
					  SCMP_SYS(ioctl), 1,
					  SCMP_CMP(1, SCMP_CMP_EQ,
						   request[i]))) < 0)
			return r;

	return 0;
}
