/*
 * sydbox/pink.c
 *
 * pinktrace wrapper functions
 *
 * Copyright (c) 2013, 2014, 2015, 2018 Ali Polatel <alip@exherbo.org>
 * Based in part upon strace which is:
 *   Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 *   Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 *   Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 *   Copyright (c) 1996-2000 Wichert Akkerman <wichert@cistron.nl>
 *   Copyright (c) 2005-2016 Dmitry V. Levin <ldv@strace.io>
 *   Copyright (c) 2016-2021 The strace developers.
 * All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"
#include "bsd-compat.h"
#include "compiler.h"
#include "pink.h"
#include "syd.h"
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

/* For definitions of struct msghdr and struct mmsghdr. */
#include <sys/socket.h>
/* UNIX_PATH_MAX */
#include <sys/un.h>
#define sockaddr_un sockaddr_un_tmp
#include <linux/un.h>
#undef sockaddr_un

#ifndef HAVE_STRUCT_MMSGHDR
struct mmsghdr {
	struct msghdr msg_hdr;
	unsigned msg_len;
};
#endif
typedef struct msghdr struct_msghdr;

#define SYD_RETURN_IF_DETACHED(current) do { \
	if (current->flags & SYD_DETACHED) { \
		return 0; \
	}} while (0)

#if HAVE_PROCESS_VM_READV
static ssize_t _pink_process_vm_readv(pid_t pid,
				      const struct iovec *local_iov,
				      unsigned long liovcnt,
				      const struct iovec *remote_iov,
				      unsigned long riovcnt,
				      unsigned long flags)
{
	ssize_t r;
# if defined(__NR_process_vm_readv)
	r = syscall(__NR_process_vm_readv, (long)pid,
		    local_iov, liovcnt,
		    remote_iov, riovcnt, flags);
# else
	static long sysnum = 0;

	if (!sysnum)
		sysnum = seccomp_syscall_resolve_name("process_vm_readv");
	if (sysnum == __NR_SCMP_ERROR || sysnum < 0) {
		errno = ENOSYS;
		return -1;
	} else {
		r = syscall(sysnum, (long)pid,
			    local_iov, liovcnt,
			    remote_iov, riovcnt, flags);
	}
# endif
	return r;
}

# define process_vm_readv _pink_process_vm_readv
#else
# define process_vm_readv(...) (errno = ENOSYS, -1)
#endif

#if HAVE_PROCESS_VM_WRITEV
SYD_GCC_ATTR((unused))
static ssize_t _pink_process_vm_writev(pid_t pid,
				       const struct iovec *local_iov,
				       unsigned long liovcnt,
				       const struct iovec *remote_iov,
				       unsigned long riovcnt,
				       unsigned long flags)
{
	ssize_t r;
# if defined(__NR_process_vm_writev)
	r = syscall(__NR_process_vm_writev, (long)pid,
		    local_iov, liovcnt,
		    remote_iov, riovcnt,
		    flags);
# else
	static long sysnum = 0;

	if (!sysnum)
		sysnum = seccomp_syscall_resolve_name("process_vm_writev");
	if (sysnum == __NR_SCMP_ERROR || sysnum < 0) {
		errno = ENOSYS;
		return -1;
	} else {
		r = syscall(sysnum, (long)pid,
			    local_iov, liovcnt,
			    remote_iov, riovcnt, flags);
	}
# endif
	return r;
}

# define process_vm_writev _pink_process_vm_writev
#else
# define process_vm_writev(...) (errno = ENOSYS, -1)
#endif

static inline int abi_wordsize(uint32_t arch)
{
	switch (arch) {
#if defined(__x86_64__)
	case SCMP_ARCH_X86_64:
		return 8;
		break;
	case SCMP_ARCH_X86:
		return 4;
		break;
	case SCMP_ARCH_X32:
		return 4;
		break;
#elif defined(__aarch64__)
	switch (current->arch) {
	case SCMP_ARCH_AARCH64:
		return 8;
		break;
	case SCMP_ARCH_ARM:
		return 4;
		break;
#elif defined(__powerpc64__)
	case SCMP_ARCH_PPC64:
		return 8;
		break;
	case SCMP_ARCH_PPC:
		return 4;
		break;
#endif
	case SCMP_ARCH_NATIVE:
	default:
		return (int)(sizeof(long));
		break;
	}
}

static int process_vm_read(syd_process_t *current, long addr, void *buf,
			   size_t count)
{
	size_t wsize;

#if SIZEOF_LONG > 4
	wsize = abi_wordsize(SCMP_ARCH_NATIVE);
	if (wsize < sizeof(addr))
		addr &= (1ul << 8 * wsize) - 1;
#endif

	int r;
#if HAVE_PROCESS_VM_READV
	static bool cross_memory_attach_works = true;

	if (!cross_memory_attach_works) {
		int memfd;
		if ((memfd = syd_proc_mem_open(current->pid)) < 0)
			return memfd;
		r = syd_proc_mem_read(memfd, addr, buf, count);
		close(memfd);
	} else {
		struct iovec local[1], remote[1];
		local[0].iov_base = buf;
		remote[0].iov_base = (void *)addr;
		local[0].iov_len = remote[0].iov_len = count;

		r = process_vm_readv(current->pid, local, 1, remote, 1, /*flags:*/0);
		if (errno == ENOSYS || errno == EPERM)
			cross_memory_attach_works = false;
	}
#else
	int memfd;
	if ((memfd = syd_proc_mem_open(current->pid)) < 0)
		return memfd;
	r = syd_proc_mem_read(memfd, addr, buf, count);
	close(memfd);
#endif
	return r;
}

static int process_vm_write(syd_process_t *current, long addr, const void *buf,
			    size_t count)
{
	size_t wsize;

#if SIZEOF_LONG > 4
	wsize = abi_wordsize(current->arch);
	if (wsize < sizeof(addr))
		addr &= (1ul << 8 * wsize) - 1;
#endif

	int r;
#if HAVE_PROCESS_VM_WRITEV
	static bool cross_memory_attach_works = true;

	if (!cross_memory_attach_works) {
		int memfd;
		if ((memfd = syd_proc_mem_open(current->pid)) < 0)
			return memfd;
		r = syd_proc_mem_write(memfd, addr, buf, count);
		close(memfd);
	} else {
		struct iovec local[1], remote[1];
		local[0].iov_base = (void *)buf;
		remote[0].iov_base = (void *)addr;
		local[0].iov_len = remote[0].iov_len = count;

		r = process_vm_writev(current->pid, local, 1, remote, 1, /*flags:*/0);
		if (errno == ENOSYS || errno == EPERM)
			cross_memory_attach_works = false;
	}
#else
	int memfd;
	if ((memfd = syd_proc_mem_open(current->pid)) < 0)
		return memfd;
	r = syd_proc_mem_write(memfd, addr, buf, count);
	close(memfd);
#endif
	return r;
}

int syd_kill(pid_t pid, pid_t tgid, int sig)
{
	int r = 0;
#ifdef __NR_tgkill
	if (syscall(__NR_tgkill, pid, tgid, sig) < 0)
		r = -errno;
#else
	if (kill(pid, sig) < 0)
		r = -errno;
#endif
	return r;
}

SYD_GCC_ATTR((nonnull(1,3)))
int syd_read_vm_data(syd_process_t *current, long addr, char *dest, size_t len)
{
	return process_vm_read(current, addr, dest, len);
}

SYD_GCC_ATTR((nonnull(1,3)))
ssize_t syd_write_vm_data(syd_process_t *current, long addr, const char *src,
			  size_t len)
{
	return process_vm_write(current, addr, src, len);
}

SYD_GCC_ATTR((nonnull(1,3)))
int syd_read_vm_data_full(syd_process_t *current, long addr, unsigned long *argval)
{
	ssize_t l;

	errno = 0;
	l = syd_read_vm_data(current, addr, (char *)argval, sizeof(*argval));
	if (l < 0)
		return -errno;
	if (sizeof(long) != (size_t)l)
		return -EFAULT;
	return 0;
}

inline int syd_read_syscall(syd_process_t *current, long *sysnum)
{
	SYD_RETURN_IF_DETACHED(current);
	BUG_ON(sysnum);

	*sysnum = current->sysnum;

	return 0;
}

inline int syd_read_argument(syd_process_t *current, unsigned arg_index, long *argval)
{
	SYD_RETURN_IF_DETACHED(current);
	BUG_ON(argval);
	BUG_ON(arg_index < 6);

	*argval = current->args[arg_index];

	return 0;
}

int syd_read_argument_int(syd_process_t *current, unsigned arg_index, int *argval)
{
	SYD_RETURN_IF_DETACHED(current);
	BUG_ON(argval);
	BUG_ON(arg_index < 6);

	*argval = (int)current->args[arg_index];

	return 0;
}

ssize_t syd_read_string(syd_process_t *current, long addr, char *dest, size_t len)
{
	SYD_RETURN_IF_DETACHED(current);

	return process_vm_read(current, addr, dest, len);
}

int syd_read_socket_argument(syd_process_t *current, unsigned arg_index,
			     unsigned long *argval)
{
	int r;

	SYD_RETURN_IF_DETACHED(current);
	BUG_ON(argval);

	bool decode_socketcall = !strcmp(current->sysname, "socketcall");
	if (!decode_socketcall) {
		*argval = current->args[arg_index];
		return 0;
	}

	size_t wsize;
	long addr;
	unsigned long u_addr;

	addr = current->args[1];
	u_addr = addr;
	wsize = abi_wordsize(current->arch);
	errno = 0;
	if (wsize == sizeof(int)) {
		unsigned int arg;
		if ((r = process_vm_read(current, u_addr,
					 (long unsigned *)&arg,
					 sizeof(unsigned int))) < 0)
			return r;
		*argval = arg;
	} else {
		unsigned long arg;
		if ((r = process_vm_read(current, u_addr,
					 (long unsigned *)&arg,
					 sizeof(unsigned long))) < 0)
			return r;
		*argval = arg;
	}

	return 0;
}

SYD_GCC_ATTR((nonnull(1,2)))
int syd_read_socket_subcall(syd_process_t *current, long *subcall)
{
	SYD_RETURN_IF_DETACHED(current);

	bool decode_socketcall = !strcmp(current->sysname, "socketcall");
	if (decode_socketcall) {
		*subcall = current->args[0];
	} else {
		*subcall = current->sysnum;
	}
	return 0;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_read_socket_address(syd_process_t *current,
			    bool sockaddr_in_msghdr,
			    unsigned arg_index, int *fd,
			    struct pink_sockaddr *sockaddr)
{
	int r;
	unsigned long myfd;
	unsigned long addr, addrlen;

	SYD_RETURN_IF_DETACHED(current);

	if (fd) {
		if ((r = syd_read_socket_argument(current, 0, &myfd)) < 0)
			return r;
		*fd = (int)myfd;
	}
	if ((r = syd_read_socket_argument(current, arg_index, &addr)) < 0)
		return r;
	if (addr == 0) {
		sockaddr->family = -1;
		sockaddr->length = 0;
		return 0;
	}

	if (!sockaddr_in_msghdr) {
		if ((r = syd_read_socket_argument(current, arg_index + 1,
						  &addrlen)) < 0)
			return r;
		if (addrlen < 2 || addrlen > sizeof(sockaddr->u))
			addrlen = sizeof(sockaddr->u);

		memset(&sockaddr->u, 0, sizeof(sockaddr->u));
		if ((r = process_vm_read(current, addr, sockaddr->u.pad, addrlen)) < 0)
			return r;
		sockaddr->u.pad[sizeof(sockaddr->u.pad) - 1] = '\0';

		sockaddr->family = sockaddr->u.sa.sa_family;
		sockaddr->length = addrlen;
	} else {
		struct msghdr msg;
		struct msghdr *const msg_native = &msg;
		struct_msghdr msg_compat;

		if (sizeof(*msg_native) == sizeof(msg_compat)) {
			r = syd_read_vm_data_full(current, addr, (void *)&msg);
			if (r < 0)
				return r;
			addrlen = sizeof(*msg_native);
		} else {
			r = syd_read_vm_data_full(current, addr,
						  (void *)&msg_compat);
			if (r < 0)
				return r;
			msg_native->msg_name = (void *)(unsigned
							long)msg_compat.msg_name;
			msg_native->msg_namelen = msg_compat.msg_namelen;
			addrlen = sizeof(msg_compat);
		}
		addr = (unsigned long)msg_native->msg_name;

		if (addrlen < 2) {
			sockaddr->family = -1;
			sockaddr->length = 0;
			return 0;
		}

		union {
			struct sockaddr sa;
			struct sockaddr_un sa_un;
			struct sockaddr_in sa_in;
			struct sockaddr_in6 sa6;
			struct sockaddr_nl nl;
			struct sockaddr_storage storage;
			char pad[sizeof(struct sockaddr_storage) + 1];
		} addrbuf;

		if ((unsigned) addrlen > sizeof(addrbuf.storage))
			addrlen = sizeof(addrbuf.storage);

		if ((r = process_vm_read(current, addr, addrbuf.pad, addrlen)) < 0)
			return r;
		memset(&addrbuf.pad[addrlen], 0, sizeof(addrbuf.pad) - addrlen);

		sockaddr->length = addrlen;
		memset(&sockaddr->u, 0, sizeof(sockaddr->u));
		sockaddr->family = addrbuf.sa.sa_family;
		switch (sockaddr->family) {
		case AF_UNIX:
			sockaddr->u.sa_un.sun_family = AF_UNIX;
			strlcpy(sockaddr->u.sa_un.sun_path,
				addrbuf.sa_un.sun_path,
				UNIX_PATH_MAX);
			break;
		case AF_INET:
			sockaddr->u.sa_in.sin_family = AF_INET;
			sockaddr->u.sa_in.sin_port = addrbuf.sa_in.sin_port;
			memcpy(&sockaddr->u.sa_in.sin_addr,
			       &addrbuf.sa_in.sin_addr,
			       sizeof(struct in_addr));
			break;
		case AF_INET6:
			sockaddr->u.sa6.sin6_family = AF_INET6;
			sockaddr->u.sa6.sin6_port = addrbuf.sa6.sin6_port;
			memcpy(&sockaddr->u.sa6.sin6_addr,
			       &addrbuf.sa6.sin6_addr,
			       sizeof(struct in6_addr));
			break;
		case AF_NETLINK:
			sockaddr->u.nl.nl_family = AF_NETLINK;
			sockaddr->u.nl.nl_pad = addrbuf.nl.nl_pad;
			sockaddr->u.nl.nl_pid = addrbuf.nl.nl_pid;
			sockaddr->u.nl.nl_groups = addrbuf.nl.nl_groups;
			break;
		default:
			sockaddr->length = 0;
			break;
		}
	}

	return 0;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_write_retval(syd_process_t *current, long retval, int error)
{
	SYD_RETURN_IF_DETACHED(current);

	sydbox->response->val = retval;
	sydbox->response->error = error;

	return 0;
}

ssize_t syd_write_data(syd_process_t *current, long addr, const void *buf,
		       size_t count)
{
	SYD_RETURN_IF_DETACHED(current);

	return process_vm_write(current, addr, buf, count);
}

int test_cross_memory_attach(bool report)
{
	int pipefd[2];

	if (pipe(pipefd) < 0)
		die_errno("pipe");

	pid_t pid = fork();
	if (pid < 0) {
		die_errno("fork");
	} else if (pid == 0) {
		const char *addr = "ping";

		close(pipefd[0]);
		write(pipefd[1], &addr, sizeof(long));
		close(pipefd[1]);
		pause();
		_exit(0);
	}
	long addr;
	size_t len = 5; /* "ping" */
	char dest[5];
	close(pipefd[1]);
	if (read(pipefd[0], &addr, sizeof(long)) < 0)
		die_errno("pipe_read");
	close(pipefd[0]);

	struct iovec local[1], remote[1];
	local[0].iov_base = dest;
	remote[0].iov_base = (void *)addr;
	local[0].iov_len = remote[0].iov_len = len;

	if (process_vm_readv(pid, local, 1, remote, 1, 0) < 0) {
		int save_errno = errno;
		say_errno("process_vm_readv");
		if (report && (errno == ENOSYS || errno == EPERM)) {
			say("warning: Your system does not support process_vm_readv");
			say("warning: Please enable CONFIG_CROSS_MEMORY_ATTACH in your "
			    "kernel configuration.");
		}
		return -save_errno;
	}
	if (strcmp(dest, "ping")) {
		if (report) {
			say("warning: Your system does not support process_vm_readv: \"%s\"", dest);
			say("warning: Please enable CONFIG_CROSS_MEMORY_ATTACH in your "
			    "kernel configuration.");
		}
		return -ENOSYS;
	}

	kill(pid, SIGKILL);
	wait(NULL);

	if (report)
		say("[*] cross memory attach is functional.");
	return 0;
}

int test_proc_mem(bool report)
{
	int pipefd[2];

	if (pipe(pipefd) < 0)
		die_errno("pipe");

	pid_t pid = fork();
	if (pid < 0) {
		die_errno("fork");
	} else if (pid == 0) {
		const char *addr = "ping";

		close(pipefd[0]);
		write(pipefd[1], &addr, sizeof(long));
		close(pipefd[1]);
		pause();
		_exit(0);
	}
	long addr;
	size_t wsize, len = 5; /* "ping" */
	char dest[5];
	close(pipefd[1]);
	if (read(pipefd[0], &addr, sizeof(long)) < 0)
		die_errno("pipe_read");
	close(pipefd[0]);
#if SIZEOF_LONG > 4
	wsize = abi_wordsize(SCMP_ARCH_NATIVE);
	if (wsize < sizeof(addr))
		addr &= (1ul << 8 * wsize) - 1;
#endif

	int memfd = syd_proc_mem_open(pid);
	if (memfd < 0) {
		int save_errno = errno;
		say_errno("syd_proc_mem_open");
		if (report)
			say("warning: Your system does not support /proc/pid/mem "
			    "interface.");
		return -save_errno;
	}
	if (syd_proc_mem_read(memfd, addr, dest, len) < 0) {
		int save_errno = errno;
		say_errno("syd_proc_mem_read");
		if (report)
			say("warning: Your system does not support /proc/pid/mem "
			    "interface.");
		return -save_errno;
	}
	if (strcmp(dest, "ping")) {
		if (report)
			say("warning: Your system does not support /proc/pid/mem "
			    "interface: \"%s\"", dest);
		return -ENOSYS;
	}

	kill(pid, SIGKILL);
	wait(NULL);

	if (report)
		say("[*] /proc/pid/mem interface is functional.");
	return 0;
}

int test_pidfd(bool report)
{
	int getfd, pidfd, r;
	int pidfd_open, pidfd_getfd, pidfd_send_signal;
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		die_errno("fork");
	} else if (pid == 0) {
		pause();
		_exit(0);
	}

	r = 0;
	pidfd_open = seccomp_syscall_resolve_name("pidfd_open");
	if (pidfd_open == __NR_SCMP_ERROR ||
	    pidfd_open < 0) {
		if (!errno)
			errno = ENOSYS;
		r = -errno;
		say_errno("pidfd_open");
		goto out;
	}
	pidfd_getfd = seccomp_syscall_resolve_name("pidfd_getfd");
	if (pidfd_getfd == __NR_SCMP_ERROR ||
	    pidfd_getfd < 0) {
		if (!errno)
			errno = ENOSYS;
		r = -errno;
		say_errno("pidfd_getfd");
		goto out;
	}
	pidfd_send_signal = seccomp_syscall_resolve_name("pidfd_send_signal");
	if (pidfd_send_signal == __NR_SCMP_ERROR ||
	    pidfd_send_signal < 0) {
		if (!errno)
			errno = ENOSYS;
		r = -errno;
		say_errno("pidfd_send_signal");
		goto out;
	}

	pidfd = syscall(pidfd_open, pid, 0);
	if (pidfd < 0) {
		r = -errno;
		say_errno("pidfd_open");
		goto out;
	}

	getfd = syscall(pidfd_getfd, pidfd, STDERR_FILENO, 0);
	if (getfd < 0) {
		r = -errno;
		say_errno("pidfd_getfd");
		goto out;
	}

	if (syscall(pidfd_send_signal, pidfd, SIGKILL, NULL, 0) < 0) {
		r = -errno;
		say_errno("pidfd_send_signal");
		goto out;
	}

	close(pidfd);

	int wstatus;
	if (waitpid(pid, &wstatus, __WALL) < 0) {
		r = -errno;
		say_errno("waitpid");
		goto out;
	}

	if (WIFEXITED(wstatus)) {
		say("warning: process exited normally after "
		    "pidfd_send_signal.");
		r = -EINVAL;
	} else if (!WIFSIGNALED(wstatus)) {
		say("warning: process was not terminated after "
		    "pidfd_send_signal.");
		r = -EINVAL;
	} else if (WTERMSIG(wstatus) != SIGKILL) {
		say("warning: process was not terminated with SIGKILL "
		    "but %d.", WTERMSIG(wstatus));
		r = -EINVAL;
	}
out:
	if (r)
		say("warning: Your system does not support pidfd "
		    "interface.");
	else if (report)
		say("[*] pidfd interface is functional.");
	return r;
}

int test_seccomp(bool report, bool test_seccomp_load)
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		die_errno("fork");
	} else if (pid == 0) {
		int r;
		scmp_filter_ctx ctx;

		r = 0;
		if ((ctx = seccomp_init(SCMP_ACT_ALLOW)) == NULL) {
			r = -errno;
			say_errno("seccomp_init");
			goto out;
		}

		if ((r = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
					  SCMP_SYS(mount), 0)) < 0) {
			errno = -r;
			say_errno("seccomp_rule_add");
			goto out;
		}

		if (test_seccomp_load && (r = seccomp_load(ctx)) < 0) {
			errno = -r;
			say_errno("seccomp_load");
		}

		seccomp_release(ctx);
out:
		if (r)
			say("warning: Your system does not support seccomp "
			    "filters.");
		else if (report)
			say("[*] seccomp filters are functional.");
		_exit(-r);
	}

	int wstatus;
	if (waitpid(pid, &wstatus, __WALL) < 0)
		die_errno("waitpid");
	if (WIFEXITED(wstatus))
		return -WEXITSTATUS(wstatus);
	return -EINVAL;
}
