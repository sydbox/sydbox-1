/*
 * sydbox/pink.c
 *
 * pinktrace wrapper functions
 *
 * Copyright (c) 2013, 2014, 2015, 2018, 2021 Ali Polatel <alip@exherbo.org>
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
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

/* For definitions of struct msghdr and struct mmsghdr. */
#include <sys/socket.h>
/* UNIX_PATH_MAX */
#include <sys/un.h>
#define sockaddr_un sockaddr_un_tmp
#include <linux/un.h>
#undef sockaddr_un

#include "syd/syd.h"

#ifdef ENABLE_PSYSCALL
# include "psyscall_syd.h"
#endif

#ifndef HAVE_STRUCT_MMSGHDR
struct mmsghdr {
	struct msghdr msg_hdr;
	unsigned msg_len;
};
#endif
typedef struct msghdr struct_msghdr;

#ifndef __NR_process_vm_readv
# warning "Your system does not define process_vm_readv, setting to 310."
# warning "Please update your Linux kernel and headers."
# define __NR_process_vm_readv 310
#endif

#ifndef __NR_process_vm_writev
# warning "Your system does not define process_vm_writev, setting to 311."
# warning "Please update your Linux kernel and headers."
# define __NR_process_vm_writev 311
#endif

static ssize_t pink_process_vm_readv(pid_t pid,
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

static ssize_t pink_process_vm_writev(pid_t pid,
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

static ssize_t process_vm_read(syd_process_t *current, long addr, void *buf,
			       size_t count)
{
#if SIZEOF_LONG > 4
	size_t wsize = abi_wordsize(SCMP_ARCH_NATIVE);
	if (wsize < sizeof(addr))
		addr &= (1ul << 8 * wsize) - 1;
#endif

	ssize_t r = 0, nread;
#if !SYDBOX_DEF_PROC_MEM
	static bool cross_memory_attach_works = true;
retry_vm_readv:
	if (use_cross_memory_attach() && cross_memory_attach_works) {
		struct iovec local[1], remote[1];
		local[0].iov_base = ((char *)(buf)) + r;
		remote[0].iov_base = (void *)(addr + r);
		local[0].iov_len = remote[0].iov_len = count - r;

		errno = 0;
		nread = pink_process_vm_readv(current->pid, local, 1,
					      remote, 1, /*flags:*/0);
		if (nread > 0)
			r += nread;
		if (errno == EINTR || (nread > 0 && (size_t)r < count)) {
			goto retry_vm_readv;
		} else if (errno == ENOSYS || errno == EPERM) {
			cross_memory_attach_works = false;
			goto retry_vm_readv;
		} else if (errno == ESRCH) {
			/*
			 * SECURITY:
			 * Process dead, and may be replaced by another process.
			 * Invalidate FDs ASAP!
			 */
			sydbox_proc_invalidate();
		} else if (nread < 0 && r == 0) {
			int save_errno = errno;
			say_errno("process_vm_read(%d)", current->pid);
			errno = save_errno;
		}
		return r;
	}
#endif
	/*
	 * SECURITY:
	 * sydbox->pifd_mem is only secure to reopen using syd_proc_mem_open().
	 */
	bool mem_open = false, mem_open_ok = false;
	if (mem_open) {
		int memfd;
		if ((memfd = syd_proc_mem_open(sydbox->pfd)) < 0)
			return memfd;
		sydbox->pfd_mem = memfd;
		if (mem_open)
			mem_open_ok = true;
	}
mem_read:
	errno = 0;
	nread = syd_proc_mem_read(sydbox->pfd_mem, addr + r,
				  ((char *)buf) + r, count - r);
	if (nread > 0)
		r += nread;
	if (errno == EINTR || (nread > 0 && (size_t)r < count)) {
		goto mem_read;
	} else if (proc_esrch(errno)) {
		if (sydbox->pfd_mem >= 0)
			close(sydbox->pfd_mem);
		if (sydbox->pidfd >= 0)
			close(sydbox->pidfd);
		sydbox->pfd_mem = -1;
		sydbox->pidfd = -1;
		errno = ESRCH;
		return r;
	} else if (!mem_open && (!nread || errno == EBADF || errno == ESPIPE)) {
		close(sydbox->pfd_mem);
		sydbox->pfd_mem = -1;
		mem_open = true;
		goto mem_open;
	} else if (nread < 0 && r == 0) { /* not partial read */
		int save_errno = errno;
		say_errno("proc_mem_read(%d)", current->pid);
		errno = save_errno;
	}
	if (!mem_open_ok && sydbox->pfd_mem >= 0) {
		close(sydbox->pfd_mem);
		sydbox->pfd_mem = -1;
	}
	dump(DUMP_CROSS_MEMORY, "read", current->pid, addr, nread, -r);
	return r;
}

static ssize_t proc_mem_write(syd_process_t *current, long addr, void *buf, size_t count)
{
	int r;
	ssize_t nwritten;

	/*
	 * SECURITY:
	 * sydbox->pifd_mem is only secure to reopen using syd_proc_mem_open().
	 */
	bool mem_open = false, mem_open_ok = false;
mem_open:
	if (mem_open) {
		int memfd;
		if ((memfd = syd_proc_mem_open(sydbox->pfd)) < 0)
			return memfd;
		sydbox->pfd_mem = memfd;
		if (mem_open)
			mem_open_ok = true;
	}
	r = 0;
mem_write:
	errno = 0;
	nwritten = syd_proc_mem_write(sydbox->pfd_mem,
				      addr + r,
				      ((char *)buf) + r,
				      count - r);
	if (nwritten > 0)
		r += nwritten;
	if (errno == EINTR || (nwritten > 0 && (size_t)r < count)) {
		goto mem_write;
	} else if (proc_esrch(errno)) {
		if (sydbox->pfd_mem)
			close(sydbox->pfd_mem);
		if (sydbox->pidfd)
			close(sydbox->pidfd);
		sydbox->pfd_mem = -1;
		sydbox->pidfd = -1;
		errno = ESRCH;
		return r;
	} else if (!mem_open && (!nwritten || errno == EBADF || errno == ESPIPE)) {
		close(sydbox->pfd_mem);
		sydbox->pfd_mem = -1;
		mem_open = true;
		goto mem_open;
	} else if (nwritten < 0 && r == 0) { /* not partial write */
		int save_errno = errno;
		say_errno("proc_mem_write(%d)", current->pid);
		errno = save_errno;
	}
	if (!mem_open_ok && sydbox->pfd_mem >= 0) {
		close(sydbox->pfd_mem);
		sydbox->pfd_mem = -1;
	}
	dump(DUMP_CROSS_MEMORY, "write", current->pid, addr, nwritten, -r);
	return r;
}

static ssize_t process_vm_write(syd_process_t *current, long addr, void *buf,
				size_t count)
{
	if (!process_alive(current))
		return -ESRCH;

#if SIZEOF_LONG > 4
	size_t wsize = abi_wordsize(current->arch);
	if (wsize < sizeof(addr))
		addr &= (1ul << 8 * wsize) - 1;
#endif

	ssize_t r = 0, nwritten = 0;
#if !SYDBOX_DEF_PROC_MEM
	static bool cross_memory_attach_works = true;
retry_vm_writev:
	if (use_cross_memory_attach() && cross_memory_attach_works) {
		struct iovec local[1], remote[1];
		local[0].iov_base = ((char *)(buf)) + r;
		remote[0].iov_base = (void *)(addr + r);
		local[0].iov_len = remote[0].iov_len = count - r;

		errno = 0;
		nwritten = pink_process_vm_writev(current->pid,
						  local, 1,
						  remote, 1, /*flags:*/0);
		if (nwritten > 0)
			r += nwritten;
		if (errno == EINTR || (nwritten > 0 && (size_t)r < count)) {
			goto retry_vm_writev;
		} else if (errno == ENOSYS || errno == EPERM) {
			cross_memory_attach_works = false;
			goto retry_vm_writev;
		} else if (errno == ESRCH) {
			/*
			 * SECURITY:
			 * Process dead, and may be replaced by another process.
			 * Invalidate FDs ASAP!
			 */
			sydbox_proc_invalidate();
		} else if (nwritten < 0 && r == 0) {
			int save_errno = errno;
			say_errno("process_vm_write(%d)", current->pid);
			errno = save_errno;
		}
		return r;
	}
#endif
	return proc_mem_write(current, addr, buf, count);
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
ssize_t syd_write_vm_data(syd_process_t *current, long addr, char *src,
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
	SYD_RETURN_IF_DEAD(current);
	BUG_ON(sysnum);

	*sysnum = current->sysnum;

	return 0;
}

inline int syd_read_argument(syd_process_t *current, unsigned arg_index, long *argval)
{
	SYD_RETURN_IF_DEAD(current);
	BUG_ON(argval);
	BUG_ON(arg_index < 6);

	*argval = current->args[arg_index];

	return 0;
}

int syd_read_argument_int(syd_process_t *current, unsigned arg_index, int *argval)
{
	SYD_RETURN_IF_DEAD(current);
	BUG_ON(argval);
	BUG_ON(arg_index < 6);

	*argval = (int)current->args[arg_index];

	return 0;
}

ssize_t syd_read_string(syd_process_t *current, long addr, char *dest, size_t len)
{
	SYD_RETURN_IF_DEAD(current);

	return process_vm_read(current, addr, dest, len);
}

int syd_read_socket_argument(syd_process_t *current, unsigned arg_index,
			     unsigned long *argval)
{
	int r;

	SYD_RETURN_IF_DEAD(current);
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
	SYD_RETURN_IF_DEAD(current);

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

	SYD_RETURN_IF_DEAD(current);

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
	SYD_RETURN_IF_DEAD(current);

	sydbox->response->val = retval;
	sydbox->response->error = error;

	return 0;
}

ssize_t syd_write_data(syd_process_t *current, long addr, void *buf,
		       size_t count)
{
	SYD_RETURN_IF_DEAD(current);

	return process_vm_write(current, addr, buf, count);
}

int syd_rmem_alloc(syd_process_t *current)
{
#if !ENABLE_PSYSCALL
	return -ENOSYS;
#else
#if ENABLE_STATIC
	if (current->pid == sydbox->execve_pid) {
		/* psyscall can't inject into static bin. */
		return -ENOTSUP;
	}
#endif
	if (current->addr == -1) {
		/* psyscall could not inject to this process (is it static?).*/
		return -ENOTSUP;
	} else if (current->addr != 0) {
		return 0; /* Already allocated. */
	}

	errno = 0;
	long addr = (long)palloc(current->pid, SYD_REMOTE_MEM_MAX);
	int r;
	if (addr <= 0) {
		r = -errno;
		current->addr = -1;
	} else {
		r = 0;
		current->addr = addr;
	}
	dump(DUMP_CROSS_MEMORY, "mmap", current->pid, addr,
	     SYD_REMOTE_MEM_MAX, -r);
	return r;
#endif
}

int syd_rmem_write(syd_process_t *current)
{
#if !ENABLE_PSYSCALL
	return -ENOSYS;
#else
	int r;
	bool write = false;
	for (uint8_t i = 0; i < 6; i++) {
		if (current->addr_arg[i])
			write = true;
		current->addr_arg[i] = false;
	}
	if (!write)
		return 0;

	if ((r = pink_regset_fill(current->pid, current->regset)) < 0) {
		say_errno("pink_regset_fill");
		return -r;
	}
#if 0
#if ENABLE_PSYSCALL
		if (current->addr > 0) {
			/* TOCTOU Mitigation */
			long addr = syd_remote_addr(current->addr,
						    info->arg_index);
			ssize_t nwritten = proc_mem_write(current, addr,
							  abspath, sizeof(abspath));
			if (nwritten == sizeof(abspath)) {
				say("TOCTOU mitigation active!");
				current->addr_arg[info->arg_index] = true;
			} else if (!errno) {
				say("psyscall_mem_write: short write");
			} else {
				say_errno("psyscall_mem_write");
			}
		}
#endif
		goto out;
#endif

	return 0;
#if 0
	for (uint8_t idx = 0; idx < 6; idx++) {
		if (!current->addr_arg[idx])
			continue;
		long addr = syd_remote_addr(current->addr, idx);
		say("Accessing process:%d to modify the %s() "
		    "argument %d to read-only memory at %p...",
		    current->pid, current->sysname,
		    idx, (void*)addr);
		if ((r = pink_write_argument(pid, current->regset,
					     idx, addr)) < 0) {
			errno = -r;
			say_errno("pink_write_argument");
		}
		say("Successfully changed argument %d of the %s() "
		    "system call for pid:%d to read-only pointer %p!",
		    idx, current->sysname, current->pid,
		    (void *)addr);
	}
#endif
#endif
}

bool syd_seccomp_request_is_valid(void)
{
	return !seccomp_notify_id_valid(sydbox->notify_fd, sydbox->request->id);
}

static volatile atomic_bool test_child_notify = ATOMIC_VAR_INIT(false);
static void test_seccomp_sig_chld(int sig, siginfo_t *info, void *ucontext)
{
	switch (info->si_code) {
	case CLD_EXITED:
	case CLD_KILLED:
	case CLD_DUMPED:
		syd_set_state(&test_child_notify, true);
		break;
	default:
		break;
	}
}

int test_cross_memory_attach(bool report)
{
	int pipefd[2], r;

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
	ssize_t nread;
	close(pipefd[1]);
	if ((nread = read(pipefd[0], &addr, sizeof(long))) < 0)
		die_errno("pipe_read");
	if (nread != sizeof(long))
		die_errno("pipe_read<%ld!=%zu>", nread, sizeof(long));
	close(pipefd[0]);

	struct iovec local[1], remote[1];
	local[0].iov_base = dest;
	remote[0].iov_base = (void *)addr;
	local[0].iov_len = remote[0].iov_len = len;

	r = 0;
	if (pink_process_vm_readv(pid, local, 1, remote, 1, 0) < 0) {
		r = -errno;
		say_errno("process_vm_readv");
		if (report && (errno == ENOSYS || errno == EPERM)) {
			say("warning: Your system does not support process_vm_readv");
			say("warning: Please enable CONFIG_CROSS_MEMORY_ATTACH in your "
			    "kernel configuration.");
		}
		goto out;
	}
	if (strcmp(dest, "ping")) {
		if (report) {
			say("warning: Your system does not support process_vm_readv: \"%s\"", dest);
			say("warning: Please enable CONFIG_CROSS_MEMORY_ATTACH in your "
			    "kernel configuration.");
		}
		r = -ENOSYS;
		goto out;
	}

out:
	kill(pid, SIGKILL);

	/* wait for child to send SIGCHLD */
	for (;!syd_get_state(&test_child_notify););
	syd_set_state(&test_child_notify, false);

	wait(NULL);

	if (report)
		say("[*] cross memory attach is functional.");
	return r;
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
	size_t len = 5; /* "ping" */
	char dest[5];
	ssize_t nread;
	close(pipefd[1]);
	if ((nread = read(pipefd[0], &addr, sizeof(long))) < 0)
		die_errno("pipe_read");
	if (nread != sizeof(long))
		die_errno("pipe_read<%ld!=%zu>", nread, sizeof(long));
	close(pipefd[0]);
#if SIZEOF_LONG > 4
	size_t wsize = abi_wordsize(SCMP_ARCH_NATIVE);
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
		close(memfd);
		return -save_errno;
	}
	dest[len-1] = '\0';
	if (strcmp(dest, "ping")) {
		if (report)
			say("warning: Your system does not support /proc/pid/mem "
			    "interface: \"%s\"", dest);
		close(memfd);
		return -ENOSYS;
	}

	kill(pid, SIGKILL);

	/* wait for child to send SIGCHLD */
	for (;!syd_get_state(&test_child_notify););
	syd_set_state(&test_child_notify, false);

	wait(NULL);

	if (report)
		say("[*] /proc/pid/mem interface is functional.");

	close(memfd);
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

	/* wait for child to send SIGCHLD */
	for (;!syd_get_state(&test_child_notify););
	syd_set_state(&test_child_notify, false);

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

/*
 * Writes if architecture is valid in the second argument.
 * Return value 0 means succesful detection.
 * > 0 means test process terminated by this signal value.
 * < 0 means one of the seccomp calls in the test process returned this negated
 * errno.
 * The second argument is definitely updated only when return value is 0.
 * Otherwise its state is undefined.
 */
int syd_seccomp_arch_is_valid(uint32_t arch, bool *result)
{
	int r;

	if (!result)
		return -ENOMEM;

	pid_t pid = fork();
	if (pid < 0) {
		return -errno;
	} else if (pid == 0) {
		scmp_filter_ctx ctx;
		if (!(ctx = seccomp_init(SCMP_ACT_ALLOW)))
			_exit(errno);
		if ((r = seccomp_arch_add(ctx, arch)) != 0 &&
		    r != -EEXIST)
			_exit(-r);
		uint32_t sys_getpid = seccomp_syscall_resolve_name("getpid");
		if ((r = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
					  sys_getpid, 0)) != 0) {
			if (r == -EOPNOTSUPP) {
				say_errno("error adding syscall getpid:%u "
					  "for architecture %#x",
					  sys_getpid, arch);
				_exit(-EOPNOTSUPP);
			} else if (r == -EACCES || r == -EFAULT) {
				_exit(0);
			} else {
				_exit(-r);
			}
		}
		if ((r = seccomp_load(ctx)) != 0) {
			if (r == -EOPNOTSUPP) {
				say_errno("error adding syscall getpid:%u "
					  "for architecture %#x",
					  sys_getpid, arch);
				_exit(-EOPNOTSUPP);
			} else if (r == -EACCES || r == -EFAULT) {
				_exit(0);
			} else {
				_exit(-r);
			}
		}
		_exit(0);
	}
	/* wait for child to send SIGCHLD */
	for (;!syd_get_state(&test_child_notify););
	syd_set_state(&test_child_notify, false);

	int status;
restart_waitpid:
	if (waitpid(pid, &status, 0) < 0) {
		if (errno == EINTR)
			goto restart_waitpid;
		return -errno;
	}

	r = 0;
	bool valid = false;
	if (WIFEXITED(status)) {
		r = WEXITSTATUS(status);
		if (r == 0)
			valid = true;
		else if (r == EDOM) /* invalid architecture */
			r = 0; /* valid = false; */
		else
			r = -r; /* negate errno */
	} else if (WIFSIGNALED(status)) {
		int sig = WTERMSIG(status);
		say("architecture test process terminated with %#x", sig);
		r = sig;
	}
	*result = valid;
	return r;
}

void test_setup(void)
{
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = test_seccomp_sig_chld;
	sa.sa_flags = SA_RESTART | SA_SIGINFO;
	if (sigaction(SIGCHLD, &sa, NULL) < 0)
		die_errno("sigaction(SIGCHLD)");
}

uint8_t test_seccomp_arch(void)
{
	int r;
	bool valid = false;
	uint8_t arch_num_total = 0;
	uint8_t arch_num_valid = 0;
#define ack "[93m***[00;00m"
#define nack "[92m!!![00;00m"
#define yes "valid on this system"
#define no "not supported on this system"
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_NATIVE, &valid);
	printf("--- native is %svalid.\n", valid ? "" : "not ");
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_X86, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s x86 is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_X32, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s x32 is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_X86_64, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s x86_64 is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_ARM, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s arm is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_AARCH64, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s aarch64 is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_MIPS, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s mips is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_MIPS64, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s mips64 is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_MIPS64N32, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s mips64n32 is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_MIPSEL, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s mipsel is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_MIPSEL64, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s mipsel64 is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_MIPSEL64N32, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s mipsel64n32 is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_PPC, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s ppc is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_PPC64, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s ppc64 is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_PPC64LE, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s ppc64le is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_S390, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s s390 is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_S390X, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s s390x is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_PARISC, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s parisc is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_PARISC64, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s parisc64 is %s.\n", valid ? ack : nack, valid ? yes : no);
	r = syd_seccomp_arch_is_valid(SCMP_ARCH_RISCV64, &valid);
	++arch_num_total; if (!r && valid) { ++arch_num_valid; }
	printf("%s riscv64 is %s.\n", valid ? ack : nack, valid ? yes : no);
#undef ack
#undef nack
#undef yes
#undef no

	const struct scmp_version *v = seccomp_version();
	say("[>] libseccomp-%d.%d.%d supports %u architectures.",
	    v->major, v->minor, v->micro,
	    arch_num_total);
	say("[>] 1 native, %u valid, %u invalid on this system.",
	    arch_num_valid, arch_num_total - arch_num_valid);

	return arch_num_valid;
}

int test_seccomp(bool report)
{
	int r = 0;
	pid_t pid;
	int pfd[2];

	if (pipe2(pfd, O_CLOEXEC|O_DIRECT) < 0) {
		r = -errno;
		say_errno("can't pipe");
		goto out;
	}
	pid = fork();
	if (pid < 0) {
		die_errno("fork");
	} else if (pid == 0) {
		scmp_filter_ctx ctx;

		close(pfd[0]);
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

		if ((r = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY,
					  SCMP_SYS(gettid), 0)) < 0) {
			errno = -r;
			say_errno("seccomp_rule_add");
			goto out;
		}

		if ((r = seccomp_load(ctx)) < 0) {
			errno = -r;
			say_errno("seccomp_load");
			goto out;
		}

		int fd;
		ssize_t count;

		if ((fd = seccomp_notify_fd(ctx)) < 0) {
			r = fd;
			errno = -fd;
			say_errno("seccomp_notify_fd");
			goto out;
		}

		errno = 0;
		count = atomic_write(pfd[1], &fd, sizeof(int));
		if (count < 0 || (size_t)count != sizeof(int)) {
			if (!errno)
				errno = EINVAL;
			r = -errno;
			say_errno("can't write int to pipe: %zu != %zu", count,
				  sizeof(int));
			goto out;
		}
		kill(getpid(), SIGSTOP);

		pid_t tid = syscall(__NR_gettid);
		if (tid >= 0)
			r = 0;

		seccomp_release(ctx);
out:
		if (r)
			say("warning: Your system does not support seccomp "
			    "filters.");
		else if (report)
			say("[*] seccomp filters are functional.");
		_exit(-r);
	}

	int fd;
	ssize_t count;

	close(pfd[1]);
	errno = 0;
	count = atomic_read(pfd[0], &fd, sizeof(int));
	if (!count && count != sizeof(int)) { /* count=0 is EOF */
		if (!errno)
			errno = EINVAL;
		r = -errno;
		say_errno("failed to read int from pipe: %zu != %zu",
			  count, sizeof(int));
		goto out;
	} else if (count < 0) {
		say_errno("failed to load seccomp filters");
		r = -EINVAL;
		goto out;
	}
	close(pfd[0]);

	int pidfd = syscall(__NR_pidfd_open, pid, 0);
	if (pidfd < 0) {
		r = -errno;
		say_errno("pidfd_open(%d)", pid);
		goto out;
	}
	if ((fd = syscall(__NR_pidfd_getfd, pidfd, fd, 0)) < 0) {
		r = -errno;
		say_errno("pidfd_getfd(%d)", pid);
		goto out;
	}
	kill(pid, SIGCONT);

	struct pollfd pollfd;
	pollfd.fd = fd;
	pollfd.events = POLLIN;
	errno = 0;
restart_poll:
	if ((r = poll(&pollfd, 1, 100)) < 0) {
		if (syd_get_state(&test_child_notify)) { /* SIGCHLD? */
			goto wait;
		} else if (!errno || errno == EINTR) {
			goto restart_poll;
		}
		r = -errno;
		goto out;
	}
	short revents = pollfd.revents;
	if (!r && !revents)
		goto restart_poll;
	if (revents & POLLIN) {
		struct seccomp_notif *request;
		struct seccomp_notif_resp *response;

		if ((r = seccomp_notify_alloc(&request, &response)) < 0) {
			errno = -r;
			say_errno("seccomp_notify_alloc");
			goto out;
		}
		memset(request, 0, sizeof(struct seccomp_notif));
		memset(response, 0, sizeof(struct seccomp_notif_resp));
notify_receive:
		if ((r = seccomp_notify_receive(fd, request)) < 0) {
			if (r == -ECANCELED || r == -EINTR) {
				goto notify_receive;
			} else if (r == -ENOENT || errno == ENOTTY) {
				/* If we didn't find a notification,
				 * it could be that the task was
				 * interrupted by a fatal signal between
				 * the time we were woken and
				 * when we were able to acquire the rw lock.
				 */
				errno = -r;
				say_errno("seccomp_notify_receive");
				goto out;
			} else {
				errno = -r;
				say_errno("seccomp_notify_receive");
				goto out;
			}
		}
		if (request->id == 0 && request->pid == 0)
			goto restart_poll;
		response->id = request->id;
		response->flags |= SECCOMP_USER_NOTIF_FLAG_CONTINUE;
		response->error = 0;
		response->val = 0;
notify_respond:
		/* 0 if valid, ENOENT if not */
		if ((r = seccomp_notify_id_valid(fd, request->id)) < 0 ||
		    (r = seccomp_notify_respond(fd, response)) < 0) {
			if (r == -ECANCELED || r == -EINTR) {
				goto notify_respond;
			} else if (r == -ENOENT || errno == ENOTTY) {
				/* If we didn't find a notification,
				 * it could be that the task was
				 * interrupted by a fatal signal between
				 * the time we were woken and
				 * when we were able to acquire the rw lock.
				 */
				errno = -r;
				say_errno("seccomp_notify_respond");
				goto out;
			} else {
				errno = -r;
				say_errno("seccomp_notify_respond");
				goto out;
			}
		}
	} else if (revents & POLLHUP || revents & POLLERR) {
		r = -ESRCH;
		goto out;
	} else if (revents & POLLNVAL) {
		r = -EINVAL;
		goto out;
	}

	/* wait for child to send SIGCHLD */
	for (;!syd_get_state(&test_child_notify););
	syd_set_state(&test_child_notify, false);

	int wstatus;
wait:
	if (waitpid(pid, &wstatus, __WALL) < 0)
		die_errno("waitpid");
	if (WIFEXITED(wstatus))
		return -WEXITSTATUS(wstatus);
	return -EINVAL;
}
