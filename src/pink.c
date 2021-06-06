/*
 * sydbox/pink.c
 *
 * pinktrace wrapper functions
 *
 * Copyright (c) 2013, 2014, 2015, 2018 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"
#include "pink.h"
#include "syd.h"
#include <errno.h>
#include <string.h>

#define SYD_RETURN_IF_DETACHED(current) do { \
	if (current->flags & SYD_DETACHED) { \
		return 0; \
	}} while (0)

#if PINK_HAVE_PROCESS_VM_READV
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
	errno = ENOSYS;
	return -1;
# endif
	return r;
}

# define process_vm_readv _pink_process_vm_readv
#else
# define process_vm_readv(...) (errno = ENOSYS, -1)
#endif

#if PINK_HAVE_PROCESS_VM_WRITEV
PINK_GCC_ATTR((unused))
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
	errno = ENOSYS;
	return -1;
# endif
	return r;
}

# define process_vm_writev _pink_process_vm_writev
#else
# define process_vm_writev(...) (errno = ENOSYS, -1)
#endif

static inline int abi_wordsize(const syd_process_t *current)
{
	switch (current->arch) {
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

PINK_GCC_ATTR((nonnull(1,3)))
int syd_read_vm_data(syd_process_t *current, long addr, char *dest, size_t len)
{
	struct iovec local[1], remote[1];

#if SIZEOF_LONG > 4
	size_t wsize = abi_wordsize(current);
	if (wsize < sizeof(addr))
		addr &= (1ul << 8 * wsize) - 1;
#endif
	local[0].iov_base = dest;
	remote[0].iov_base = (void *)addr;
	local[0].iov_len = remote[0].iov_len = len;

	return process_vm_readv(current->pid, local, 1, remote, 1, /*flags:*/0);
}

PINK_GCC_ATTR((nonnull(1,3)))
ssize_t syd_write_vm_data(syd_process_t *current, long addr, const char *src,
			  size_t len)
{
#if PINK_HAVE_PROCESS_VM_WRITEV
	struct iovec local[1], remote[1];

#if SIZEOF_LONG > 4
	size_t wsize = abi_wordsize(current);
	if (wsize < sizeof(addr))
		addr &= (1ul << 8 * wsize) - 1;
#endif
	local[0].iov_base = (void *)src;
	remote[0].iov_base = (void *)addr;
	local[0].iov_len = remote[0].iov_len = len;
#endif

	return process_vm_writev(current->pid, local, 1, remote, 1, /*flags:*/ 0);
}

PINK_GCC_ATTR((nonnull(1,3)))
int syd_read_vm_data_full(syd_process_t *current, long addr, unsigned long *argval)
{
	ssize_t l;

	errno = 0;
	l = syd_read_vm_data(current, addr, (char *)argval, sizeof(long));
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
	size_t wsize;

	SYD_RETURN_IF_DETACHED(current);

#if SIZEOF_LONG > 4
	wsize = abi_wordsize(current);
	if (wsize < sizeof(addr))
		addr &= (1ul << 8 * wsize) - 1;
#endif

	struct iovec local[1], remote[1];
	local[0].iov_base = dest;
	remote[0].iov_base = (void *)addr;
	local[0].iov_len = remote[0].iov_len = len;

	return process_vm_readv(current->pid, local, 1, remote, 1, /*flags:*/0);
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
	wsize = abi_wordsize(current);
	errno = 0;
	if (wsize == sizeof(int)) {
		unsigned int arg;
		if ((r = syd_read_vm_data_full(current, u_addr, (long unsigned *)&arg)) < 0)
			return r;
		*argval = arg;
	} else {
		unsigned long arg;
		if ((r = syd_read_vm_data_full(current, u_addr, &arg)) < 0)
			return r;
		*argval = arg;
	}

	return 0;
}

PINK_GCC_ATTR((nonnull(1,2)))
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

PINK_GCC_ATTR((nonnull(1,4)))
int syd_read_socket_address(syd_process_t *current, unsigned arg_index, int *fd,
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
	if ((r = syd_read_socket_argument(current, arg_index + 1, &addrlen)) < 0)
		return r;

	if (addr == 0) {
		sockaddr->family = -1;
		sockaddr->length = 0;
		return 0;
	}
	if (addrlen < 2 || addrlen > sizeof(sockaddr->u))
		addrlen = sizeof(sockaddr->u);

	memset(&sockaddr->u, 0, sizeof(sockaddr->u));
	if ((r = syd_read_vm_data(current, addr, (char *)sockaddr->u.pad, addrlen)) < 0)
		return r;
	sockaddr->u.pad[sizeof(sockaddr->u.pad) - 1] = '\0';

	sockaddr->family = sockaddr->u.sa.sa_family;
	sockaddr->length = addrlen;

	return 0;
}

PINK_GCC_ATTR((nonnull(1)))
int syd_write_retval(syd_process_t *current, long retval, int error)
{
	SYD_RETURN_IF_DETACHED(current);

	sydbox->response->val = retval;
	sydbox->response->error = error;

	return 0;
}
