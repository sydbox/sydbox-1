/*
 * libsyd/pidfd.c
 *
 * Simple interface to Linux' pidfd utilities.
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the GNU General Public License v3 (or later)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "syd.h"
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#include <asm/unistd.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_pidfd_send_signal
# warning "Your system does not define pidfd_send_signal, setting to 424."
# warning "Please update your Linux kernel and headers."
# define __NR_pidfd_send_signal 424
#endif

#ifndef __NR_pidfd_open
# warning "Your system does not define pidfd_open, setting to 434."
# warning "Please update your Linux kernel and headers."
# define __NR_pidfd_open 434
#endif

#ifndef __NR_pidfd_getfd
# warning "Your system does not define pidfd_getfd, setting to 438."
# warning "Please update your Linux kernel and headers."
# define __NR_pidfd_getfd 438
#endif

inline int syd_pidfd_open(pid_t pid, unsigned int flags)
{
#ifndef __NR_pidfd_open
	return -ENOSYS;
#else
	return syscall(__NR_pidfd_open, pid, flags);
#endif
}

inline int syd_pidfd_getfd(int pidfd, int targetfd, unsigned int flags)
{
#ifndef __NR_pidfd_getfd
	return -ENOSYS;
#else
	return syscall(__NR_pidfd_getfd, pidfd, targetfd, flags);
#endif
}

inline bool syd_pidfd_send_signal(int pidfd, int sig, siginfo_t *info,
				  unsigned int flags)
{
#ifndef __NR_pidfd_send_signal
	return -ENOSYS;
#else
	int r = syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
	if (r == 0 || (r < 0 && errno == ESRCH))
		return true;
	return false;
#endif
}
