/*
 * libsyd/unshare.c
 *
 * libsyd: Interface for Linux namespaces (containers)
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 *
 * Based in part upon unshare crate's examples/runcmd.rs which is
 * Copyright (c) 2015-2016 The unshare Developers
 *   Released under the terms of the MIT License.
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "config.h"
#ifndef _GNU_SOURCE
# define _GNU_SOURCE /* setns() */
#endif
#include "syd.h"
#include <errno.h>
#include <sched.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <seccomp.h>

int syd_unshare(int fd_newpid, int fd_newnet, int fd_newns,
		int fd_newuts, int fd_newipc, int fd_newuser)
{
#define SYD_NS_TYPE_MAX 6
	uint8_t i;
	int fd, ns;
	int ns_type[SYD_NS_TYPE_MAX][2] = {
		{CLONE_NEWPID, fd_newpid},
		{CLONE_NEWNET, fd_newnet},
		{CLONE_NEWNS, fd_newns},
		{CLONE_NEWUTS, fd_newuts},
		{CLONE_NEWIPC, fd_newipc},
		{CLONE_NEWUSER, fd_newuser},
	};

	for (i = 0, fd = ns_type[0][1], ns = ns_type[0][0];
	     i < SYD_NS_TYPE_MAX;
	     fd = ns_type[++i][1], ns = ns_type[i][0])
	{
		if (fd <= 0)
			continue;
		if (syd_debug_get())
			syd_say("Unsharing %s namespace.", syd_name_namespace(ns));
		if (setns(fd, ns) < 0)
			return -errno;
	}
	return 0;
#undef SYD_NS_TYPE_MAX
}

int syd_set_death_sig(int signal)
{
	return prctl(PR_SET_PDEATHSIG, signal, 0, 0, 0) < 0 ? -errno: 0;
}

int syd_pivot_root(const char *new_root, const char *put_old)
{
	if (!new_root || !*new_root)
		return -EINVAL;
	if (!put_old || !*put_old)
		return -EINVAL;
	if (syd_debug_get()) {
		int r;
		bool ok = false;
		if ((r = syd_str_startswith(put_old, new_root, &ok)) < 0)
			return -r;
		if (!ok) {
			syd_say("The new_root is not a prefix of put old");
			return -EINVAL;
		}
	} /* else pivot_root will return EINVAL if prefix check fails. */
	if (syscall(SYS_pivot_root, new_root, put_old) < 0)
		return -errno;
	return 0;
}
