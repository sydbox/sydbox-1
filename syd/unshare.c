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
#include "syd.h"
#include <errno.h>
#include <seccomp.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

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
