/*
 * libsyd/exec.c
 *
 * libsyd restricted process execution
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "HELPME.h"
#include <syd/syd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sched.h>
#include <linux/sched.h>

struct syd_user_data {
	int errorpipe;
	const char *cmd;
	char *const *argv;
	struct syd_execv_opt *opt;
};

pid_t syd_clone3(struct clone_args *args)
{
	return syscall(SYD_clone3, args, sizeof(struct clone_args));
}

SYD_GCC_ATTR((warn_unused_result,nonnull((3))))
pid_t syd_clone(int flags, int exit_signal, unsigned long long *pidfd_out)
{
	unsigned long long pidfd = -1;
	unsigned long long parent_tid = -1;
	struct clone_args args = {0};
	args.pidfd = syd_ptr_to_u64(pidfd);
	args.parent_tid = syd_ptr_to_u64(parent_tid);
	args.flags = flags;
	args.exit_signal = exit_signal;

	pid_t pid = syd_clone3(&args);
	if (pid > 0 && (flags & CLONE_PIDFD))
		*pidfd_out = pidfd;
	return pid;
}

SYD_GCC_ATTR((warn_unused_result))
int syd_execv(const char *command,
	      size_t argc, char *const *argv,
	      struct syd_execv_opt *opt)
{
	return execv(command, argv);
}
