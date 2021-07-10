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
	      size_t argc, char **argv,
	      struct syd_exec_opt *opt)
{
	int r = 0;

	int death_sig;
	switch (opt->parent_death_signal) {
	case 0: /* Default is SIGKILL. */
		death_sig = SIGKILL;
		break;
	default:
		death_sig = abs(opt->parent_death_signal);
		break;
	}

	if ((r = syd_set_death_sig(death_sig)) < 0) {
		errno = -r;
		syd_say_errno("Error setting parent death signal");
		return r;
	}

	if (opt->pid_env_var) {
		char p[SYD_PID_MAX];
		r = snprintf(p, sizeof(p), "%u", getpid());
		if (r < 0 || (size_t)r >= sizeof(p)) {
			syd_say_errno("Error setting pid environment "
				      "variable");
			return -EINVAL;
		}
		if (setenv(opt->pid_env_var, p, 1) < 0) {
			int save_errno = errno;
			syd_say_errno("Error exporting pid environment variable "
				      "»%s«", opt->pid_env_var);
			return -save_errno;
		}
	}

	if (opt->new_root) {
		syd_say_errno("Moving the root of the file system to the "
			      "directory »%s« and making »%s« the new "
			      "root file system.",
			      opt->put_old, opt->new_root);

		if (syd_pivot_root(opt->new_root, opt->put_old) < 0) {
			int save_errno = errno;
			syd_say_errno("Error changing the root mount");
			return -save_errno;
		}
	}

	if (opt->chroot && chroot(opt->chroot) < 0) {
		int save_errno = errno;
		syd_say_errno("Error changing root directory");
		return -save_errno;
	}

	if (opt->workdir && chdir(opt->workdir) < 0) {
		int save_errno = errno;
		syd_say_errno("Error changing working directory");
		return -save_errno;
	}

	if (opt->gid && setgid(opt->gid) < 0) {
		int save_errno = errno;
		syd_say_errno("Error changing group");
		return -save_errno;
	}

	if (opt->supplementary_gids_length &&
	    setgroups(opt->supplementary_gids_length,
		      opt->supplementary_gids) < 0) {
		int save_errno = errno;
		syd_say_errno("Error setting supplementary groups");
		return -save_errno;
	}

	if (opt->uid && setuid(opt->uid) < 0) {
		int save_errno = errno;
		syd_say_errno("Error changing user");
		return -save_errno;
	}

	if (opt->close_fds_end > opt->close_fds_beg)
		for (int i = opt->close_fds_beg; i <= opt->close_fds_end; i++)
			close(i);

	char *name;
	if (opt->alias)
		name = (char *)opt->alias;
	else if (asprintf(&name, "☮%s", argv[0]) < 0)
		name = argv[0];
	argv[0] = name;
	return execv(command, argv);
}
