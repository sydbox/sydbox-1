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

SYD_GCC_ATTR((warn_unused_result))
pid_t syd_clone(int flags, int exit_signal,
		int *pidfd_out,
		pid_t *ptid_out,
		pid_t *ctid_out)
{
	struct clone_args args = {0};

	if (pidfd_out)
		flags |= CLONE_PIDFD;
	if (ptid_out)
		flags |= CLONE_PARENT_SETTID;
	if (ctid_out)
		flags |= CLONE_CHILD_SETTID;
	args.flags = flags;
	args.exit_signal = exit_signal;
	args.pidfd = syd_ptr_to_u64(pidfd_out);
	args.parent_tid = syd_ptr_to_u64(ptid_out);
	args.child_tid = syd_ptr_to_u64(ctid_out);

	return syd_clone3(&args);
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
		syd_say_errno("Error setting parent death signal to »%d«",
			      death_sig);
		/* Continue */
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

	if (opt->map_user != -1 &&
	    syd_map_id(SYD_PATH_PROC_UIDMAP,
		       opt->map_user,
		       opt->real_euid) < 0) {
		int save_errno = errno;
		syd_say_errno("Error mapping current user »%d« to root user.", opt->real_euid);
		return -save_errno;
	}

	/* Since Linux 3.19 unprivileged writing of /proc/self/gid_map
	 * has been disabled unless /proc/self/setgroups is written
	 * first to permanently disable the ability to call setgroups
	 * in that user namespace. */
	if (opt->map_group != (gid_t) -1) {
		if (opt->setgrpcmd == SYD_SETGROUPS_ALLOW) {
			errno = EINVAL;
			syd_say_errno("options setgroups=allow and "
				      "map-group are mutually exclusive.");
			return -EINVAL;
		}
		syd_setgroups_control(SYD_SETGROUPS_DENY);
		syd_map_id(SYD_PATH_PROC_GIDMAP, opt->map_group, opt->real_egid);
	}

	if (opt->setgrpcmd != SYD_SETGROUPS_NONE &&
	    (r = syd_setgroups_control(opt->setgrpcmd)) < 0) {
		errno = -r;
		switch (opt->setgrpcmd) {
		case SYD_SETGROUPS_ALLOW:
			syd_say_errno("Error allowing the »setgroups(2)« system "
				      "call in the user namespace.");
			break;
		case SYD_SETGROUPS_DENY:
			syd_say_errno("Error denying the »setgroups(2)« system "
				      "call in the user namespace.");
			break;
		default:
			abort();
		}
		/* fall through */
	}

	if ((opt->unshare_flags & CLONE_NEWNS) && opt->propagation &&
	    (r = syd_set_propagation(opt->propagation)) < 0) {
		errno = -r;
		syd_say_errno("Error recursively setting the mount propagation "
			      "flag in the new mount namespace.");
		/* fall through */
	}

	if (opt->gid != -1 && setgid(opt->gid) < 0) {
		int save_errno = errno;
		syd_say_errno("Error changing group to »%d«", opt->gid);
		return -save_errno;
	}

	if (opt->supplementary_gids_length &&
	    setgroups(opt->supplementary_gids_length,
		      opt->supplementary_gids) < 0) {
		int save_errno = errno;
		syd_say_errno("Error setting supplementary groups");
		return -save_errno;
	}

	if (opt->uid != -1 && setuid(opt->uid) < 0) {
		int save_errno = errno;
		syd_say_errno("Error changing user to »%d«", opt->uid);
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
