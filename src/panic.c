/*
 * sydbox/panic.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2018 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "syd-box.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "proc.h"

static inline int errno2retval(int err_no)
{
#if 0
#warning pink_ptrace() handles this oddity!
	if (errno == EIO) {
		/* Quoting ptrace(2):
		 * There  was  an  attempt  to read from or write to an
		 * invalid area in the parent's or child's memory,
		 * probably because the area wasn't mapped or
		 * accessible. Unfortunately, under Linux, different
		 * variations of this fault will return EIO or EFAULT
		 * more or less arbitrarily.
		 */
		/* For consistency we change the errno to EFAULT here.
		 * Because it's usually what we actually want.
		 * For example:
		 * open(NULL, O_RDONLY) (returns: -1, errno: EFAULT)
		 * under ptrace, we may get errno: EIO
		 */
		return -EFAULT;
	}
#endif
	return -err_no;
}

static int wait_one(syd_process_t *node)
{
	int status;

	if (waitpid(node->pid, &status, __WALL|WNOHANG) == -1)
		return (errno == ECHILD) ? -ESRCH : -errno;
	if ((WIFSIGNALED(status) || WIFEXITED(status)))
		return -ESRCH;
	return 0;
}

int kill_one(syd_process_t *node, int fatal_sig)
{
	int i, r;

	if ((r = wait_one(node)) == -ESRCH)
		return r;

	if (node->pidfd == 0)
		node->pidfd = syd_pidfd_open(node->pid, 0);
	if (node->pidfd > 0)
		r = syd_pidfd_send_signal(node->pidfd, fatal_sig, NULL, 0);

	for (i = 0; i < 3; i++) {
		usleep(10000);

		r = wait_one(node);
		if (r == -ESRCH) {
			dump(DUMP_KILL, node, fatal_sig);
			break;
		}
		r = -EINVAL;
	}

	if (r != -ESRCH && fatal_sig != SIGKILL)
		return kill_one(node, SIGKILL);
	return r;
}

void kill_all(int fatal_sig)
{
	syd_process_t *node;

	if (!sydbox)
		return;

	if (syd_map_size_64v(&sydbox->tree)) {
		syd_map_foreach_value(&sydbox->tree, node) {
			if (kill_one(node, fatal_sig) == -ESRCH)
				bury_process(node, true);
		}
	} else {
		node = process_lookup(sydbox->execve_pid);
		if (node && kill_one(node, fatal_sig) == -ESRCH)
			bury_process(node, true);
	}
}

void kill_all_skip(int fatal_sig, pid_t skip_pid)
{
	syd_process_t *node;

	if (!sydbox)
		return;

	syd_map_foreach_value(&sydbox->tree, node) {
		if (skip_pid && node->pid == skip_pid)
			continue;
		if (kill_one(node, fatal_sig) == -ESRCH)
			bury_process(node, true);
	}
}

SYD_GCC_ATTR((format (printf, 2, 0)))
static void report(syd_process_t *current, const char *fmt, va_list ap)
{
	int r;
	char comm[32];
	pid_t ppid, tgid;
	char *cwd = NULL;
	char *context = NULL;

	comm[0] = '\0';
	r = vasprintf(&context, fmt, ap);
	syd_proc_comm(sydbox->pfd, comm, sizeof(comm));
	syd_proc_parents(sydbox->pfd, &ppid, &tgid);
	syd_proc_cwd(sydbox->pfd_cwd, false, &cwd);
	dump(DUMP_OOPS,
	     current, tgid, ppid,
	     r == -1 ? NULL : context,
	     cwd, isatty(STDERR_FILENO));

	if (context)
		free(context);
	if (cwd)
		free(cwd);
}

int deny(syd_process_t *current, int err_no)
{
	if (sydbox->permissive)
		return 0; /* dry-run, no intervention. */
	current->retval = errno2retval(err_no);
	sydbox->response->val = 0;
	/*
	 * We expect the caller to set this.
	 * sydbox->response->val = -1;
	 * requires SCMP_FLTATR_API_TSKIP
	 */
	sydbox->response->error = -err_no;
	sydbox->response->flags = 0; /* drop SECCOMP_USER_NOTIF_FLAG_CONTINUE */

	return 0;
}

int restore(syd_process_t *current)
{
	int retval, error;

	if (sydbox->permissive)
		return 0; /* dry-run, no intervention. */

	/* return the saved return value */
	if (current->retval < 0) { /* failure */
		retval = -1;
		error = -current->retval;
	} else { /* success */
		retval = current->retval;
		error = 0;
	}

	return syd_write_retval(current, retval, error);
}

int panic(syd_process_t *current)
{
	int r;

	r = kill_one(current, SIGTERM);
	bury_process(current, true);
	return r;
}

int violation(syd_process_t *current, const char *fmt, ...)
{
	sydbox->violation = true;

	if (!sydbox->permissive) {
		va_list ap;
		va_start(ap, fmt);
		report(current, fmt, ap);
		va_end(ap);
	}

	//sig_usr(SIGUSR2);

	switch (sydbox->config.violation_decision) {
	case VIOLATION_NOOP:
	case VIOLATION_DENY:
		return 0; /* Let the caller handle this */
	case VIOLATION_KILL:
		say("VIOLATION_KILL");
		kill_one(current, SIGTERM);
		return -ESRCH;
	case VIOLATION_KILLALL:
		say("VIOLATION_KILLALL");
		kill_all(SIGLOST);
		cleanup_for_sydbox();
		exit(128 + SIGLOST);
	default:
		assert_not_reached();
	}

	/* exit */
	if (sydbox->config.violation_exit_code > 0)
		exit(sydbox->config.violation_exit_code);
	else if (sydbox->config.violation_exit_code == 0)
		exit(128 + sydbox->config.violation_exit_code);
	exit(128);
}

void sayv(SYD_GCC_ATTR((unused)) const char *fmt, ...)
{
#if SYDBOX_DUMP || SYDBOX_HAVE_DUMP_BUILTIN
	if (!dump_enabled())
		return;

	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 0);
	va_end(ap);
	fputc('\n', stderr);
#else
	return;
#endif
}

SYD_GCC_ATTR((nonnull(1)))
int log_path(const syd_process_t *restrict current,
	     int fd,
	     const aclq_t *restrict acl,
	     uint8_t arg_index,
	     const char *restrict abspath)
{
	if (fd == -1)
		return -EBADF;
	if (!acl_match_path(ACL_ACTION_NONE, acl, abspath, NULL))
		return -ENOENT;

	time_t now = time(NULL);
	switch (arg_index) {
	case 0:
		return dprintf(fd,
			       "%s=%"PRIu64"@%ld%c%#x=»%s«%c%#x%c%#x%c%#x%c%#x%c%#x\n",
			       current->sysname, current->sysnum, now,
			       SYD_ARG_SEP,
			       (unsigned int)current->args[0],
			       abspath,
			       SYD_ARG_SEP,
			       (unsigned int)current->args[1], SYD_ARG_SEP,
			       (unsigned int)current->args[2], SYD_ARG_SEP,
			       (unsigned int)current->args[3], SYD_ARG_SEP,
			       (unsigned int)current->args[4], SYD_ARG_SEP,
			       (unsigned int)current->args[5]);
	case 1:
		return dprintf(fd,
			       "%s=%"PRIu64"@%ld%c%#x%c%#x=»%s«%c%#x%c%#x%c%#x%c%#x\n",
			       current->sysname, current->sysnum, now,
			       SYD_ARG_SEP,
			       (unsigned int)current->args[0], SYD_ARG_SEP,
			       (unsigned int)current->args[1],
			       abspath,
			       SYD_ARG_SEP,
			       (unsigned int)current->args[2], SYD_ARG_SEP,
			       (unsigned int)current->args[3], SYD_ARG_SEP,
			       (unsigned int)current->args[4], SYD_ARG_SEP,
			       (unsigned int)current->args[5]);
	default:
		return -EOPNOTSUPP;
	}
}
