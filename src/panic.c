/*
 * sydbox/panic.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2018 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include "pink.h"
#include "xfunc.h"

#include <syd.h>

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

	errno = 0;
	waitpid(node->pid, &status, __WALL|WNOHANG);

	if (errno == ECHILD ||
	    (errno == 0 && (WIFSIGNALED(status) || WIFEXITED(status))))
		return -ESRCH;
	return 0;
}

int kill_one(syd_process_t *node, int fatal_sig)
{
	int i, r;
	char comm[32];

	if ((r = wait_one(node)) == -ESRCH)
		return r;

	const char *name;

	name = pink_name_signal(fatal_sig, 0);
	r = syd_proc_comm(node->pid, comm, sizeof(comm));

	fprintf(stderr, "sydbox: %s -> %d <%s> ", name,
		node->pid, r == 0 ? comm : "?");

	r = pink_trace_kill(node->pid, 0, fatal_sig);

	for (i = 0; i < 3; i++) {
		usleep(10000);

		r = wait_one(node);
		if (r == -ESRCH) {
			fputc('X', stderr);
			fprintf(stderr, " = %s",
				(fatal_sig == SIGKILL) ? "killed" : "terminated");
			break;
		}
		fputc('.', stderr);
	}

	fputc('\n', stderr);
	if (r != -ESRCH && fatal_sig != SIGKILL)
		return kill_one(node, SIGKILL);
	return r;
}

void kill_all(int fatal_sig)
{
	syd_process_t *node, *tmp;

	if (!sydbox)
		return;

	process_iter(node, tmp) {
		if (kill_one(node, fatal_sig) == -ESRCH)
			remove_process_node(node);
	}
	cleanup();
	exit(fatal_sig);
}

PINK_GCC_ATTR((format (printf, 2, 0)))
static void report(syd_process_t *current, const char *fmt, va_list ap)
{
	int r;
	char cmdline[80], comm[32];

	r = syd_proc_comm(current->pid, comm, sizeof(comm));

	say("8< -- Access Violation! --");
	vsay(fmt, ap);
	fputc('\n', stderr);
	say("proc: %s[%u] (parent:%u)", r == 0 ? comm : "?", current->pid, current->ppid);
	say("cwd: `%s'", P_CWD(current));

	if (syd_proc_cmdline(current->pid, cmdline, sizeof(cmdline)) == 0)
		say("cmdline: `%s'", cmdline);

	say(">8 --");
}

int deny(syd_process_t *current, int err_no)
{
	if (sydbox->permissive)
		return 0; /* dry-run, no intervention. */
	current->retval = errno2retval(err_no);
	sydbox->response->val = 0;
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
	remove_process_node(current);
	return r;
}

int violation(syd_process_t *current, const char *fmt, ...)
{
	va_list ap;

	sydbox->violation = true;

	if (!sydbox->permissive) {
		va_start(ap, fmt);
		report(current, fmt, ap);
		va_end(ap);
	}

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
		kill_all(SIGTERM);
		break;
	default:
		assert_not_reached();
	}

	/* exit */
	if (sydbox->config.violation_exit_code > 0)
		exit(sydbox->config.violation_exit_code);
	else if (sydbox->config.violation_exit_code == 0)
		exit(128 + sydbox->config.violation_exit_code);
	exit(sydbox->exit_code);
}
