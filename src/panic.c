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
	int i, r, pfd;
	char comm[32] = {'\0'};

	if ((r = wait_one(node)) == -ESRCH)
		return r;

	pfd = syd_proc_open(node->pid);
	if (pfd >= 0) {
		syd_proc_comm(pfd, comm, sizeof(comm));
		close(pfd);
	} else {
		comm[0] = '?';
	}
	fprintf(stderr, "sydbox: SIG<%d> -> %d <%s> ", fatal_sig,
		node->pid, comm);
	r = syd_pidfd_send_signal(sydbox->pidfd, fatal_sig, NULL, 0);

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
	syd_process_t *node;

	if (!sydbox)
		return;

	sc_map_foreach_value(&sydbox->tree, node) {
		if (kill_one(node, fatal_sig) == -ESRCH)
			bury_process(node, true);
	}
	cleanup_for_sydbox();
	exit(fatal_sig);
}

SYD_GCC_ATTR((format (printf, 2, 0)))
static void report(syd_process_t *current, const char *fmt, va_list ap)
{
	char cmdline[80], comm[32];
	pid_t ppid, tgid;
	char *cwd = NULL;
	char *context = NULL;

	comm[0] = '\0';
	cmdline[0] = '\0';
	vasprintf(&context, fmt, ap);
	syd_proc_comm(sydbox->pfd, comm, sizeof(comm));
	syd_proc_parents(sydbox->pfd, &ppid, &tgid);
	syd_proc_cwd(sydbox->pfd_cwd, false, &cwd);
	syd_proc_cmdline(sydbox->pfd, cmdline, sizeof(cmdline));
	dump(DUMP_OOPS,
	     isatty(STDERR_FILENO),
	     current->pid, current->tgid, current->ppid,
	     tgid, ppid,
	     current->sysname,
	     context,
	     P_CWD(current), cwd,
	     comm[0] == '\0' ? NULL : comm,
	     cmdline[0] == '\0' ? NULL : cmdline);

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
	exit(128);
}
