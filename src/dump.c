/*
 * sydbox/dump.c
 *
 * Event dumper using JSON lines
 *
 * Copyright (c) 2014, 2018, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>

#include "dump.h"
#include "errno2name.h"
#include "path.h"
#include "proc.h"
#include "bsd-compat.h"

#define J(s)		"\""#s"\":"
#define J_BOOL(b)	(b) ? "true" : "false"

unsigned long dump_inspect = INSPECT_DEFAULT;
static FILE *fp;
static char pathdump[PATH_MAX];
static int nodump = -1;
static unsigned long flags = DUMPF_PROCFS;
static unsigned long long id;

static void dump_flush(void)
{
	fflush(fp);
}

static void dump_cycle(void)
{
	fputs("\n", fp);
	dump_flush();
}

static void dump_close(void)
{
	if (!fp)
		return;

	dump_flush();
	fclose(fp);
	fp = NULL;
	if (pathdump[0] != '\0')
		say("dumped core `%s' for inspection.", pathdump);
}

static void dump_null(void)
{
	fprintf(fp, "null");
}

static void dump_errno(int err_no)
{
	fprintf(fp, "{"
		J(errno)"%d,"
		J(errno_name)"\"%s\""
		"}",
		err_no, errno2name(err_no));
}

static void dump_format(void)
{
	fprintf(fp, "{"
		J(id)"%llu,"
		J(shoebox)"%u,"
		J(name)"\"%s\"}",
		id++, DUMP_FMT,
		sydbox->program_invocation_name);
}

static void dump_proc_statinfo(const struct proc_statinfo *info)
{
	fprintf(fp, "{"
		J(pid)"%d,"J(ppid)"%d,"J(pgrp)"%d,"
		J(comm)"\"%s\","J(state)"\"%c\","
		J(session)"%d,"J(tty_nr)"%d,"J(tpgid)"%d,"
		J(nice)"%ld,"J(num_threads)"%ld"
		"}",
		info->pid, info->ppid, info->pgrp,
		info->comm, info->state,
		info->session, info->tty_nr, info->tpgid,
		info->nice, info->num_threads);
}

static void dump_process(pid_t pid)
{
	struct proc_statinfo info;
	syd_process_t *p;

	fprintf(fp, "{"J(pid)"%d", pid);

	if (pid <= 0) {
		fprintf(fp, "}");
		return;
	}

	fprintf(fp, ","J(stat));
	if (flags & DUMPF_PROCFS) {
		int r;
		r = proc_stat(pid, &info);
		if (r < 0)
			dump_errno(-r);
		else
			dump_proc_statinfo(&info);
	} else {
		dump_null();
	}

	/* Query SydBox process record */
	p = lookup_process(pid);

	fprintf(fp, ","J(execve_pid));
	if (!p)
		dump_null();
	else if (p->shm.clone_thread && p->shm.clone_thread->execve_pid)
		fprintf(fp, "%d", p->shm.clone_thread->execve_pid);
	else
		dump_null();

	fprintf(fp, ","J(cwd));
	if (!p)
		dump_null();
	else if (p->shm.clone_fs && p->shm.clone_fs->cwd)
		fprintf(fp, "\"%s\"", p->shm.clone_fs->cwd);
	else
		dump_null();

	fprintf(fp, ","J(rec));
	if (p) {
		fprintf(fp, "{"
			J(flag_STARTUP)"%s,"
			J(flag_IN_CLONE)"%s,"
			J(flag_IN_EXECVE)"%s,"
			J(flag_KILLED)"%s,"
			J(flag_DETACHED)"%s,"
			J(ref_CLONE_THREAD)"%u,"
			J(ref_CLONE_FS)"%u,"
			J(ref_CLONE_FILES)"%u,"
			J(ppid)"%d,"
			J(tgid)"%d,"
			J(syscall_no)"%lu,"
			J(syscall_arch)"%u",
			J_BOOL(p->flags & SYD_STARTUP),
			J_BOOL(p->flags & SYD_IN_CLONE),
			J_BOOL(p->flags & SYD_IN_EXECVE),
			J_BOOL(p->flags & SYD_KILLED),
			J_BOOL(p->flags & SYD_DETACHED),
			p->shm.clone_thread ? p->shm.clone_thread->refcnt : 0,
			p->shm.clone_fs ? p->shm.clone_fs->refcnt : 0,
			p->shm.clone_files ? p->shm.clone_files->refcnt : 0,
			p->ppid,
			p->tgid,
			p->sysnum,
			p->arch
			);
		if (p->sysname)
			fprintf(fp, ","J(syscall_name)"\"%s\"", p->sysname);

		fprintf(fp, "}");
	} else {
		dump_null();
	}

	/*
	fprintf(fp, ","J(clone_flags));
	dump_clone_flags(p->clone_flags);
	fprintf(fp, ","J(new_clone_flags));
	dump_clone_flags(p->new_clone_flags);

	fprintf(fp, ","J(sandbox)"");
	if (!(flags & DUMPF_SANDBOX) || !p->shm.clone_thread)
		dump_null();
	else
		dump_sandbox(p->shm.clone_thread->box);
	*/

	fprintf(fp, "}");
}

static int dump_init(void)
{
	int fd = -1;
	const char *pathname;

	if (!nodump)
		return -EINVAL;
	if (nodump > 0)
		return 0;

#if SYDBOX_HAVE_DUMP_BUILTIN
	fd = sydbox->dump_fd;
#endif
	if (fd < 0) {
		pathname = getenv(DUMP_ENV);
		if (pathname) {
			strlcpy(pathdump, pathname, sizeof(pathdump));
		} else {
			char template[] = "/tmp/sydbox-XXXXXX";
			if (!mkdtemp(template))
				die_errno("mkdtemp_dump");
			strlcpy(pathdump, template, sizeof(pathdump));
			strlcat(pathdump, "/", sizeof(pathdump));
			strlcat(pathdump, DUMP_NAME, sizeof(pathdump));
		}
		fd = open(pathdump, O_CREAT|O_APPEND|O_WRONLY|O_NOFOLLOW, 0600);
		if (fd < 0)
			die_errno("open_dump(`%s')", pathdump);
		if (sydbox->config.violation_decision == VIOLATION_NOOP) {
			say("dumping core `%s' for inspection.", pathdump);
		}
	}
	fp = fdopen(fd, "a");
	if (!fp)
		die_errno("fdopen_dump");
	if (fd > STDERR_FILENO &&
	    fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
		die_errno("fcntl");
	nodump = 1;

	dump_format();
	dump_cycle();
	atexit(dump_close);
	return 0;
}

void dump(enum dump what, ...)
{
	va_list ap;
	time_t now;

	if (!inspecting())
		return;

	if (dump_init() != 0)
		return;
	if (what == DUMP_INIT)
		return;
	if (what == DUMP_CLOSE) {
		dump_close();
		return;
	}
	if (what == DUMP_FLUSH) {
		dump_flush();
		return;
	}

	if (!inspected_i(what))
		return;

	time(&now);
	va_start(ap, what);

	if (what == DUMP_ASSERT) {
		const char *expr = va_arg(ap, const char *);
		const char *file = va_arg(ap, const char *);
		const char *line = va_arg(ap, const char *);
		const char *func = va_arg(ap, const char *);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(ts)"%llu,"
			J(event)"{\"id\":%u,\"name\":\"%s\"},",
			id++, (unsigned long long)now,
			DUMP_ASSERT, "assert");

		fprintf(fp, ","J(assert)"{"
			J(expr)"\"%s\","
			J(file)"\"%s\","
			J(line)"\"%s\","
			J(func)"\"%s\"}}",
			expr, file, line, func);
	} else if (what == DUMP_INTERRUPT) {
		int sig = va_arg(ap, int);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(ts)"%llu,"
			J(event)"{\"id\":%u,\"name\":\"%s\"},"
			J(signal)"%d",
			id++, (unsigned long long)now,
			DUMP_INTERRUPT, "interrupt", sig);

		fprintf(fp, "}");
	} else if (what == DUMP_THREAD_NEW || what == DUMP_THREAD_FREE) {
		pid_t pid = va_arg(ap, pid_t);
		const char *event_name;

		if (what == DUMP_THREAD_NEW)
			event_name = "thread_new";
		else /* if (what == DUMP_THREAD_FREE) */
			event_name = "thread_free";

		fprintf(fp, "{"
			J(id)"%llu,"
			J(ts)"%llu,"
			J(event)"{\"id\":%u,\"name\":\"%s\"},"
			J(pid)"%d",
			id++, (unsigned long long)now,
			what, event_name, pid);

		fprintf(fp, ","J(process));
		dump_process(pid);
		fprintf(fp, "}");
	} else if (what == DUMP_STARTUP) {
		pid_t pid = va_arg(ap, pid_t);

		char cmdline[256];
		bool cmd = syd_proc_cmdline(pid, cmdline, sizeof(cmdline)) == 0;

		fprintf(fp, "{"
			J(id)"%llu,"
			J(ts)"%llu,"
			J(event)"{\"id\":%u,\"name\":\"%s\"},"
			J(pid)"%d,"
			J(cmd)"\"%s\"",
			id++, (unsigned long long)now,
			what, "startup", pid,
			cmd ? cmdline : "");
		fprintf(fp, ","J(process));
		dump_process(pid);
		fprintf(fp, "}");
	} else if (what == DUMP_EXIT) {
		int code = va_arg(ap, int);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(ts)"%llu,"
			J(event)"{\"id\":%u,\"name\":\"exit\"},"
			J(pid)"%d,"
			J(exit_code)"%d",
			id++, (unsigned long long)now,
			what, sydbox->execve_pid, code);
		fprintf(fp, ","J(process));
		dump_process(sydbox->execve_pid);
		fprintf(fp, "}");
	} else if (what == DUMP_SYSENT) {
		struct syd_process *current = va_arg(ap, struct syd_process *);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(ts)"%llu,"
			J(event)"{\"id\":%u,\"name\":\"sys\"},"
			J(name)"\"%s\","
			J(args)"[%ld,%ld,%ld,%ld,%ld,%ld],"
			J(repr)"[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]}",
			id++, (unsigned long long)now,
			what,
			current->sysname,
			current->args[0],
			current->args[1],
			current->args[2],
			current->args[3],
			current->args[4],
			current->args[5],
			current->repr[0] ? current->repr[0] : "",
			current->repr[1] ? current->repr[1] : "",
			current->repr[2] ? current->repr[2] : "",
			current->repr[3] ? current->repr[3] : "",
			current->repr[4] ? current->repr[4] : "",
			current->repr[5] ? current->repr[5] : "");
	} else if (what == DUMP_CHDIR) {
		pid_t pid = va_arg(ap, pid_t);
		const char *newcwd = va_arg(ap, const char *);
		const char *oldcwd = va_arg(ap, const char *);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(ts)"%llu,"
			J(event)"{\"id\":%u,\"name\":\"chdir\"}",
			id++, (unsigned long long)now,
			what);

		fprintf(fp, ","J(process));
		dump_process(pid);

		fprintf(fp, ","J(cwd)"{");

		fprintf(fp, J(new));
		if (newcwd)
			fprintf(fp, "\"%s\"", newcwd);
		else
			dump_null();
		fprintf(fp, ","J(old));
		if (oldcwd)
			fprintf(fp, "\"%s\"", oldcwd);
		else
			dump_null();

		fprintf(fp, "}}");
	} else if (what == DUMP_EXEC) {
		pid_t execve_pid = va_arg(ap, pid_t);
		const char *prog = va_arg(ap, const char *);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(ts)"%llu,"
			J(event)"{\"id\":%u,\"name\":\"exec\"}",
			id++, (unsigned long long)now,
			what);

		fprintf(fp, ","J(process));
		dump_process(execve_pid);

		fprintf(fp, ","J(prog));
		if (prog)
			fprintf(fp, "\"%s\"", prog);
		else
			dump_null();

		fprintf(fp, "}");
	} else if (what == DUMP_EXEC_MT) {
		pid_t execve_thread, leader;

		execve_thread = va_arg(ap, pid_t);
		leader = va_arg(ap, pid_t);
		const char *prog = va_arg(ap, const char *);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(ts)"%llu,"
			J(event)"{\"id\":%u,\"name\":\"exec_mt\"}",
			id++, (unsigned long long)now,
			what);

		fprintf(fp, ","J(prog));
		if (prog)
			fprintf(fp, "\"%s\"", prog);
		else
			dump_null();

		fprintf(fp, ","J(leader_thread));
		dump_process(leader);
		fprintf(fp, ","J(execve_thread));
		dump_process(execve_thread);
		fprintf(fp, "}");
	} else {
		abort();
	}

	dump_cycle();
	va_end(ap);
}
