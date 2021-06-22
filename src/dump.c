/*
 * sydbox/dump.c
 *
 * Event dumper using JSON lines
 *
 * Copyright (c) 2014, 2018, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <time.h>

#include "serializer.h"
#include "errno2name.h"
#include "proc.h"

#define J(s)		"\""#s"\":"
#define J_BOOL(b)	(b) ? "true" : "false"

unsigned long long dump_inspect = INSPECT_DEFAULT;
static FILE *fp;
static char pathdump[PATH_MAX];
static int nodump = -1;
static unsigned long flags = DUMPF_PROCFS;
static unsigned long long id;
static size_t alloc_bytes;

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


static void dump_format(const char *argv0, const char *pathname,
			const char *runas,
			const char*const*arch)
{
	int r;
	char *b_argv0 = NULL;
	char *b_runas = NULL;
	char *b_path = NULL;
	char *j_argv0, *j_runas, *j_path;

	/* Step 1: Generate escaped JSON strings. */
	if (!argv0 || !argv0[0])
		j_argv0 = "";
	else
		j_argv0 = json_escape_str(&b_argv0, argv0);
	if (!runas || !runas[0])
		j_runas = "";
	else
		j_runas = json_escape_str(&b_runas, runas);
	if (!pathname || !pathname[0])
		j_path = "";
	else
		j_path = json_escape_str(&b_path, pathname);

	/* Step 2: Generate JSON array from architectures. */
	char j_arch[(SYD_SECCOMP_ARCH_ARGV_SIZ * (16 + 1)) + 2 /* [] */];
	j_arch[0] = '[';
	char *j_arch_ptr = j_arch + 1;
	if (arch) {
		for (size_t i = 0; arch[i] != NULL; i++) {
			if (i > 0) {
				j_arch_ptr[0] = ',';
				j_arch_ptr++;
			}
			j_arch_ptr[0] = '\0';

			j_arch_ptr[0] = '"'; j_arch_ptr++;
			j_arch_ptr[0] = '\0';

			size_t len = strlen(arch[i]);
			strlcpy(j_arch_ptr, arch[i], len + 1);
			j_arch_ptr += len;

			j_arch_ptr[0] = '"'; j_arch_ptr++;
			j_arch_ptr[0] = '\0';
		}
	}
	j_arch_ptr[0] = ']';
	j_arch_ptr[1] = '\0';

	/* Step 3: Calculate the SHA1 checksum of the
	 * pathname to the command to be executed by
	 * SydBox. This should be enabled with the
	 * magic command core/trace/program_checksum
	 * by setting it to 1 or 2.
	 */
	if (magic_query_trace_program_checksum(NULL) > 0) {
		if (pathname && (r = path_to_hex(pathname)) < 0) {
			errno = -r;
			say_errno("can't calculate checksum of file "
				  "`%s'", pathname);
		}
	}

	fprintf(fp, "{"
		J(id)"%llu,"
		J(syd)"%d,"
		J(cmd)"{"J(name)"\"%s\","
			 J(path)"\"%s\","
			 J(as)"\"%s\","
			 J(hash)"\"%s\"},"
		J(arch)"%s}",
		id++, SYDBOX_API_VERSION,
		j_argv0, j_path, j_runas,
		sydbox->hash, j_arch);

	if (b_argv0)
		free(b_argv0);
	if (b_runas)
		free(b_runas);
	if (b_path)
		free(b_path);
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
	if (what == DUMP_CLOSE) {
		dump_close();
		return;
	}
	if (what == DUMP_FLUSH) {
		dump_flush();
		return;
	}


	va_start(ap, what);
	if (what == DUMP_INIT) {
		const char *argv0 = va_arg(ap, const char *);
		const char *path = va_arg(ap, const char *);
		const char *runas = va_arg(ap, const char *);
		const char *const*arch = va_arg(ap, const char *const*);
		dump_format(argv0, path, runas, arch);
		dump_cycle();
		va_end(ap);
		return;

	}

	if (!inspected_i(what)) {
		va_end(ap);
		return;
	}

	time(&now);

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
			J(sig)"%d",
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
			J(pid)"%u,"
			J(event)"{\"id\":%u,\"name\":\"%s\"}}",
			id++, (unsigned long long)now, pid,
			what, event_name);

	} else if (what == DUMP_STARTUP) {
		pid_t pid = va_arg(ap, pid_t);

		char cmdline[256];
		bool cmd = syd_proc_cmdline(pid, cmdline, sizeof(cmdline)) == 0;

		fprintf(fp, "{"
			J(id)"%llu,"
			J(ts)"%llu,"
			J(pid)"%u,"
			J(event)"{\"id\":%u,\"name\":\"%s\"},"
			J(cmd)"\"%s\"}",
			id++, (unsigned long long)now, pid,
			what, "startup",
			cmd ? cmdline : "");
	} else if (what == DUMP_EXIT) {
		int code = va_arg(ap, int);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(ts)"%llu,"
			J(pid)"%d,"
			J(event)"{\"id\":%u,\"name\":\"exit\"},"
			J(exit_code)"%d}",
			id++, (unsigned long long)now,
			sydbox->execve_pid, what, code);
	} else if (what == DUMP_SYSENT) {
		struct syd_process *current = va_arg(ap, struct syd_process *);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(ts)"%llu,"
			J(pid)"%u,"
			J(event)"{\"id\":%u,\"name\":\"sys\"},"
			J(name)"\"%s\","
			J(args)"[%ld,%ld,%ld,%ld,%ld,%ld],"
			J(repr)"[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]}",
			id++, (unsigned long long)now, current->pid,
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
			J(pid)"%u,"
			J(event)"{\"id\":%u,\"name\":\"chdir\"}",
			id++, (unsigned long long)now, pid,
			what);


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
			J(pid)"%u,"
			J(event)"{\"id\":%u,\"name\":\"exec\"},"
			J(cmd)"\"%s\"}",
			id++, (unsigned long long)now, execve_pid,
			what, prog);
	} else if (what == DUMP_EXEC_MT) {
		pid_t execve_thread, leader;

		execve_thread = va_arg(ap, pid_t);
		leader = va_arg(ap, pid_t);
		const char *prog = va_arg(ap, const char *);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(ts)"%llu,"
			J(event)"{\"id\":%u,\"name\":\"exec_mt\"},"
			J(leader_pid)"%u,"J(execve_pid)"%u,"
			J(cmd)"\"%s\"}",
			id++, (unsigned long long)now, what,
			leader, execve_thread, prog); /* TODO quote: cmd */
	} else if (what == DUMP_ALLOC) {
		size_t size = va_arg(ap, size_t);
		const char *func = va_arg(ap, const char *);

		if (size == 0) {
			size = alloc_bytes;
			func = "sum";
		} else if ((unsigned long long)(alloc_bytes + size) > SIZE_MAX) {
			say("dump: alloc_bytes:%zu overflowed over SIZE_MAX:%zu "
			    "with request:%zu",
			    alloc_bytes, SIZE_MAX, size);
			alloc_bytes = 0;
		} else {
			alloc_bytes += size;
		}
		fprintf(fp, "{"
			J(id)"%llu,"
			J(ts)"%llu,"
			J(event)"{\"id\":%u,\"name\":\"alloc\"},"
			J(size)"%zu,"
			J(func)"\"%s\"}",
			id++, (unsigned long long)now,
			what, size, func);
	} else if (what == DUMP_MEMORY_ACCESS) {
		const char *type = va_arg(ap, const char *);
		pid_t pid = va_arg(ap, pid_t);
		long addr = va_arg(ap, long);
		int err_no = va_arg(ap, int);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(ts)"%llu,"
			J(event)"{\"id\":%u,\"name\":\"memory\"},"
			J(pid)"%d,"
			J(memory)"{"
			J(addr)"%ld,"
			J(errno)"%d,"
			J(type)"\"%s\"},",
			id++, (unsigned long long)now,
			what, pid, addr, err_no, type);

		fprintf(fp, ","J(process));
		dump_process(pid);
		fprintf(fp, "}");
	} else {
		abort();
	}

	dump_cycle();
	va_end(ap);
}
