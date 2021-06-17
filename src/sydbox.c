/*
 * sydbox/sydbox.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2018, 2020, 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon strace which is:
 *   Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 *   Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 *   Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 *   Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"
#include "compiler.h"
#include "daemon.h"
#include "dump.h"

#include <time.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <getopt.h>
#include <poll.h>
#include <pthread.h>
#include <seccomp.h>
#include "asyd.h"
#include "macro.h"
#include "file.h"
#include "pathlookup.h"
#include "proc.h"
#include "util.h"

#include <syd.h>
#if SYDBOX_DEBUG
# define UNW_LOCAL_ONLY
# include <libunwind.h>
#endif

#ifndef NR_OPEN
# define NR_OPEN 1024
#endif

#define switch_execve_flags(f) ((f) & ~(SYD_IN_CLONE|SYD_IN_EXECVE|SYD_KILLED))

sydbox_t *sydbox;
static unsigned os_release;
static volatile sig_atomic_t interrupted;
static volatile sig_atomic_t alarmed;
static volatile sig_atomic_t child_notified;
static sigset_t empty_set, blocked_set;
static struct sigaction child_sa;

static void dump_one_process(syd_process_t *current, bool verbose);
static void sig_usr(int sig);
static void sig_alrm(int sig);

static inline bool process_is_alive(pid_t pid, pid_t tgid);
static inline int process_reopen_proc_mem(pid_t pid, syd_process_t *current,
					  bool kill_on_error);
static inline pid_t process_find_exec(pid_t pid);
static inline syd_process_t *process_init(pid_t pid, syd_process_t *parent);

static void about(void)
{
	printf(PACKAGE"-"VERSION GITVERSION);

	printf("\nOptions:");
#if SYDBOX_HAVE_DUMP_BUILTIN
	printf(" dump:yes");
#else
	printf(" dump:no");
#endif
	printf(" seccomp:yes");
	printf(" ipv6:yes");
	printf(" netlink:yes");
	fputc('\n', stdout);
}

SYD_GCC_ATTR((noreturn))
static void usage(FILE *outfp, int code)
{
	fprintf(outfp, "\
"PACKAGE"-"VERSION GITVERSION" -- seccomp based application sandbox\n\
usage: "PACKAGE" [-hvb] [--dry-run] [-d <fd|path|tmp>]\n\
              [--export <bpf|pfc:filename>] [--memaccess 0..3]\n\
              [--arch arch...] [--config pathspec...] [--magic magic...]\n\
              [--chroot directory] [--chdir directory]\n\
              [--env var...] [--env var=val...]\n\
              [--ionice class:data] [--nice level]\n\
              [--background] [--stdout logfile] [--stderr logfile]\n\
              [--startas name] [--umask mode]\n\
              [--uid user-id] [--gid group-id] {command [arg...]}\n\
       "PACKAGE" [--export <bpf|pfc:filename>]\n\
              [--arch arch...] [--config pathspec...]\n\
              [--magic command...] {noexec}\n\
       "PACKAGE" --test\n\
\n\
Hey you, out there beyond the wall,\n\
Breaking bottles in the hall,\n\
Can you help me?\n\
\n\
Read the "PACKAGE"(1) manual page for more information.\n\
Send bug reports to \"" PACKAGE_BUGREPORT "\"\n\
Attaching poems encourages consideration tremendously.\n");
	exit(code);
}

#if SYDBOX_DEBUG
static void print_addr_info(FILE *f, unw_word_t ip)
{
	char cmd[256];
	char buf[LINE_MAX];
	FILE *p;

	snprintf(cmd, 256, "addr2line -pfasiC -e /proc/%u/exe %lx", getpid(), ip);
	p = popen(cmd, "r");

	if (p == NULL) {
		fprintf(f, "%s: errno:%d %s\n", cmd, errno, strerror(errno));
		return;
	}

	while (fgets(buf, LINE_MAX, p) != NULL) {
		if (buf[0] == '\0')
			fputs("?\n", f);
		else
			fprintf(f, "\t%s", buf);
	}

	pclose(p);
}

static void print_backtrace(FILE *f)
{
	unw_word_t ip;
	unw_cursor_t cursor;
	unw_context_t uc;

	unw_getcontext(&uc);
	unw_init_local(&cursor, &uc);

	do {
		unw_get_reg(&cursor, UNW_REG_IP, &ip);
		print_addr_info(f, ip);
	} while (unw_step(&cursor) > 0);
}
#endif

static void kill_save_errno(pid_t pid, int sig)
{
	int saved_errno = errno;

	(void) kill(pid, sig);
	errno = saved_errno;
}

static int process_proc(struct syd_process *p)
{
	int r = 0;

	/*
	 * Note: pidfd_open only works with thread-group leaders.
	 * If the process id is not a thread-group leader,
	 * pidfd_open returns EINVAL.
	 */
	if (p->pidfd < 0 &&
	    (p->pidfd = syscall(__NR_pidfd_open, p->pid, 0)) < 0) {
		r = -errno;
		p->pidfd = -1;
		if (errno == EINVAL) {
			; /* process id not a thread-group leader. */
		} else if (proc_esrch(errno)) {
			p->flags |= SYD_KILLED;
			return -ESRCH;
		} else {
			say_errno("pidfd_open(%d)", p->pid);
		}
		goto out;
	}

	if (proc_mem_open_once())
	{
		int memfd;
		if ((memfd = syd_proc_mem_open(p->pid)) < 0) {
			r = -memfd;
			p->memfd = -1;
			if (proc_esrch(-r)) {
				p->flags |= SYD_KILLED;
				return -ESRCH;
			} else if (-r != ENOENT) {
				say_errno("proc_mem_open(%d)", p->pid);
			}
			goto out;
		}
		p->memfd = memfd;
	} else {
		p->memfd = -1;
	}

out:
	return r;
}

static void new_shared_memory_clone_thread(struct syd_process *p)
{
	int r;

	p->shm.clone_thread = xmalloc(sizeof(struct syd_process_shared_clone_thread));
	p->shm.clone_thread->refcnt = 1;
	p->shm.clone_thread->execve_pid = 0;
	if ((r = new_sandbox(&p->shm.clone_thread->box)) < 0) {
		free(p->shm.clone_thread);
		errno = -r;
		die_errno("new_sandbox");
	}
}

static void new_shared_memory_clone_fs(struct syd_process *p)
{
	p->shm.clone_fs = xmalloc(sizeof(struct syd_process_shared_clone_fs));
	p->shm.clone_fs->refcnt = 1;
	p->shm.clone_fs->cwd = NULL;
}

static void new_shared_memory_clone_files(struct syd_process *p)
{
	p->shm.clone_files = xmalloc(sizeof(struct syd_process_shared_clone_files));
	p->shm.clone_files->refcnt = 1;
	if (!sc_map_init_64v(&p->shm.clone_files->sockmap,
			     SYDBOX_SOCKMAP_CAP,
			     SYDBOX_MAP_LOAD_FAC)) {
		errno = -ENOMEM;
		die_errno("failed to initialize sockmap for process %d",
			  p->pid);
	}
}

static void new_shared_memory(struct syd_process *p)
{
	new_shared_memory_clone_thread(p);
	new_shared_memory_clone_fs(p);
	new_shared_memory_clone_files(p);
}

static syd_process_t *new_thread(pid_t pid)
{
	syd_process_t *thread;

	thread = syd_calloc(1, sizeof(syd_process_t));
	if (!thread)
		return NULL;

	thread->pid = pid;
	thread->ppid = SYD_PPID_NONE;
	thread->tgid = SYD_TGID_NONE;

	thread->pidfd = -1;
	thread->memfd = -1;
	/*
	 * process_proc return -ESRCH indicating dead process. In this case
	 * SYD_KILLED flag is already set on the process, so nothing to do here.
	 */
	process_proc(thread);

	process_add(thread);

	dump(DUMP_THREAD_NEW, pid);
	return thread;
}

static syd_process_t *new_process(pid_t pid)
{
	syd_process_t *process;

	process = new_thread(pid);
	if (!process)
		return NULL;
	process->tgid = process->pid;
	new_shared_memory(process);

	return process;
}

static syd_process_t *new_thread_or_kill(pid_t pid)
{
	syd_process_t *thread;

	thread = new_thread(pid);
	if (!thread) {
		kill_save_errno(pid, SIGKILL);
		die_errno("malloc() failed, killed %u", pid);
	}

	return thread;
}

static syd_process_t *new_process_or_kill(pid_t pid)
{
	syd_process_t *process;

	process = new_process(pid);
	if (!process) {
		kill_save_errno(pid, SIGKILL);
		die_errno("malloc() failed, killed %u", pid);
	}

	return process;
}

void reset_process(syd_process_t *p)
{
	if (!p)
		return;

	p->sysnum = 0;
	p->sysname = NULL;
	p->subcall = 0;
	p->retval = 0;

	memset(p->args, 0, sizeof(p->args));
	for (unsigned short i = 0; i < 6; i++) {
		if (p->repr[i]) {
			free(p->repr[i]);
			p->repr[i] = NULL;
		}
	}
}

static inline void save_exit_code(int exit_code)
{
	dump(DUMP_EXIT, exit_code);
	sydbox->exit_code = exit_code;
}

static inline void save_exit_signal(int signum)
{
	save_exit_code(128 + signum);
}

static inline void save_exit_status(int status)
{
	if (WIFEXITED(status))
		save_exit_code(WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		save_exit_signal(WTERMSIG(status));
	else
		save_exit_signal(SIGKILL); /* Assume SIGKILL */
}

static void init_shareable_data(syd_process_t *current, syd_process_t *parent)
{
	bool share_thread, share_fs, share_files;

	if (!parent) {
		int r;
		char *cwd;
		if ((r = proc_cwd(current->pid, sydbox->config.use_toolong_hack,
				  &cwd)) < 0) {
			errno = -r;
			say_errno("proc_cwd");
			P_CWD(current) = strdup("/");
		} else {
			P_CWD(current) = cwd;
		}
		copy_sandbox(P_BOX(current), box_current(NULL));
		return;
	}

	share_thread = share_fs = share_files = false;
	if (parent->new_clone_flags & SYD_CLONE_THREAD)
		share_thread = true;
	if (parent->new_clone_flags & SYD_CLONE_FS)
		share_fs = true;
	if (parent->new_clone_flags & SYD_CLONE_FILES)
		share_files = true;

	/*
	 * Link together for memory sharing, as necessary
	 * Note: thread in this context is any process which shares memory.
	 * (May not always be a real thread: (e.g. vfork)
	 *
	 * Note: If the parent process has magic lock set, this means the
	 * sandbox information can no longer be edited. Treat such cases as
	 * `threads'. (Threads only share sandbox_t which is constant when
	 * magic_lock is set.)
	 * TODO: We need to simplify the sandbox data structure to take more
	 * advantage of such cases and decrease memory usage.
	 */
	current->clone_flags = parent->new_clone_flags;

	if (share_thread || P_BOX(parent)->magic_lock == LOCK_SET) {
		current->shm.clone_thread = parent->shm.clone_thread;
		P_CLONE_THREAD_RETAIN(current);
	} else {
		new_shared_memory_clone_thread(current);
		copy_sandbox(P_BOX(current), box_current(parent));
	}
	if (share_thread)
		P_EXECVE_PID(current) = P_EXECVE_PID(parent);

	if (share_fs) {
		current->shm.clone_fs = parent->shm.clone_fs;
		P_CLONE_FS_RETAIN(current);
	} else {
		new_shared_memory_clone_fs(current);
		P_CWD(current) = xstrdup(P_CWD(parent));
	}

	if (share_files) {
		current->shm.clone_files = parent->shm.clone_files;
		P_CLONE_FILES_RETAIN(current);
	} else {
		new_shared_memory_clone_files(current);
	}
}

static void init_process_data(syd_process_t *current, syd_process_t *parent)
{
	init_shareable_data(current, parent);

	if (sydbox->config.allowlist_per_process_directories &&
	    (!parent || current->pid != parent->pid)) {
		procadd(&sydbox->config.proc_pid_auto, current->pid);
	}
}

static syd_process_t *clone_process(syd_process_t *p, pid_t cpid)
{
	bool new_child;
	syd_process_t *child;

	child = lookup_process(cpid);
	new_child = (child == NULL);

	if (new_child)
		child = new_thread_or_kill(cpid);

	/*
	 * Careful here, the process may still be a thread although new
	 * clone flags is missing CLONE_THREAD
	 */
	if (p->new_clone_flags & SYD_CLONE_THREAD) {
		child->ppid = p->ppid;
		child->tgid = p->tgid;
	} else if (proc_parents(child->pid, &child->tgid, &child->ppid) < 0) {
		say_errno("proc_parents");
		child->ppid = p->pid;
		child->tgid = child->pid;
	}

	if (new_child)
		init_process_data(child, p);

	/* clone OK: p->pid <-> cpid */
	p->new_clone_flags = 0;
	p->flags &= ~SYD_IN_CLONE;
	if (p->flags & SYD_KILLED) {
		/* Parent had died already and we do not need the process entry
		 * anymore. Farewell. */
		bury_process(p);
	}

	return child;
}

void bury_process(syd_process_t *p)
{
	pid_t pid;

	if (!p)
		return;
	pid = p->pid;
	dump(DUMP_THREAD_FREE, pid);

	if (p->pidfd >= 0) {
		close(p->pidfd);
		p->pidfd = -1;
	}
	if (p->memfd >= 0) {
		close(p->memfd);
		p->memfd = -1;
	}
	if (p->abspath) {
		free(p->abspath);
		p->abspath = NULL;
	}
	for (unsigned short i = 0; i < 6; i++) {
		if (p->repr[i]) {
			free(p->repr[i]);
			p->repr[i] = NULL;
		}
	}

	process_remove(p);

	/* Release shared memory */
	P_CLONE_THREAD_RELEASE(p);
	P_CLONE_FS_RELEASE(p);
	P_CLONE_FILES_RELEASE(p);

	if (sydbox->config.allowlist_per_process_directories)
		procdrop(&sydbox->config.proc_pid_auto, pid);

	sc_map_del_64v(&sydbox->tree, pid);
	free(p); /* good bye, good bye, good bye. */
}

/* Drop leader, switch to the thread, reusing leader's tid */
static void tweak_execve_thread(syd_process_t *leader,
				syd_process_t *execve_thread)
{
	if (sydbox->config.allowlist_per_process_directories)
		procdrop(&sydbox->config.proc_pid_auto, execve_thread->pid);
	if (execve_thread->pidfd >= 0) {
		close(execve_thread->pidfd);
		execve_thread->pidfd = -1;
	}
	if (execve_thread->memfd >= 0) {
		close(execve_thread->memfd);
		execve_thread->memfd = -1;
	}
	process_remove(execve_thread);

	execve_thread->pid = leader->pid;
	execve_thread->pidfd = leader->pidfd;
	execve_thread->memfd = leader->memfd;
	execve_thread->flags = switch_execve_flags(leader->flags);
	if (!P_CWD(execve_thread))
		P_CWD(execve_thread) = P_CWD(leader);

	process_add(execve_thread);
}

static void switch_execve_leader(pid_t leader_pid, syd_process_t *execve_thread)
{

	dump(DUMP_EXEC_MT, execve_thread->pid, leader_pid,
	     execve_thread->abspath);

	syd_process_t *leader = lookup_process(leader_pid);
	if (!leader)
		goto out;
	process_remove(leader);

	bool clone_thread = false, clone_fs = false;
	if (P_CLONE_THREAD_REFCNT(leader) > 1) {
		P_CLONE_THREAD_RELEASE(leader);
		clone_thread = true;
	}
	if (P_CLONE_FS_REFCNT(leader) > 1) {
		P_CLONE_FS_RELEASE(leader);
		clone_fs = true;
	}
	P_CLONE_FILES_RELEASE(leader);

	tweak_execve_thread(leader, execve_thread);
	if (execve_thread->abspath)
		free(execve_thread->abspath);

	execve_thread->ppid = leader->ppid;
	execve_thread->tgid = leader->tgid;
	execve_thread->clone_flags = leader->clone_flags;
	execve_thread->abspath = leader->abspath;
	free(leader);

out:
	if (!clone_thread)
		new_shared_memory_clone_thread(execve_thread);
	if (!clone_fs)
		new_shared_memory_clone_fs(execve_thread);
	if (!P_CWD(execve_thread))
		sysx_chdir(execve_thread);
}

void remove_process_node(syd_process_t *p)
{
	if (p->flags & SYD_KILLED) {
		if (sydbox->config.allowlist_per_process_directories)
			procdrop(&sydbox->config.proc_pid_auto, p->pid);
		if (p->pidfd >= 0) {
			close(p->pidfd);
			p->pidfd = -1;
		}
		if (p->memfd >= 0) {
			close(p->memfd);
			p->memfd = -1;
		}
	} else if (p->flags & SYD_IN_CLONE || p->flags & SYD_IN_EXECVE) {
		p->flags |= SYD_KILLED;
		remove_process_node(p);
	} else if (!(p->flags & SYD_KILLED)) {
		bury_process(p);
	}
}

static void remove_process(pid_t pid, int status)
{
	syd_process_t *p;

	if (pid == sydbox->execve_pid)
		save_exit_status(status);

	p = lookup_process(pid);
	if (!p)
		return;
	/* This is a proper exit notification,
	 * no more children expected, clear flags. */
	p->flags &= ~(SYD_IN_CLONE|SYD_IN_EXECVE|SYD_KILLED);

	remove_process_node(p);
}

static syd_process_t *parent_process(pid_t pid_task, syd_process_t *p_task)
{
	pid_t ppid, tgid;
	unsigned short parent_count;
	syd_process_t *parent_node, *node;

	/* Try (really) hard to find the parent process. */

	/* Step 1: Check for ppid entry. */
	if (p_task && p_task->ppid != 0) {
		node = lookup_process(p_task->ppid);
		if (node)
			return node;
		pid_task = p_task->pid;
	}

	/* Step 2: Check /proc/$pid/status
	 * TODO: Two things to consider here:
	 * 1. Is it correct to always prefer Tgid over Ppid?
	 * 2. Is it more reliable to switch steps 2 & 3?
	 */
	if (!proc_parents(pid_task, &tgid, &ppid) &&
			((parent_node = lookup_process(tgid)) ||
			 (tgid != ppid && (parent_node = lookup_process(ppid)))))
		return parent_node;

	/*
	 * Step 3: Check for IN_CLONE|IN_EXECVE flags and /proc/$pid/task
	 * We need IN_EXECVE for threaded exec -> leader lost case.
	 */
	parent_count = 0;
	sc_map_foreach_value(&sydbox->tree, node) {
		if (node->flags & (SYD_IN_CLONE|SYD_IN_EXECVE)) {
			if (!syd_proc_task_find(node->pid, pid_task))
				return node;
			if (parent_count < 2) {
				parent_count++;
				parent_node = node;
			}
		}
	}

	if (parent_count == 1)
		/* We have the suspect! */
		return parent_node;

	return NULL;
}

static void interrupt(int sig)
{
	interrupted = sig;
}

static void sig_alrm(int sig)
{
	alarmed = true;
}

static void sig_chld(int sig, siginfo_t *info, void *ucontext)
{
	pid_t pid = info->si_pid;

	switch (info->si_code) {
	case CLD_EXITED:
		if (pid == sydbox->execve_pid)
			save_exit_code(info->si_status);
		break;
	case CLD_KILLED:
	case CLD_DUMPED:
		if (pid == sydbox->execve_pid)
			save_exit_signal(info->si_status);
		break;
	default:
		return;
	}

	for (;;) {
		int status;
restart_waitpid:
		pid = waitpid(-1, &status, __WALL|WNOHANG);
		if (pid < 0) {
			if (errno == EINTR)
				goto restart_waitpid;
			else if (errno != ECHILD)
				say_errno("waitpid");
			break;
		} else if (pid == sydbox->execve_pid) {
			if (WIFEXITED(status)) {
				sydbox->exit_code = WEXITSTATUS(status);
			} else if (WIFSIGNALED(status)) {
				sydbox->exit_code = 128 + WTERMSIG(status);
			} else {
				sydbox->exit_code = 128;
			}
		}
	}
}

static unsigned get_os_release(void)
{
	unsigned rel;
	const char *p;
	struct utsname u;

	if (uname(&u) < 0)
		die_errno("uname");
	/* u.release has this form: "3.2.9[-some-garbage]" */
	rel = 0;
	p = u.release;
	for (;;) {
		if (!(*p >= '0' && *p <= '9'))
			die("Bad OS release string: '%s'", u.release);
		/* Note: this open-codes KERNEL_VERSION(): */
		rel = (rel << 8) | atoi(p);
		if (rel >= KERNEL_VERSION(1,0,0))
			break;
		while (*p >= '0' && *p <= '9')
			p++;
		if (*p != '.') {
			if (rel >= KERNEL_VERSION(0,1,0)) {
				/* "X.Y-something" means "X.Y.0" */
				rel <<= 8;
				break;
			}
			die("Bad OS release string: '%s'", u.release);
		}
		p++;
	}

	return rel;
}

static void dump_one_process(syd_process_t *current, bool verbose)
{
	int r;
	char comm[32];
	const char *CG, *CB, *CN, *CI, *CE; /* good, bad, important, normal end */
	struct proc_statinfo info;

	pid_t pid = current->pid;
	uint32_t arch = current->arch;
	pid_t ppid = current->ppid;
	pid_t tgid = current->tgid;
	struct acl_node *node;
	struct sockmatch *match;

	if (isatty(STDERR_FILENO)) {
		CG = ANSI_GREEN;
		CB = ANSI_DARK_MAGENTA;
		CI = ANSI_CYAN;
		CN = ANSI_YELLOW;
		CE = ANSI_NORMAL;
	} else {
		CG = CB = CI = CN = CE = "";
	}

	fprintf(stderr, "%s-- Information on Process ID: %u%s\n", CG, pid, CE);
	if (current->pid == sydbox->execve_pid)
		fprintf(stderr, "\t%sParent ID: SYDBOX%s\n", CN, CE);
	else if (current->ppid > 0)
		fprintf(stderr, "\t%sParent ID: %u%s\n", CN, ppid > 0 ? ppid : 0, CE);
	else
		fprintf(stderr, "\t%sParent ID: ? (Orphan)%s\n", CN, CE);
	fprintf(stderr, "\t%sThread Group ID: %u%s\n", CN, tgid > 0 ? tgid : 0, CE);
	if (syd_proc_comm(current->pid, comm, sizeof(comm)) == 0)
		fprintf(stderr, "\t%sComm: `%s'%s\n", CN, comm, CE);
	else
		fprintf(stderr, "\t%sComm: `?'%s\n", CN, CE);
	if (current->shm.clone_fs)
		fprintf(stderr, "\t%sCwd: `%s'%s\n", CN, P_CWD(current), CE);
	fprintf(stderr, "\t%sSyscall: {no:%lu arch:%d name:%s}%s\n", CN,
			current->sysnum, arch, current->sysname, CE);
	fprintf(stderr, "\t%sFlags: ", CN);
	r = 0;
	if (current->flags & SYD_STARTUP) {
		fputs("STARTUP", stderr);
		r = 1;
	}
	if (current->flags & SYD_IN_CLONE) {
		fprintf(stderr, "%sIN_CLONE", (r == 1) ? "|" : "");
		/*r = 1; */
	}

	if (!verbose)
		return;

	if (proc_stat(pid, &info) < 0) {
		fprintf(stderr, "%sproc_stat failed (errno:%d %s)%s\n",
			CB, errno, strerror(errno), CE);
	} else {
		fprintf(stderr, "\t%sproc: pid=%d ppid=%d pgrp=%d%s\n",
			CI,
			info.pid, info.ppid, info.pgrp,
			CE);
		fprintf(stderr, "\t%sproc: comm=`%s' state=`%c'%s\n",
			CI,
			info.comm, info.state,
			CE);
		fprintf(stderr, "\t%sproc: session=%d tty_nr=%d tpgid=%d%s\n",
			CI,
			info.session, info.tty_nr, info.tpgid,
			CE);
		fprintf(stderr, "\t%sproc: nice=%ld num_threads=%ld%s\n",
			CI,
			info.nice, info.num_threads,
			CE);
	}

	if (!current->shm.clone_thread || !current->shm.clone_thread->box)
		return;

	fprintf(stderr, "\t%sSandbox: {exec:%s read:%s write:%s sock:%s}%s\n",
		CN,
		sandbox_mode_to_string(P_BOX(current)->mode.sandbox_exec),
		sandbox_mode_to_string(P_BOX(current)->mode.sandbox_read),
		sandbox_mode_to_string(P_BOX(current)->mode.sandbox_write),
		sandbox_mode_to_string(P_BOX(current)->mode.sandbox_network),
		CE);
	fprintf(stderr, "\t%sMagic Lock: %s%s\n", CN, lock_state_to_string(P_BOX(current)->magic_lock), CE);
	fprintf(stderr, "\t%sExec Whitelist:%s\n", CI, CE);
	ACLQ_FOREACH(node, &P_BOX(current)->acl_exec)
		fprintf(stderr, "\t\t%s`%s'%s\n", CN, (char *)node->match, CE);
	fprintf(stderr, "\t%sRead Whitelist:%s\n", CI, CE);
	ACLQ_FOREACH(node, &P_BOX(current)->acl_read)
		fprintf(stderr, "\t\t%s`%s'%s\n", CN, (char *)node->match, CE);
	fprintf(stderr, "\t%sWrite Whitelist:%s\n", CI, CE);
	ACLQ_FOREACH(node, &P_BOX(current)->acl_write)
		fprintf(stderr, "\t\t%s`%s'%s\n", CN, (char *)node->match, CE);
	fprintf(stderr, "\t%sNetwork Whitelist bind():%s\n", CI, CE);
	ACLQ_FOREACH(node, &P_BOX(current)->acl_network_bind) {
		match = node->match;
		if (match->str) {
			fprintf(stderr, "\t\t%s`%s'%s\n", CN, match->str, CE);
		} else {
			fprintf(stderr, "\t\t%s((%p))%s\n", CN, (void *)match, CE);
		}
	}
	fprintf(stderr, "\t%sNetwork Whitelist connect():%s\n", CI, CE);
	ACLQ_FOREACH(node, &P_BOX(current)->acl_network_connect) {
		match = node->match;
		if (match->str) {
			fprintf(stderr, "\t\t%s`%s'%s\n", CN, match->str, CE);
		} else {
			fprintf(stderr, "\t\t%s((%p))%s\n", CN, (void *)match, CE);
		}
	}
}

static void sig_usr(int sig)
{
	bool complete_dump;
	unsigned count;
	syd_process_t *node;

	if (!sydbox)
		return;

	complete_dump= !!(sig == SIGUSR2);

	fprintf(stderr, "\nsydbox: Received SIGUSR%s\n", complete_dump ? "2" : "1");

#if SYDBOX_DEBUG
	fprintf(stderr, "sydbox: Debug enabled, printing backtrace\n");
	print_backtrace(stderr);
#endif

	fprintf(stderr, "sydbox: Dumping process tree:\n");
	count = 0;
	sc_map_foreach_value(&sydbox->tree, node) {
		dump_one_process(node, complete_dump);
		count++;
	}
	fprintf(stderr, "Tracing %u process%s\n", count, count > 1 ? "es" : "");
}

SYD_GCC_ATTR((unused))
static int proc_info(pid_t pid) {
	char *cmd;

	xasprintf(&cmd, "cat /proc/%d/stat", sydbox->execve_pid);
	system(cmd); free(cmd);
	xasprintf(&cmd, "cat /proc/%d/status", sydbox->execve_pid);
	system(cmd); free(cmd);
	xasprintf(&cmd, "cat /proc/%d/seccomp", sydbox->execve_pid);
	system(cmd); free(cmd);
	xasprintf(&cmd, "cat /proc/%d/syscall", sydbox->execve_pid);
	system(cmd); free(cmd);
	xasprintf(&cmd, "ls -l /proc/%d/fd", sydbox->execve_pid);
	system(cmd); free(cmd);

	return 0;
}

static void reap_zombies(syd_process_t *current, pid_t pid)
{
	if (current)
		remove_process_node(current);
	else if (pid >= 0)
		remove_process(pid, 0);

	syd_process_t *node;
	sc_map_foreach_value(&sydbox->tree, node) {
		if (node->flags & SYD_KILLED) {
			if (!(node->flags & (SYD_IN_CLONE|SYD_IN_EXECVE)))
				remove_process_node(node);
		} else if (!process_is_alive(node->pid, node->tgid)) {
			remove_process_node(node);
		}
	}
}

static bool process_kill(pid_t pid, pid_t tgid, int sig)
{
	int r;
	syd_process_t *current;

	current = lookup_process(pid);
	if (!current)
		return false;
	if (current->pidfd < 0) {
		if (!sig)
			return true;
		if (syd_kill(pid, tgid, sig) == -ESRCH)
			return false;
		return true;
	}

	r = syscall(__NR_pidfd_send_signal, current->pidfd, sig, NULL, 0);
	if (r < 0) {
		if (errno == ESRCH)
			return false;
		say_errno("pidfd_send_signal");
		return false;
	}

	return true;
}

static inline bool process_is_alive(pid_t pid, pid_t tgid)
{
	int r;
	struct proc_statinfo info;

	if (!process_kill(pid, tgid, 0)) {
		return false;
	} else if ((r = proc_stat(pid, &info)) < 0) {
		if (r != -ENOENT && r != -ESRCH)
			say_errno("proc_stat(%d)", pid);
		return false;
	} else if (info.state == 'Z') {
		// Zombie process, not alive.
		return false;
	}
	return true;
}

static inline int process_reopen_proc_mem(pid_t pid, syd_process_t *current,
					  bool kill_on_error)
{
	if (!current && pid >= 0)
		current = lookup_process(pid);
	if (!current)
		return -ESRCH;
	if (!current->update_mem)
		return 0;
	if (current->memfd >= 0) {
		close(current->memfd);
		current->memfd = -1;
	}
	current->memfd = syd_proc_mem_open(current->pid);
	current->update_mem = false;
	if (current->memfd < 0) {
		errno = -current->memfd;
		current->memfd = -1;
		if (proc_esrch(errno)) {
			current->flags |= SYD_KILLED;
			return -ESRCH;
		} else {
			say_errno("proc_mem_open(%d)", current->pid);
		}
		return -errno;
	}
	return 0;
}

static inline pid_t process_find_exec(pid_t exec_pid)
{
	syd_process_t *node;

	sc_map_foreach_value(&sydbox->tree, node) {
		if (node->pid == node->tgid &&
		    !(node->flags & SYD_KILLED) &&
		    proc_has_task(node->pid, exec_pid))
			return node->pid;
	}

	return 0;
}

static syd_process_t *process_init(pid_t pid, syd_process_t *parent)
{
	syd_process_t *current;

	if (parent) {
		current = clone_process(parent, pid);
		parent->clone_flags &= ~SYD_IN_CLONE;
		//if (magic_query_violation_raise_safe(current))
		//	say("new process: %d of parent %d", pid, parent->pid);
	} else {
		current = new_process(pid);
		new_shared_memory_clone_fs(current);
		sysx_chdir(current);
		//if (magic_query_violation_raise_safe(current))
		//	say("new process: %d with no parent", pid);
	}
	reap_zombies(NULL, -1);

	return current;
}

static int wait_for_notify_fd(void)
{
	int r;
	struct pollfd pollfd;

	pollfd.fd = sydbox->notify_fd;
	pollfd.events = POLLIN;
	errno = 0;
	if ((r = poll(&pollfd, 1, 1000)) < 0) {
		if (!errno || errno == EINTR)
			return -ETIMEDOUT;
		return -errno;
	}
	short revents = pollfd.revents;
	if (!r && !revents)
		return -ETIMEDOUT;
	if (revents & POLLIN)
		return 0;
	if (revents & POLLHUP || revents & POLLERR)
		return -ESRCH;
	if (revents & POLLNVAL)
		return -EINVAL;
	assert_not_reached();
}

static void init_early(void)
{
	assert(!sydbox);

	os_release = get_os_release();
	sydbox = xmalloc(sizeof(sydbox_t));
	sydbox->violation = false;
	sydbox->execve_wait = false;
	sydbox->exit_code = EXIT_SUCCESS;
	sydbox->program_invocation_name = NULL;
	sydbox->seccomp_fd = -1;
	sydbox->notify_fd = -1;
#if SYDBOX_HAVE_DUMP_BUILTIN
	sydbox->dump_fd = 0;
#endif
	sydbox->bpf_only = false;
	sydbox->permissive = false;
	sydbox->export_mode = SYDBOX_EXPORT_NUL;
	sydbox->export_path = NULL;
	if (!sc_map_init_64v(&sydbox->tree,
			     SYDBOX_PROCMAP_CAP,
			     SYDBOX_MAP_LOAD_FAC)) {
		errno = ENOMEM;
		die_errno("failed to allocate hashmap for process tree");
	}
	config_init();
	filter_init();
	syd_abort_func(kill_all);
}

static void init_signals(void)
{
	struct sigaction sa;

	sigemptyset(&empty_set);
	sigemptyset(&blocked_set);

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	int r;
#define x_sigaction(sig, act, oldact) \
	do { \
		r = sigaction((sig), (act), (oldact)); \
		if (r < 0) \
			die_errno("sigaction"); \
	} while (0)

	x_sigaction(SIGTTOU, &sa, NULL); /* SIG_IGN */
	x_sigaction(SIGTTIN, &sa, NULL); /* SIG_IGN */
	x_sigaction(SIGTSTP, &sa, NULL); /* SIG_IGN */

	sigaddset(&blocked_set, SIGHUP);
	sigaddset(&blocked_set, SIGINT);
	sigaddset(&blocked_set, SIGQUIT);
	sigaddset(&blocked_set, SIGPIPE);
	sigaddset(&blocked_set, SIGTERM);
	sigaddset(&blocked_set, SIGABRT);
	sigaddset(&blocked_set, SIGUSR1);
	sigaddset(&blocked_set, SIGUSR2);

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = interrupt;
	x_sigaction(SIGHUP, &sa, NULL);
	x_sigaction(SIGINT, &sa, NULL);
	x_sigaction(SIGQUIT, &sa, NULL);
	x_sigaction(SIGPIPE, &sa, NULL);
	x_sigaction(SIGTERM, &sa, NULL);
	x_sigaction(SIGABRT, &sa, NULL);
	x_sigaction(SIGUSR1, &sa, NULL);
	x_sigaction(SIGUSR2, &sa, NULL);

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = sig_alrm;
	x_sigaction(SIGALRM, &sa, NULL);

	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = sig_chld;
	sa.sa_flags = SA_RESTART | SA_SIGINFO;
	x_sigaction(SIGCHLD, &sa, NULL);

#undef x_sigaction
}

static int handle_interrupt(int sig)
{
	switch (sig) {
	case SIGUSR1:
	case SIGUSR2:
		sig_usr(sig);
		return 0;
	default:
		dump(DUMP_INTERRUPT, sig);
		kill_all(sig);
		dump(DUMP_CLOSE);
		return 128 + sig;
	}
}

SYD_GCC_ATTR((unused))
static int check_interrupt(void)
{
	int r = 0;

	sigprocmask(SIG_SETMASK, &empty_set, NULL);
	if (interrupted) {
		int sig = interrupted;
		r = handle_interrupt(sig);
	}
	sigprocmask(SIG_BLOCK, &blocked_set, NULL);

	return r;
}

static int event_clone(syd_process_t *current, const char clone_type,
		       long clone_flags)
{
	assert(current);

	if (!current->new_clone_flags) {
		switch (clone_type) {
		case 'f':
		case 'v':
		case 'c':
			current->new_clone_flags = pack_clone_flags(clone_flags);
			break;
		case '3': /* Cannot decode argument, treat as non-thread */
			current->new_clone_flags = 0;
			break;
		default:
			assert_not_reached();
		}
	}
	current->flags |= SYD_IN_CLONE;

	return 0;
}

static int event_exec(syd_process_t *current)
{
	int r;
	const char *match;

	assert(current);

	if (current->shm.clone_thread &&
	    P_BOX(current)->magic_lock == LOCK_PENDING) {
		/* magic commands are locked */
		P_BOX(current)->magic_lock = LOCK_SET;
	}

	current->flags |= SYD_IN_EXECVE;
	if (current->shm.clone_thread)
		P_EXECVE_PID(current) = current->pid;

	if (!current->abspath) /* nothing left to do */
		return 0;

	/* kill_if_match and resume_if_match */
	r = 0;
	if (acl_match_path(ACL_ACTION_NONE, &sydbox->config.exec_kill_if_match,
			   current->abspath, &match)) {
		say("kill_if_match pattern=`%s' matches execve path=`%s'",
		    match, current->abspath);
		say("killing process");
		process_kill(current->pid, current->tgid, SIGKILL);
		return -ESRCH;
	} else if (acl_match_path(ACL_ACTION_NONE, &sydbox->config.exec_resume_if_match,
				  current->abspath, &match)) {
		say("resume_if_match pattern=`%s' matches execve path=`%s'",
		    match, current->abspath);
		say("detaching from process");
		current->flags |= SYD_DETACHED;
		return -ESRCH;
	}
	/* execve path does not match if_match patterns */

	if (magic_query_violation_raise_safe(current)) {
		say("execve: %d executed `%s'", current->pid, current->abspath);
		dump(DUMP_EXEC, current->pid, current->abspath);
	}

	free(current->abspath);
	current->abspath = NULL;

	return r;
}

static int event_syscall(syd_process_t *current)
{
	return sysnotify(current);
}

static int notify_loop(syd_process_t *current)
{
	int r;
	pid_t pid;

	if ((r = seccomp_notify_alloc(&sydbox->request,
				      &sydbox->response)) < 0) {
		errno = -r;
		die_errno("seccomp_notify_alloc");
	}
	memset(sydbox->response, 0, sizeof(struct seccomp_notif_resp));

	for (;;) {
		char *name = NULL;
		bool jump = false;
		bool update_mem = false, update_mem_now = false;
		syd_process_t *parent;

		pid = sydbox->execve_pid;
wait_for_notify_fd:
		if ((r = wait_for_notify_fd()) < 0) {
			if (r == -ETIMEDOUT) {
				reap_zombies(NULL, -1);
				if (!process_count_alive())
					break;
				goto wait_for_notify_fd;
			} else if (r == -ESRCH) {
				reap_zombies(lookup_process(pid), pid);
				break;
			} else {
				errno = -r;
				say_errno("poll");
				break;
			}
		} /* else { ; } notify fd is ready to read. */

		if (child_notified) {
			pid = child_notified;
			child_notified = 0;

			reap_zombies(lookup_process(pid), pid);
			if (!process_count_alive())
				break;
		}
		memset(sydbox->request, 0, sizeof(struct seccomp_notif));
notify_receive:
		if ((r = seccomp_notify_receive(sydbox->notify_fd,
						sydbox->request)) < 0) {
			if (r == -ECANCELED || r == -EINTR) {
				goto notify_receive;
			} else if (r == -ENOENT) {
				/* If we didn't find a notification,
				 * it could be that the task was
				 * interrupted by a fatal signal between
				 * the time we were woken and
				 * when we were able to acquire the rw lock.
				 */
				reap_zombies(lookup_process(pid), pid);
				continue;
			} else {
				/* TODO use:
				 * __NR_pidfd_send_signal to kill the process
				 * on abnormal exit.
				 */
				say_errno("seccomp_notify_receive");
				break;
			}
		}

		if (sydbox->request->id == 0 && sydbox->request->pid == 0) {
			reap_zombies(NULL, -1);
			continue;
		}
		memset(sydbox->response, 0, sizeof(struct seccomp_notif_resp));
		sydbox->response->id = sydbox->request->id;
		sydbox->response->flags |= SECCOMP_USER_NOTIF_FLAG_CONTINUE;
		sydbox->response->error = 0;
		sydbox->response->val = 0;

		pid = sydbox->request->pid;
		name = seccomp_syscall_resolve_num_arch(sydbox->request->data.arch,
							sydbox->request->data.nr);
		current = lookup_process(pid);
		if (request_is_valid(sydbox->request->id) == -ENOENT) {
			if (current) {
				current->flags |= SYD_KILLED;
				remove_process_node(current);
			}
			if (process_count_alive() == 0)
				jump = true;
			goto out;
		} else if (current &&
			   process_reopen_proc_mem(-1,
						   current,
						   true) == -ESRCH) {
			if (process_count_alive() == 0)
				jump = true;
			goto notify_respond;
		}

		/* Search early for exit before getting a process entry. */
		if (name && (!strcmp(name, "exit") || !strcmp(name, "exit_group"))) {
			//if (pid == sydbox->execve_pid)
			//	sydbox->exit_code = sydbox->request->data.args[0];
			reap_zombies(current, -1);
			if (process_count_alive() == 0)
				jump = true;
			goto notify_respond;
		}

		/* Search early for execve before getting a process entry. */
		if (name && (!strcmp(name, "execve") || !strcmp(name, "execveat"))) {
			/* memfd is no longer valid, reopen next turn,
			 * reading /proc/pid/mem on a process stopped
			 * for execve returns EPERM! */
			update_mem_now = false;
			if (sydbox->execve_wait) { /* allow the initial exec */
				sydbox->execve_wait = false;
				goto notify_respond;
			} else if (proc_mem_open_once()) {
				update_mem = true;
			}
			pid_t execve_pid = 0;
			pid_t leader_pid = process_find_exec(pid);
			if (!current) {
				parent = lookup_process(leader_pid);
				current = process_init(pid, parent);
				assert(current);
			}
			execve_pid = P_EXECVE_PID(current);
			if (execve_pid == 0 && pid != leader_pid) {
				execve_pid = leader_pid;
				current->sysnum = sydbox->request->data.nr;
				current->sysname = name;
			}

			if (execve_pid) {
				if (pid != execve_pid) {
					current = lookup_process(pid);
					assert(current);

					switch_execve_leader(execve_pid,
							     current);
					goto notify_respond;
				}
				P_EXECVE_PID(current) = 0;
				reap_zombies(NULL, -1);
			}
			current->flags &= ~SYD_IN_CLONE;
			event_exec(current);
		}

		if (!current) {
			parent = parent_process(pid, NULL);
			current = process_init(pid, parent);
			assert(current);
		}
		current->sysnum = sydbox->request->data.nr;
		current->sysname = name;
		for (unsigned short idx = 0; idx < 6; idx++)
			current->args[idx] = sydbox->request->data.args[idx];
		if (current->update_cwd) {
			r = sysx_chdir(current);
			if (r < 0)
				say_errno("sys_chdir");
			current->update_cwd = false;
		}
		if (update_mem) {
			current->update_mem = true;
			update_mem = false;
		}
		if (update_mem_now && current->update_mem) {
			update_mem_now = false;
			process_reopen_proc_mem(-1, current, true);
			if (!process_alive(current)) {
				if (process_count_alive() == 0)
					jump = true;
				goto notify_respond;
			}
		}

		if (!name) {
			;
		} else if (!strcmp(name, "clone")) {
			event_clone(current, 'c', current->args[2]);
		} else if (!strcmp(name, "fork")) {
			event_clone(current, 'f', 0);
		} else if (!strcmp(name, "vfork")) {
			event_clone(current, 'v', 0);
		} else if (!strcmp(name, "clone3")) {
			event_clone(current, '3', 0);
		} else if (!strcmp(name, "chdir") || !strcmp(name, "fchdir")) {
			current->flags &= ~SYD_IN_CLONE;
			current->update_cwd = true;
		} else { /* all system calls including exec end up here. */
			current->flags &= ~SYD_IN_CLONE;
			event_syscall(current);
		}

notify_respond:
		/* 0 if valid, ENOENT if not */
		if (request_is_valid(sydbox->request->id) == -ENOENT) {
			if (current) {
				current->flags |= SYD_KILLED;
				remove_process_node(current);
			}
			if (process_count_alive() == 0)
				jump = true;
			goto out;
		}
		if (update_mem_now && current->update_mem) {
			update_mem_now = false;
			process_reopen_proc_mem(-1, current, true);
			if (!process_alive(current)) {
				if (process_count_alive() == 0)
					jump = true;
				goto out;
			}
		}
		if ((r = seccomp_notify_respond(sydbox->notify_fd,
						sydbox->response)) < 0) {
			if (r == -ECANCELED || r == -EINTR) {
				goto notify_respond;
			} else if (r == -ENOENT) {
				/* If we didn't find a notification,
				 * it could be that the task was
				 * interrupted by a fatal signal between
				 * the time we were woken and
				 * when we were able to acquire the rw lock.
				 */
				reap_zombies(current, -1);
			} else {
				/* TODO use:
				 * __NR_pidfd_send_signal to kill the process
				 * on abnormal exit.
				 */
				say_errno("seccomp_notify_respond");
				// proc_info(sydbox->execve_pid);
				break;
			}
		}
out:
		if (name)
			free(name);
		if (jump)
			break;

		/* We handled quick cases, we are permitted to interrupt now. */
		if (check_interrupt() != 0)
			break;
	}

	seccomp_notify_free(sydbox->request, sydbox->response);
	close(sydbox->notify_fd);
	sydbox->notify_fd = -1;
	r = sydbox->exit_code;

	return r;
}

static pid_t startup_child(char **argv)
{
	int r, pfd[2];
	char *pathname = NULL;
	pid_t pid = 0;

	bool noexec = streq(argv[0], SYDBOX_NOEXEC_NAME);
	if (!noexec) {
		pathname = path_lookup(argv[0]);
		if (!pathname)
			die_errno("can't exec `%s'", argv[0]);
	}
	if (pipe2(pfd, O_CLOEXEC|O_DIRECT) < 0)
		die_errno("can't pipe");

	pid = fork();
	if (pid < 0)
		die_errno("can't fork");
	else if (pid == 0) {
		sydbox->in_child = true;
		sydbox->seccomp_fd = pfd[1];

		if (change_umask() < 0)
			say_errno("change_umask");
		if (change_nice() < 0)
			say_errno("change_nice");
		if (change_ionice() < 0)
			say_errno("change_ionice");
		if (change_root_directory() < 0)
			die_errno("change_root_directory");
		if (change_working_directory() < 0)
			die_errno("change_working_directory");
		if (change_group() < 0)
			die_errno("change_group");
		if (change_user() < 0)
			die_errno("change_user");
		if (change_background() < 0)
			die_errno("change_background");
		if ((r = sysinit_seccomp()) < 0) {
			errno = -r;
			if (errno == ENOTTY || errno == ENOENT)
				errno = EINVAL;
			die_errno("seccomp load failed");
		}
		cleanup();
		free(sydbox);
		if (noexec)
			_exit(getenv(SYDBOX_NOEXEC_ENV) ?
				atoi(getenv(SYDBOX_NOEXEC_ENV)) :
				0);
		if (get_startas())
			argv[0] = (char *)get_startas();
		execv(pathname, argv);
		fprintf(stderr, PACKAGE": execv path:\"%s\" failed (errno:%d %s)\n",
			pathname, errno, strerror(errno));
		free(pathname); /* not NULL because noexec is handled above. */
		_exit(EXIT_FAILURE);
	}

	/* write end of the pipe is not used. */
	close(pfd[1]);

	if (sydbox->export_path)
		free(sydbox->export_path);
	if (pathname)
		free(pathname);

	sydbox->execve_pid = pid;
	sydbox->execve_wait = true;

	sydbox->seccomp_fd = pfd[0];
	if (!use_notify()) {
		sydbox->exit_code = 0;
	} else {
		int fd;
		if ((r = parent_read_int(&fd)) < 0) {
			say_errno("failed to load seccomp filters");
			say("Invalid sandbox options given.");
			exit(-r);
		} else {
			sydbox->notify_fd = fd;

			close(pfd[0]);
			sydbox->seccomp_fd = -1;
			//close(pfd[0]); /* read end is no longer necessary */

			if ((sydbox->execve_pidfd = syscall(__NR_pidfd_open, pid, 0)) < 0)
				die_errno("failed to open pidfd for pid:%d", pid);
			if ((fd = syscall(__NR_pidfd_getfd, sydbox->execve_pidfd,
					  fd, 0)) < 0)
				die_errno("failed to obtain seccomp user fd");
			// close(sydbox->notify_fd);
			sydbox->notify_fd = fd;
		}
	}

	return pid;
}

void cleanup(void)
{
	assert(sydbox);

	if (sydbox->seccomp_fd >= 0)
		close(sydbox->seccomp_fd);
	if (sydbox->notify_fd >= 0)
		close(sydbox->notify_fd);

	if (sydbox->program_invocation_name)
		free(sydbox->program_invocation_name);

	const char *path;
	syd_process_t *proc_node;
	sc_map_foreach_value(&sydbox->config.proc_pid_auto, path)
		free((char *)path);
	sc_map_foreach_value(&sydbox->tree, proc_node) {
		if (proc_node->flags & SYD_KILLED)
			proc_node->flags &= ~SYD_KILLED;
		remove_process_node(proc_node);
	}
	sc_map_term_64s(&sydbox->config.proc_pid_auto);
	sc_map_term_64v(&sydbox->tree);

	filter_free();
	// reset_sandbox(&sydbox->config.box_static);

	struct acl_node *acl_node;
	ACLQ_FREE(acl_node, &sydbox->config.exec_kill_if_match, free);
	ACLQ_FREE(acl_node, &sydbox->config.exec_resume_if_match, free);

	ACLQ_FREE(acl_node, &sydbox->config.filter_exec, free);
	ACLQ_FREE(acl_node, &sydbox->config.filter_read, free);
	ACLQ_FREE(acl_node, &sydbox->config.filter_write, free);
	ACLQ_FREE(acl_node, &sydbox->config.filter_network, free_sockmatch);

	systable_free();
}

int main(int argc, char **argv)
{
	int opt, i, r, opt_t[4];
	char *c;
	const char *env;
	struct utsname buf_uts;

	int32_t arch;
	size_t arch_argv_idx = 0;
	char *arch_argv[32] = { NULL };

	/* Early initialisations */
	init_early();

#if SYDBOX_HAVE_DUMP_BUILTIN
	long dump_fd;
	char *end;

# if SYDBOX_DUMP
	sydbox->dump_fd = STDERR_FILENO;
# else
	if (strstr(argv[0], PACKAGE"-dump"))
		sydbox->dump_fd = STDERR_FILENO;
# endif

	const char *shoebox = getenv("SHOEBOX");
	if (shoebox) {
		sydbox->dump_fd = open(shoebox,
				       SYDBOX_DUMP_FLAGS,
				       SYDBOX_DUMP_MODE);
		if (sydbox->dump_fd < 0)
			die_errno("open(`%s')", shoebox);
	}
#endif

	/* Long options are present for compatibility with sydbox-0.
	 * Thus they are not documented!
	 */
	int options_index;
	char *profile_name;
	struct option long_options[] = {
		{"dry-run",	no_argument,		NULL,	0},
		{"profile",	required_argument,	NULL,	1},
		{"help",	no_argument,		NULL,	'h'},
		{"version",	no_argument,		NULL,	'v'},
		{"bpf",		no_argument,		NULL,	'b'},
		{"config",	required_argument,	NULL,	'c'},
		{"magic",	required_argument,	NULL,	'm'},
		{"env",		required_argument,	NULL,	'E'},
		{"arch",	required_argument,	NULL,	'a'},
		{"dump",	no_argument,		NULL,	'd'},
		{"export",	required_argument,	NULL,	'e'},
		{"test",	no_argument,		NULL,	't'},
		{"chdir",	required_argument,	NULL,	'D'},
		{"chroot",	required_argument,	NULL,	'C'},
		{"memaccess",	required_argument,	NULL,	'M'},
		{"background",	no_argument,		NULL,	'B'},
		{"stdout",	required_argument,	NULL,	'1'},
		{"stderr",	required_argument,	NULL,	'2'},
		{"startas",	required_argument,	NULL,	'A'},
		{"ionice",	required_argument,	NULL,	'I'},
		{"nice",	required_argument,	NULL,	'N'},
		{"umask",	required_argument,	NULL,	'K'},
		{"uid",		required_argument,	NULL,	'U'},
		{"gid",		required_argument,	NULL,	'G'},
		{NULL,		0,		NULL,	0},
	};

	const struct sigaction sa = { .sa_handler = SIG_DFL };
	if (sigaction(SIGCHLD, &sa, &child_sa) < 0)
		die_errno("sigaction");

	while ((opt = getopt_long(argc, argv, "a:A:bBc:d:e:C:D:m:E:M:I:N:K:thv1:2:U:G:",
				  long_options, &options_index)) != EOF) {
		switch (opt) {
		case 0:
			sydbox->permissive = true;
			break;
		case 1:
			/* special case for backwards compatibility */
			profile_name = xmalloc(sizeof(char) * (strlen(optarg) + 2));
			profile_name[0] = SYDBOX_PROFILE_CHAR;
			strcpy(&profile_name[1], optarg);
			config_parse_spec(profile_name);
			free(profile_name);
			break;
		case 'a':
			if (arch_argv_idx >= 32)
				die("too many -a arguments");
			arch_argv[arch_argv_idx++] = xstrdup(optarg);
			break;
		case 'b':
			sydbox->bpf_only = true;
			break;
		case 'c':
			config_parse_spec(optarg);
			break;
#if SYDBOX_HAVE_DUMP_BUILTIN
		case 'd':
			sydbox->config.violation_decision = VIOLATION_NOOP;
			magic_set_sandbox_all("dump", NULL);
			if (!optarg) {
				say("option requires an argument: d");
				usage(stderr, 1);
			}
			if (!strcmp(optarg, "tmp")) {
				sydbox->dump_fd = -1;
			} else {
				errno = 0;
				dump_fd = strtoul(optarg, &end, 10);
				if ((errno && errno != EINVAL) ||
				    (unsigned long)dump_fd > INT_MAX)
				{
					say_errno("Invalid argument for option -d: "
						  "`%s'", optarg);
					usage(stderr, 1);
				} else if (end != strchr(optarg, '\0')) {
					dump_fd = open(optarg,
						       SYDBOX_DUMP_FLAGS,
						       SYDBOX_DUMP_MODE);
					if (dump_fd < 0)
						die_errno("Failed to open dump file "
							  "`%s'", optarg);
				}
				if (sydbox->dump_fd > STDERR_FILENO)
					close(sydbox->dump_fd);
				sydbox->dump_fd = (int)dump_fd;
			}
			break;
#else
		case 'd':
			say("dump not supported, compile with --enable-dump");
			usage(stderr, 1);
#endif
		case 'e':
			if (startswith(optarg, "bpf")) {
				sydbox->export_mode = SYDBOX_EXPORT_BPF;
			} else if (startswith(optarg, "pfc")) {
				sydbox->export_mode = SYDBOX_EXPORT_PFC;
			} else {
				say("Invalid argument to --export");
				usage(stderr, 1);
			}
			if (strlen(optarg) > 4 && optarg[3] == ':')
				sydbox->export_path = xstrdup(optarg + 4);
			break;
		case 'm':
			r = magic_cast_string(NULL, optarg, 0);
			if (MAGIC_ERROR(r))
				die("invalid magic: `%s': %s",
				    optarg, magic_strerror(r));
			break;
		case 'A':
			set_startas(xstrdup(optarg));
			break;
		case 'B':
			set_background(true);
			break;
		case '1':
			set_redirect_stdout(xstrdup(optarg));
			break;
		case '2':
			set_redirect_stderr(xstrdup(optarg));
			break;
		case 'C':
			set_root_directory(xstrdup(optarg));
			break;
		case 'D':
			set_working_directory(xstrdup(optarg));
			break;
		case 'I':
			c = strchr(optarg, ':');
			if (!c)
				set_ionice(atoi(optarg), 0);
			else
				set_ionice(atoi(optarg), atoi(c + 1));
			break;
		case 'N':
			set_nice(atoi(optarg));
			break;
		case 'K':
			set_umask(atoi(optarg));
			break;
		case 'U':
			set_uid(atoi(optarg));
			break;
		case 'G':
			set_gid(atoi(optarg));
			break;
		case 'E':
			if (putenv(optarg))
				die_errno("putenv");
			break;
		case 'M':
			errno = 0;
			opt = strtoul(optarg, &end, 10);
			if ((errno && errno != EINVAL) ||
			    (unsigned long)opt > SYDBOX_CONFIG_MEMACCESS_MAX)
			{
				say_errno("Invalid argument for option --memory: "
					  "`%s'", optarg);
				usage(stderr, 1);
			}
			sydbox->config.mem_access = opt;
			break;
		case 't':
			if (uname(&buf_uts) < 0) {
				say_errno("uname");
			} else {
				say("%s/%s %s %s",
				    buf_uts.sysname,
				    buf_uts.nodename,
				    buf_uts.release,
				    buf_uts.version);
			}
			say("[>] Checking for requirements...");
			opt_t[0] = test_cross_memory_attach(true);
			opt_t[1] = test_proc_mem(true);
			opt_t[2] = test_pidfd(true);
			opt_t[3] = test_seccomp(true);
			r = 0;
			for (i = 0; i < 4; i++) {
				if (opt_t[i] != 0) {
					r = opt_t[i];
					break;
				}
			}
			if (opt_t[0] != 0) {
				say("Enable CONFIG_CROSS_MEMORY_ATTACH "
				    "in your kernel configuration "
				    "for cross memory attach to work.");
			}
			if (opt_t[0] != 0 && opt_t[1] != 0) {
				say("warning: Neither cross memory attach "
				    "nor /proc/pid/mem interface is "
				    "available.");
				say("Sandboxing is only supported with bpf "
				    "mode.");
			}
			if (!r)
				say("[>] SydBox is supported on this system!");
			exit(r == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
			break;
		case 'h':
			usage(stdout, 0);
		case 'v':
			about();
			return 0;
		default:
			usage(stderr, 1);
		}
	}

	if (optind == argc) {
		say("No command given.");
		usage(stderr, 1);
	}

	if ((env = getenv(SYDBOX_CONFIG_ENV)))
		config_parse_spec(env);

	config_done();
	sysinit();

	/* Late validations for options */
	if (!sydbox->config.restrict_general &&
	    /*
	    !sydbox->config.restrict_ioctl &&
	    !sydbox->config.restrict_mmap &&
	    !sydbox->config.restrict_shm_wr &&
	    */
	    SANDBOX_OFF_ALL()) {
		say("All restrict and sandbox options are off.");
		die("Refusing to run the program `%s'.", argv[optind]);
	}

	/* initialize Secure Computing */
	if (sydbox->config.restrict_general > 0)
		sydbox->seccomp_action = SCMP_ACT_ERRNO(EPERM);
	else
		sydbox->seccomp_action = SCMP_ACT_ALLOW;
	if (!(sydbox->ctx = seccomp_init(sydbox->seccomp_action)))
		die_errno("seccomp_init");
	if ((r = seccomp_attr_set(sydbox->ctx, SCMP_FLTATR_CTL_OPTIMIZE, 2)) < 0)
		say("can't optimize seccomp filter (%d %s), continuing...",
		    -r, strerror(-r));
	seccomp_arch_add(sydbox->ctx, SCMP_ARCH_NATIVE);
	for (i = arch_argv_idx - 1; i >= 0; i--) {
		if (arch_argv[i] == NULL)
			continue;
		arch = arch_from_string(arch_argv[i]);
		if (arch < 0) {
			errno = EINVAL;
			die_errno("invalid architecture %s", arch_argv[i]);
		}

		r = seccomp_arch_add(sydbox->ctx, (uint32_t)arch);
		if (r == -EINVAL) {
			say("architecture %s: not ok, continuing..",
			    arch_argv[i]);
			say("system calls in arch %s will be killed!",
			    arch_argv[i]);
		}

		free(arch_argv[i]);
	}

	/*
	 * Initial program_invocation_name to be used for P_COMM(current).
	 * Saves one proc_comm() call.
	 */
	sydbox->program_invocation_name = xstrdup(argv[optind]);

	/* Set useful environment variables for children */
	setenv("SYDBOX", SEE_EMILY_PLAY, 1);
	setenv("SYDBOX_VERSION", VERSION, 1);
	setenv("SYDBOX_API_VERSION", STRINGIFY(SYDBOX_API_VERSION), 1);
	setenv("SYDBOX_ACTIVE", THE_PIPER, 1);

	/* Poison! */
	if (streq(argv[optind], "/bin/sh"))
		fprintf(stderr, "[01;35m" PINK_FLOYD "[00;00m");

	/* All ready, initialize dump */
	dump(DUMP_INIT);

	/* STARTUP_CHILD must not be called before the signal handlers get
	   installed below as they are inherited into the spawned process. */
	int exit_code;
	pid_t pid;
	if (use_notify()) {
		init_signals();
		pid = startup_child(&argv[optind]);
		syd_process_t *current = new_process_or_kill(pid);
		init_process_data(current, NULL);
		dump(DUMP_STARTUP, pid);
		(void)notify_loop(current);
	} else {
		int status;
		startup_child(&argv[optind]);
		for (;;) {
			errno = 0;
			pid = waitpid(-1, &status, __WALL);
			switch (errno) {
			case 0:
				if (pid == sydbox->execve_pid) {
					if (WIFEXITED(status))
						sydbox->exit_code =
							WEXITSTATUS(status);
					else if (WIFSIGNALED(status))
						sydbox->exit_code = 128 +
							WTERMSIG(status);
				}
				break;
			case EINTR:
				continue;
			case ECHILD:
				goto out;
			default:
				say_errno("waitpid");
				goto out;
			}
		}
	}
out:
	cleanup();
	exit_code = sydbox->exit_code;
	if (sydbox->violation) {
		if (sydbox->config.violation_exit_code > 0)
			exit_code = sydbox->config.violation_exit_code;
		else if (sydbox->config.violation_exit_code == 0 &&
			 sydbox->exit_code < 128)
			exit_code = 128 /* + sydbox->exit_code */;
	}
	dump(DUMP_ALLOC, 0, NULL);
	dump(DUMP_CLOSE);
	free(sydbox);
	return exit_code;
}
