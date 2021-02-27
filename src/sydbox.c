/*
 * sydbox/sydbox.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2020, 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon strace which is:
 *   Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 *   Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 *   Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 *   Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * Released under the terms of the 3-clause BSD license
 */

#include "sydbox.h"
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
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <getopt.h>
#include "asyd.h"
#include "macro.h"
#include "file.h"
#include "pathlookup.h"
#include "proc.h"
#include "util.h"
#if SYDBOX_HAVE_SECCOMP
#include "seccomp.h"
#endif

#include <syd.h>
#if SYDBOX_DEBUG
# define UNW_LOCAL_ONLY
# include <libunwind.h>
#endif

#if PINK_HAVE_SEIZE
static int post_attach_sigstop = SYD_IGNORE_ONE_SIGSTOP;
# define syd_use_seize (post_attach_sigstop == 0)
#else
# define post_attach_sigstop SYD_IGNORE_ONE_SIGSTOP
# define syd_use_seize 0
#endif

#ifndef NR_OPEN
# define NR_OPEN 1024
#endif

#define switch_execve_flags(f) ((f) & ~(SYD_IN_CLONE|SYD_IN_EXECVE|SYD_IN_SYSCALL|SYD_KILLED))

sydbox_t *sydbox;
static unsigned os_release;
static volatile sig_atomic_t interrupted;
static sigset_t empty_set, blocked_set;
static struct sigaction child_sa;

static void dump_one_process(syd_process_t *current, bool verbose);
static void sig_usr(int sig);

static void about(void)
{
	printf(PACKAGE"-"VERSION GITVERSION);
	printf(" (pinktrace-%d.%d.%d",
	       PINKTRACE_VERSION_MAJOR,
	       PINKTRACE_VERSION_MINOR,
	       PINKTRACE_VERSION_MICRO);

	if (STRLEN_LITERAL(PINKTRACE_VERSION_SUFFIX) > 0)
		fputs(PINKTRACE_VERSION_SUFFIX, stdout);
	if (STRLEN_LITERAL(PINKTRACE_GIT_HEAD) > 0)
		printf(" git:%s", PINKTRACE_GIT_HEAD);
	puts(")");

	printf("Options:");
#if SYDBOX_HAVE_SECCOMP
	printf(" seccomp:yes");
#else
	printf(" seccomp:no");
#endif
	printf(" ipv6:%s", PINK_HAVE_IPV6 ? "yes" : "no");
	printf(" netlink:%s", PINK_HAVE_NETLINK ? "yes" : "no");
	fputc('\n', stdout);
}

PINK_GCC_ATTR((noreturn))
static void usage(FILE *outfp, int code)
{
	fprintf(outfp, "\
"PACKAGE"-"VERSION GITVERSION" -- ptrace & seccomp based sandbox\n\
usage: "PACKAGE" [-hv] [-c pathspec...] [-m magic...] [-E var=val...] {command [arg...]}\n\
-h          -- Show usage and exit\n\
-v          -- Show version and exit\n\
-c pathspec -- path spec to the configuration file, may be repeated\n\
-m magic    -- run a magic command during init, may be repeated\n\
-E var=val  -- put var=val in the environment for command, may be repeated\n\
-E var      -- remove var from the environment for command, may be repeated\n\
\n\
Hey you, out there beyond the wall,\n\
Breaking bottles in the hall,\n\
Can you help me?\n\
\n\
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

static void new_shared_memory_clone_thread(struct syd_process *p)
{
	int r;

	p->shm.clone_thread = xmalloc(sizeof(struct syd_process_shared_clone_thread));
	p->shm.clone_thread->refcnt = 1;
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
	p->shm.clone_files->savebind = NULL;
	p->shm.clone_files->sockmap = NULL;
}

static void new_shared_memory(struct syd_process *p)
{
	new_shared_memory_clone_thread(p);
	new_shared_memory_clone_fs(p);
	new_shared_memory_clone_files(p);
}

static syd_process_t *new_thread(pid_t pid, short flags)
{
	int r;
	syd_process_t *thread;

	thread = calloc(1, sizeof(syd_process_t));
	if (!thread)
		return NULL;

	thread->pid = pid;
	thread->ppid = SYD_PPID_NONE;
	thread->tgid = SYD_TGID_NONE;

	if ((r = pink_regset_alloc(&thread->regset)) < 0) {
		free(thread);
		errno = -r;
		return NULL;
	}

	thread->abi = PINK_ABI_DEFAULT;
	thread->flags = SYD_STARTUP | flags;
	thread->trace_step = SYD_STEP_NOT_SET;

	process_add(thread);

	dump(DUMP_THREAD_NEW, pid);
	return thread;
}

static syd_process_t *new_process(pid_t pid, short flags)
{
	syd_process_t *process;

	process = new_thread(pid, flags);
	if (!process)
		return NULL;
	process->tgid = process->pid;
	new_shared_memory(process);

	return process;
}

static syd_process_t *new_thread_or_kill(pid_t pid, short flags)
{
	syd_process_t *thread;

	thread = new_thread(pid, flags);
	if (!thread) {
		kill_save_errno(pid, SIGKILL);
		die_errno("malloc() failed, killed %u", pid);
	}

	return thread;
}

static syd_process_t *new_process_or_kill(pid_t pid, short flags)
{
	syd_process_t *process;

	process = new_process(pid, flags);
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
	memset(p->args, 0, sizeof(p->args));
	p->subcall = 0;
	p->retval = 0;
	p->flags &= ~SYD_STOP_AT_SYSEXIT;

	if (P_SAVEBIND(p)) {
		free_sockinfo(P_SAVEBIND(p));
		P_SAVEBIND(p) = NULL;
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
		P_CWD(current) = xgetcwd(); /* FIXME: too long hack changes
					       directories, this may not work! */
		copy_sandbox(P_BOX(current), box_current(NULL));
		return;
	}

	share_thread = share_fs = share_files = false;
	if (parent->new_clone_flags & CLONE_THREAD)
		share_thread = true;
	if (parent->new_clone_flags & CLONE_FS)
		share_fs = true;
	if (parent->new_clone_flags & CLONE_FILES)
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

	if (sydbox->config.whitelist_per_process_directories &&
	    (!parent || current->pid != parent->pid)) {
		procadd(&sydbox->config.hh_proc_pid_auto, current->pid);
	}
}

static syd_process_t *clone_process(syd_process_t *p, pid_t cpid)
{
	syd_process_t *child;
	bool new_child;

	child = lookup_process(cpid);
	new_child = (child == NULL);

	if (new_child)
		child = new_thread_or_kill(cpid, post_attach_sigstop);
	if (p->new_clone_flags & CLONE_THREAD) {
		child->ppid = p->ppid;
		child->tgid = p->tgid;
	} else {
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

	if (p->abspath) {
		free(p->abspath);
		p->abspath = NULL;
	}
	if (p->regset) {
		pink_regset_free(p->regset);
		p->regset = NULL;
	}

	process_remove(p);

	/* Release shared memory */
	P_CLONE_THREAD_RELEASE(p);
	P_CLONE_FS_RELEASE(p);
	P_CLONE_FILES_RELEASE(p);

	if (sydbox->config.whitelist_per_process_directories)
		procdrop(&sydbox->config.hh_proc_pid_auto, pid);

	free(p); /* good bye, good bye, good bye. */
}

/* Drop leader, switch to the thread, reusing leader's tid */
static void tweak_execve_thread(syd_process_t *execve_thread, pid_t leader_pid, short flags)
{
	if (sydbox->config.whitelist_per_process_directories)
		procdrop(&sydbox->config.hh_proc_pid_auto, execve_thread->pid);
	process_remove(execve_thread);

	execve_thread->pid = leader_pid;
	execve_thread->flags = switch_execve_flags(flags);

	process_add(execve_thread);
}

static void switch_execve_leader(syd_process_t *leader, syd_process_t *execve_thread)
{
	process_remove(leader);

	P_CLONE_THREAD_RELEASE(leader);
	P_CLONE_FS_RELEASE(leader);
	P_CLONE_FILES_RELEASE(leader);

	if (leader->regset)
		pink_regset_free(leader->regset);
	if (execve_thread->abspath)
		free(execve_thread->abspath);

	tweak_execve_thread(execve_thread, leader->pid, leader->flags);
	execve_thread->ppid = leader->ppid;
	execve_thread->tgid = leader->tgid;
	execve_thread->clone_flags = leader->clone_flags;
	execve_thread->abspath = leader->abspath;

	free(leader);
}

void remove_process_node(syd_process_t *p)
{
	if (p->flags & SYD_IN_CLONE || p->flags & SYD_IN_EXECVE) {
		/* Let's wait for the children before the funeral. */
		if (sydbox->config.whitelist_per_process_directories)
			procdrop(&sydbox->config.hh_proc_pid_auto, p->pid);
		p->flags |= SYD_KILLED;
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
	syd_process_t *parent_node, *node, *tmp;

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

	/* Step 3: Check for IN_CLONE|IN_EXECVE flags and /proc/$pid/task
	 * We need IN_EXECVE for threaded exec -> leader lost case.
	 */
	parent_count = 0;
	process_iter(node, tmp) {
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

static void dump_clone_flags(int flags)
{
	int r = 0;

	if (flags & SIGCHLD) {
		fprintf(stderr, "SIGCHLD");
		r = 1;
	}
#ifdef CLONE_CHILD_CLEARTID
	if (flags & CLONE_CHILD_CLEARTID) {
		fprintf(stderr, "%sCLONE_CHILD_CLEARTID", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_CHILD_CLEARTID */
#ifdef CLONE_CHILD_SETTID
	if (flags & CLONE_CHILD_SETTID) {
		fprintf(stderr, "%sCLONE_CHILD_SETTID", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_CHILD_SETTID */
#ifdef CLONE_FILES
	if (flags & CLONE_FILES) {
		fprintf(stderr, "%sCLONE_FILES", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_FILES */
#ifdef CLONE_FS
	if (flags & CLONE_FS) {
		fprintf(stderr, "%sCLONE_FS", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_FS */
#ifdef CLONE_IO
	if (flags & CLONE_IO) {
		fprintf(stderr, "%sCLONE_IO", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_IO */
#ifdef CLONE_NEWIPC
	if (flags & CLONE_NEWIPC) {
		fprintf(stderr, "%sCLONE_NEWIPC", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_NEWIPC */
#ifdef CLONE_NEWNET
	if (flags & CLONE_NEWNET) {
		fprintf(stderr, "%sCLONE_NEWNET", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_NEWNET */
#ifdef CLONE_NEWNS
	if (flags & CLONE_NEWNS) {
		fprintf(stderr, "%sCLONE_NEWNS", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_NEWNS */
#ifdef CLONE_NEWPID
	if (flags & CLONE_NEWPID) {
		fprintf(stderr, "%sCLONE_NEWPID", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_NEWPID */
#ifdef CLONE_NEWUTS
	if (flags & CLONE_NEWUTS) {
		fprintf(stderr, "%sCLONE_NEWUTS", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_NEWUTS */
#ifdef CLONE_PARENT
	if (flags & CLONE_PARENT) {
		fprintf(stderr, "%sCLONE_PARENT", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_PARENT */
#ifdef CLONE_PARENT_SETTID
	if (flags & CLONE_PARENT_SETTID) {
		fprintf(stderr, "%sCLONE_PARENT_SETTID", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_PARENT_SETTID */
#ifdef CLONE_PID
	if (flags & CLONE_PID) {
		fprintf(stderr, "%sCLONE_PID", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_PID */
#ifdef CLONE_PTRACE
	if (flags & CLONE_PTRACE) {
		fprintf(stderr, "%sCLONE_PTRACE", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_PTRACE */
#ifdef CLONE_SETTLS
	if (flags & CLONE_SETTLS) {
		fprintf(stderr, "%sCLONE_SETTLS", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_SETTLS */
#ifdef CLONE_SIGHAND
	if (flags & CLONE_SIGHAND) {
		fprintf(stderr, "%sCLONE_SIGHAND", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_SIGHAND */
#ifdef CLONE_STOPPED
	if (flags & CLONE_STOPPED) {
		fprintf(stderr, "%sCLONE_STOPPED", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_STOPPED */
#ifdef CLONE_SYSVSEM
	if (flags & CLONE_SYSVSEM) {
		fprintf(stderr, "%sCLONE_SYSVSEM", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_SYSVSEM */
#ifdef CLONE_THREAD
	if (flags & CLONE_THREAD) {
		fprintf(stderr, "%sCLONE_THREAD", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_THREAD */
#ifdef CLONE_UNTRACED
	if (flags & CLONE_UNTRACED) {
		fprintf(stderr, "%sCLONE_UNTRACED", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_UNTRACED */
#ifdef CLONE_VFORK
	if (flags & CLONE_VFORK) {
		fprintf(stderr, "%sCLONE_VFORK", (r == 1) ? "|" : "");
		r = 1;
	}
#endif /* CLONE_VFORK */
#ifdef CLONE_VM
	if (flags & CLONE_VM)
		fprintf(stderr, "%sCLONE_VM", (r == 1) ? "|" : "");
#endif /* CLONE_VM */
}

static void dump_one_process(syd_process_t *current, bool verbose)
{
	int r;
	char comm[32];
	const char *CG, *CB, *CN, *CI, *CE; /* good, bad, important, normal end */
	struct proc_statinfo info;

	pid_t pid = current->pid;
	short abi = current->abi;
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
	fprintf(stderr, "\t%sSyscall: {no:%lu abi:%d name:%s}%s\n", CN,
			current->sysnum, abi, current->sysname, CE);
	fprintf(stderr, "\t%sFlags: ", CN);
	r = 0;
	if (current->flags & SYD_STARTUP) {
		fputs("STARTUP", stderr);
		r = 1;
	}
	if (current->flags & SYD_IGNORE_ONE_SIGSTOP) {
		fprintf(stderr, "%sIGNORE_ONE_SIGSTOP", (r == 1) ? "|" : "");
		r = 1;
	}
	if (current->flags & SYD_IN_SYSCALL) {
		fprintf(stderr, "%sIN_SYSCALL", (r == 1) ? "|" : "");
		r = 1;
	}
	if (current->flags & SYD_IN_CLONE) {
		fprintf(stderr, "%sIN_CLONE", (r == 1) ? "|" : "");
		r = 1;
	}
	if (current->flags & SYD_STOP_AT_SYSEXIT)
		fprintf(stderr, "%sSTOP_AT_SYSEXIT", (r == 1) ? "|" : "");
	fprintf(stderr, "%s\n", CN);
	if (current->clone_flags) {
		fprintf(stderr, "\t%sClone flags: ", CN);
		dump_clone_flags(current->clone_flags);
		fprintf(stderr, "%s\n", CE);
	}

	if (current->clone_flags & (CLONE_THREAD|CLONE_FS|CLONE_FILES)) {
		fprintf(stderr, "\t%sClone flag refs: ", CN);
		r = 0;
		if (current->clone_flags & CLONE_THREAD) {
			fprintf(stderr, "CLONE_THREAD{ref=%u}",
				current->shm.clone_thread ? current->shm.clone_thread->refcnt : 0);

			r = 1;
		}
		if (current->clone_flags & CLONE_FS) {
			fprintf(stderr, "%sCLONE_FS{ref=%u}", (r == 1) ? "|" : "",
				current->shm.clone_fs ? current->shm.clone_fs->refcnt : 0);
			r = 1;
		}
		if (current->clone_flags & CLONE_FILES) {
			fprintf(stderr, "%sCLONE_FILES{ref=%u}", (r == 1) ? "|" : "",
				current->shm.clone_files ? current->shm.clone_files->refcnt : 0);
			r = 1;
		}
		if (current->clone_flags & CLONE_VFORK)
			fprintf(stderr, "%sCLONE_VFORK", (r == 1) ? "|" : "");
		fprintf(stderr, "%s\n", CN);
	}
	if (current->new_clone_flags) {
		fprintf(stderr, "\t%sNew clone flags: ", CN);
		dump_clone_flags(current->new_clone_flags);
		fprintf(stderr, "%s\n", CE);
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

	if (!verbose || !current->shm.clone_thread || !current->shm.clone_thread->box)
		return;

	fprintf(stderr, "\t%sSandbox: {exec:%s read:%s write:%s sock:%s}%s\n",
		CN,
		sandbox_mode_to_string(P_BOX(current)->sandbox_exec),
		sandbox_mode_to_string(P_BOX(current)->sandbox_read),
		sandbox_mode_to_string(P_BOX(current)->sandbox_write),
		sandbox_mode_to_string(P_BOX(current)->sandbox_network),
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
	syd_process_t *node, *tmp;

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
	process_iter(node, tmp) {
		dump_one_process(node, complete_dump);
		count++;
	}
	fprintf(stderr, "Tracing %u process%s\n", count, count > 1 ? "es" : "");
}

static void init_early(void)
{
	assert(!sydbox);

	os_release = get_os_release();
	sydbox = xmalloc(sizeof(sydbox_t));
	sydbox->proctab = NULL;
	sydbox->violation = false;
	sydbox->execve_wait = false;
	sydbox->exit_code = EXIT_SUCCESS;
	sydbox->program_invocation_name = NULL;
	config_init();
	dump(DUMP_INIT);
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

	sa.sa_handler = interrupt;
	x_sigaction(SIGHUP, &sa, NULL);
	x_sigaction(SIGINT, &sa, NULL);
	x_sigaction(SIGQUIT, &sa, NULL);
	x_sigaction(SIGPIPE, &sa, NULL);
	x_sigaction(SIGTERM, &sa, NULL);
	x_sigaction(SIGABRT, &sa, NULL);
	x_sigaction(SIGUSR1, &sa, NULL);
	x_sigaction(SIGUSR2, &sa, NULL);

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

static int event_startup(syd_process_t *current)
{
	int r;

	if (!(current->flags & SYD_STARTUP))
		return 0;

	if ((r = syd_trace_setup(current)) < 0)
		return r;

	current->flags &= ~SYD_STARTUP;

	return 0;
}

static int event_clone(syd_process_t *current, enum pink_event event)
{
	assert(current);

	if (!current->new_clone_flags) {
		/* No syscall-enter received before clone event. */
		switch (event) {
		case PINK_EVENT_FORK:
			current->new_clone_flags = SIGCHLD;
			break;
		case PINK_EVENT_VFORK:
			current->new_clone_flags = CLONE_VM|CLONE_VFORK|SIGCHLD;
			break;
		case PINK_EVENT_CLONE:
			current->new_clone_flags = CLONE_THREAD;
			break;
		default:
			assert_not_reached();
		}
		current->flags |= SYD_IN_CLONE;
	}

	int r;
	long cpid = -1;

	r = syd_trace_geteventmsg(current, (unsigned long *)&cpid);
	if (r < 0 || cpid <= 0)
		return (r < 0) ? r : -EINVAL;

	clone_process(current, cpid);

	return 0;
}

static int event_exec(syd_process_t *current)
{
	int r;
	const char *match;

	if (sydbox->execve_wait) {
#if SYDBOX_HAVE_SECCOMP
		if (sydbox->config.use_seccomp)
			sydbox->execve_wait = false;
#endif
		return 0;
	}

	assert(current);

	if (P_BOX(current)->magic_lock == LOCK_PENDING) {
		/* magic commands are locked */
		P_BOX(current)->magic_lock = LOCK_SET;
	}

	/* Drop all threads except this one */
	syd_process_t *node, *tmp;
	process_iter(node, tmp) {
		if (current->pid != node->pid &&
		    current->tgid == node->tgid &&
		    current->shm.clone_thread == node->shm.clone_thread) {
			remove_process_node(node); /* process_iter is delete-safe. */
		}
	}

	if (!current->abspath) /* nothing left to do */
		return 0;

	/* kill_if_match and resume_if_match */
	r = 0;
	if (acl_match_path(ACL_ACTION_NONE, &sydbox->config.exec_kill_if_match,
			   current->abspath, &match)) {
		say("kill_if_match pattern=`%s' matches execve path=`%s'",
		    match, current->abspath);
		say("killing process");
		syd_trace_kill(current, SIGKILL);
		return -ESRCH;
	} else if (acl_match_path(ACL_ACTION_NONE, &sydbox->config.exec_resume_if_match,
				  current->abspath, &match)) {
		say("resume_if_match pattern=`%s' matches execve path=`%s'",
		    match, current->abspath);
		say("detaching from process");
		syd_trace_detach(current, 0);
		return -ESRCH;
	}
	/* execve path does not match if_match patterns */

	free(current->abspath);
	current->abspath = NULL;

	return r;
}

static int event_syscall(syd_process_t *current)
{
	int r = 0;

	if (sydbox->execve_wait) {
#if SYDBOX_HAVE_SECCOMP
		if (sydbox->config.use_seccomp)
			return 0;
#endif
		if (entering(current)) {
			current->flags |= SYD_IN_SYSCALL;
		} else {
			current->flags &= ~SYD_IN_SYSCALL;
			sydbox->execve_wait = false;
		}
		return 0;
	}

	if (entering(current)) {
#if SYDBOX_HAVE_SECCOMP
		if (sydbox->config.use_seccomp &&
		    (current->flags & SYD_STOP_AT_SYSEXIT)) {
			/* seccomp: skipping sysenter */
			current->flags |= SYD_IN_SYSCALL;
			return 0;
		}
#endif
		if ((r = syd_regset_fill(current)) < 0)
			return r; /* process dead */
		r = sysenter(current);
#if SYDBOX_HAVE_SECCOMP
		if (sydbox->config.use_seccomp &&
		    !(current->flags & SYD_STOP_AT_SYSEXIT)) {
			/* seccomp: skipping sysexit, resuming */
			current->trace_step = SYD_STEP_RESUME;
			return r;
		}
#endif
		current->flags |= SYD_IN_SYSCALL;
	} else {
		if ((r = syd_regset_fill(current)) < 0)
			return r; /* process dead */
		r = sysexit(current);
		current->flags &= ~SYD_IN_SYSCALL;
	}
	return r;
}

#if SYDBOX_HAVE_SECCOMP
static int event_seccomp(syd_process_t *current)
{
	int r;

	if (sydbox->execve_wait)
		return 0; /* execve() seccomp trap */

	if ((r = syd_regset_fill(current)) < 0)
		return r; /* process dead */
	r = sysenter(current);
	if (current->flags & SYD_STOP_AT_SYSEXIT) {
		/* step using PTRACE_SYSCALL until we hit sysexit.
		 * Appearently the order we receive the ptrace events
		 * changed in Linux-4.8.0 so we need a conditional here.
		 */
		if (os_release >= KERNEL_VERSION(4,8,0))
			current->flags |= SYD_IN_SYSCALL;
		else
			current->flags &= ~SYD_IN_SYSCALL;
		current->trace_step = SYD_STEP_SYSCALL;
	}
	return r;
}
#endif

static int trace(void)
{
	int pid, wait_errno;
	bool stopped;
	int r;
	int status, sig;
	unsigned event;
	syd_process_t *current;
	int syscall_trap_sig;

	syscall_trap_sig = sydbox->trace_options & PINK_TRACE_OPTION_SYSGOOD
			   ? SIGTRAP | 0x80
			   : SIGTRAP;
	/*
	 * Used to be while(process_count() > 0), but in this testcase:
	 * int main() { _exit(!!fork()); }
	 * under sydbox, parent sometimes (rarely) manages
	 * to exit before we see the first stop of the child,
	 * and we are losing track of it.
	 *
	 * Waiting for ECHILD works better.
	 */
	while (1) {
		if ((r = check_interrupt()) != 0)
			return r;

		sigprocmask(SIG_SETMASK, &empty_set, NULL);
		errno = 0;
		pid = waitpid(-1, &status, __WALL);
		wait_errno = errno;
		sigprocmask(SIG_SETMASK, &blocked_set, NULL);

		dump(DUMP_WAIT, pid, status, wait_errno);

		if (pid < 0) {
			switch (wait_errno) {
			case EINTR:
				continue;
			default:
				goto cleanup;
			}
		}


		if (WIFSIGNALED(status) || WIFEXITED(status)) {
			remove_process(pid, status);
			continue;
		} else if (!WIFSTOPPED(status)) {
			/* Process entry not available here yet,
			 * better paranoid than sorry.
			 */
			say("PANIC: not stopped (status:0x%04x)", status);
			say("Killing process %u", pid);

			errno = 0;
			pink_trace_kill(pid, 0, SIGTERM);
			if (errno != ESRCH) {
				usleep(10000);
				pink_trace_kill(pid, 0, SIGKILL);
			}
			continue;
		}

		event = pink_event_decide(status);
		current = lookup_process(pid);

		/* Under Linux, execve changes pid to thread leader's pid,
		 * and we see this changed pid on EVENT_EXEC and later,
		 * execve sysexit. Leader "disappears" without exit
		 * notification. Let user know that, drop leader's tcb,
		 * and fix up pid in execve thread's tcb.
		 * Effectively, execve thread's tcb replaces leader's tcb.
		 *
		 * BTW, leader is 'stuck undead' (doesn't report WIFEXITED
		 * on exit syscall) in multithreaded programs exactly
		 * in order to handle this case.
		 *
		 * PTRACE_GETEVENTMSG returns old pid starting from Linux 3.0.
		 * On 2.6 and earlier, it can return garbage.
		 */
		if (event == PINK_EVENT_EXEC) {
			syd_process_t *execve_thread;
			long old_tid = -1;

			if (os_release >= KERNEL_VERSION(3,0,0)) {
				r = pink_trace_geteventmsg(pid, (unsigned long *) &old_tid);
				if (r < 0 || old_tid <= 0)
					die("old_pid not available after execve for pid:%u", pid);
			}

			if (old_tid > 0 && pid != old_tid) {
				execve_thread = lookup_process(old_tid);
				assert(execve_thread);

				if (current)
					switch_execve_leader(current, execve_thread);
				else
					tweak_execve_thread(execve_thread, pid,
							    execve_thread->flags);
				current = execve_thread;
			}

			r = event_exec(current);
			if (r == -ECHILD) /* process ignored */
				goto restart_tracee_with_sig_0;
			else if (r < 0) /* process dead */
				continue;
		}

		/* If we are here we *must* have a process entry for the usual
		 * cases however there is still a chance we may have the
		 * new-born child of a clone()! */
		if (!current) {
			syd_process_t *parent;

			parent = parent_process(pid, current);

			YELL_ON(parent, "pid %u, status %#x, event %d|%s (-pent)",
				pid, status, event, pink_name_event(event));
			current = clone_process(parent, pid);
			BUG_ON(current); /* Just bizarre, no questions */
		}

		if ((current->flags & SYD_STARTUP) && event_startup(current) < 0)
				continue; /* process dead */

		sig = WSTOPSIG(status);

		switch (event) {
		case 0:
			break;
#if PINK_HAVE_SEIZE
		case PINK_EVENT_STOP:
			/*
			 * PTRACE_INTERRUPT-stop or group-stop.
			 * PTRACE_INTERRUPT-stop has sig == SIGTRAP here.
			 */
			switch (sig) {
			case SIGSTOP:
			case SIGTSTP:
			case SIGTTIN:
			case SIGTTOU:
				stopped = true;
				goto handle_stopsig;
			case SIGTRAP:
				/* fall through */
			default:
				break;
			}
			goto restart_tracee_with_sig_0;
#endif
#if SYDBOX_HAVE_SECCOMP
		case PINK_EVENT_SECCOMP:
#endif
		case PINK_EVENT_FORK:
		case PINK_EVENT_VFORK:
		case PINK_EVENT_CLONE:
#if SYDBOX_HAVE_SECCOMP
			r = (event == PINK_EVENT_SECCOMP) ? event_seccomp(current)
							  : event_clone(current, event);
#else
			r = event_clone(current, event);
#endif
			if (r < 0)
				continue; /* process dead */
			/* fall through */
		default:
			goto restart_tracee_with_sig_0;
		}

		assert(!(current->flags & SYD_STARTUP));

		/* Is this post-attach SIGSTOP?
		 * Interestingly, the process may stop
		 * with STOPSIG equal to some other signal
		 * than SIGSTOP if we happend to attach
		 * just before the process takes a signal.
		 */
		if (sig == SIGSTOP && current->flags & SYD_IGNORE_ONE_SIGSTOP) {
			/* ignore SIGSTOP */
			current->flags &= ~SYD_IGNORE_ONE_SIGSTOP;
			goto restart_tracee_with_sig_0;
		}

		if (sig != syscall_trap_sig) {
			siginfo_t si;

			/* Nonzero (true) if tracee is stopped by signal
			 * (as opposed to "tracee received signal").
			 * TODO: shouldn't we check for errno == EINVAL too?
			 * We can get ESRCH instead, you know...
			 */
			stopped = (pink_trace_get_siginfo(pid, &si) < 0);
#if PINK_HAVE_SEIZE
handle_stopsig:
#endif
			if (!stopped)
				/* It's signal-delivery-stop. Inject the signal */
				goto restart_tracee;

			/* It's group-stop */
#if PINK_HAVE_SEIZE
			if (syd_use_seize) {
				/*
				 * This ends ptrace-stop, but does *not* end group-stop.
				 * This makes stopping signals work properly on straced process
				 * (that is, process really stops. It used to continue to run).
				 */
				syd_trace_listen(current);
				continue;
			}
			/* We don't have PTRACE_LISTEN support... */
#endif
			goto restart_tracee;
		}

		/* We handled quick cases, we are permitted to interrupt now. */
		if ((r = check_interrupt()) != 0)
			return r;

		/* This should be syscall entry or exit.
		 * (Or it still can be that pesky post-execve SIGTRAP!)
		 * Handle it.
		 */
		r = event_syscall(current);
		if (r != 0) {
			/* ptrace() failed in event_syscall().
			 * Likely a result of process disappearing mid-flight.
			 * Observed case: exit_group() or SIGKILL terminating
			 * all processes in thread group.
			 * We assume that ptrace error was caused by process death.
			 * The process is ignored and will report its death to us
			 * normally, via WIFEXITED or WIFSIGNALED exit status.
			 */
			continue;
		}
restart_tracee_with_sig_0:
		sig = 0;
restart_tracee:
		if (sig && current->pid == sydbox->execve_pid)
			save_exit_signal(term_sig(sig));
		syd_trace_step(current, sig);
	}
cleanup:
	r = sydbox->exit_code;
	if (sydbox->violation) {
		if (sydbox->config.violation_exit_code > 0)
			r = sydbox->config.violation_exit_code;
		else if (sydbox->config.violation_exit_code == 0)
			r = 128 + sydbox->exit_code;
	}

	return r;
}

static void startup_child(char **argv)
{
	int r;
	char *pathname;
	pid_t pid = 0;
	syd_process_t *child;

	r = path_lookup(argv[0], &pathname);
	if (r < 0) {
		errno = -r;
		die_errno("can't exec `%s'", argv[0]);
	}

	pid = fork();
	if (pid < 0)
		die_errno("can't fork");
	else if (pid == 0) {
#if SYDBOX_HAVE_SECCOMP
		if (sydbox->config.use_seccomp) {
			if ((r = seccomp_init()) < 0) {
				fprintf(stderr,
					"seccomp_init failed (errno:%d %s)\n",
					-r, strerror(-r));
				_exit(EXIT_FAILURE);
			}

			if ((r = sysinit_seccomp()) < 0) {
				fprintf(stderr,
					"seccomp_apply failed (errno:%d %s)\n",
					-r, strerror(-r));
				_exit(EXIT_FAILURE);
			}
		}
#endif
		pid = getpid();
		if (!syd_use_seize) {
			if ((r = pink_trace_me() < 0)) {
				fprintf(stderr,
					"ptrace(PTRACE_TRACEME) failed (errno:%d %s)\n",
					-r, strerror(-r));
				_exit(EXIT_FAILURE);
			}
		}

		if (child_sa.sa_handler != SIG_DFL &&
				sigaction(SIGCHLD, &child_sa, NULL) < 0) {
			fprintf(stderr, "sigaction failed (errno:%d %s)\n",
					errno, strerror(errno));
			_exit(EXIT_FAILURE);
		}

		kill(pid, SIGSTOP);

		execv(pathname, argv);
		fprintf(stderr, "execv failed (errno:%d %s)\n", errno, strerror(errno));
		_exit(EXIT_FAILURE);
	}

	free(pathname);
#if PINK_HAVE_SEIZE
	if (syd_use_seize) {
		/* Wait until child stopped itself */
		int status;
		while (waitpid(pid, &status, WSTOPPED) < 0) {
			if (errno == EINTR)
				continue;
			die_errno("waitpid");
		}
		if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
			kill_save_errno(pid, SIGKILL);
			die_errno("Unexpected wait status %x", status);
		}
		if (pink_trace_seize(pid, sydbox->trace_options) < 0 ||
		    pink_trace_interrupt(pid) < 0) {
			kill_save_errno(pid, SIGKILL);
			die_errno("Can't attach to %u", pid);
		}
		kill(pid, SIGCONT);
	}
#endif
	child = new_process_or_kill(pid, post_attach_sigstop);
	sydbox->execve_pid = pid;
	sydbox->execve_wait = true;
	init_process_data(child, NULL);
	dump(DUMP_STARTUP, pid);
}

void cleanup(void)
{
	struct acl_node *node;

	assert(sydbox);

	reset_sandbox(&sydbox->config.box_static);

	ACLQ_FREE(node, &sydbox->config.exec_kill_if_match, free);
	ACLQ_FREE(node, &sydbox->config.exec_resume_if_match, free);

	ACLQ_FREE(node, &sydbox->config.filter_exec, free);
	ACLQ_FREE(node, &sydbox->config.filter_read, free);
	ACLQ_FREE(node, &sydbox->config.filter_write, free);
	ACLQ_FREE(node, &sydbox->config.filter_network, free_sockmatch);

	if (sydbox->program_invocation_name)
		free(sydbox->program_invocation_name);
	free(sydbox);
	sydbox = NULL;

	systable_free();
}

int main(int argc, char **argv)
{
	int opt, r;
	const char *env;

	int ptrace_options;
	enum syd_step ptrace_default_step;

	/* Long options are present for compatibility with sydbox-0.
	 * Thus they are not documented!
	 */
	int options_index;
	char *profile_name;
	struct option long_options[] = {
		{"help",	no_argument,		NULL,	'h'},
		{"version",	no_argument,		NULL,	'v'},
		{"profile",	required_argument,	NULL,	0},
		{NULL,		0,		NULL,	0},
	};

	/* early initialisations */
	init_early();

	const struct sigaction sa = { .sa_handler = SIG_DFL };
	if (sigaction(SIGCHLD, &sa, &child_sa) < 0)
		die_errno("sigaction");

	while ((opt = getopt_long(argc, argv, "hvc:m:E:", long_options, &options_index)) != EOF) {
		switch (opt) {
		case 0:
			if (streq(long_options[options_index].name, "profile")) {
				/* special case for backwards compatibility */
				profile_name = xmalloc(sizeof(char) * (strlen(optarg) + 2));
				profile_name[0] = SYDBOX_PROFILE_CHAR;
				strcpy(&profile_name[1], optarg);
				config_parse_spec(profile_name);
				free(profile_name);
				break;
			}
			usage(stderr, 1);
		case 'h':
			usage(stdout, 0);
		case 'v':
			about();
			return 0;
		case 'c':
			config_parse_spec(optarg);
			break;
		case 'm':
			r = magic_cast_string(NULL, optarg, 0);
			if (MAGIC_ERROR(r))
				die("invalid magic: `%s': %s",
				    optarg, magic_strerror(r));
			break;
		case 'E':
			if (putenv(optarg))
				die_errno("putenv");
			break;
		default:
			usage(stderr, 1);
		}
	}

	if (optind == argc)
		usage(stderr, 1);

	if ((env = getenv(SYDBOX_CONFIG_ENV)))
		config_parse_spec(env);

	config_done();
	systable_init();
	sysinit();

	ptrace_options = PINK_TRACE_OPTION_SYSGOOD | PINK_TRACE_OPTION_EXEC;
	ptrace_default_step = SYD_STEP_SYSCALL;
	if (sydbox->config.follow_fork)
		ptrace_options |= (PINK_TRACE_OPTION_FORK |
				   PINK_TRACE_OPTION_VFORK |
				   PINK_TRACE_OPTION_CLONE);
#if PINK_HAVE_OPTION_EXITKILL
	if (sydbox->config.exit_kill)
		ptrace_options |= PINK_TRACE_OPTION_EXITKILL;
#endif
	if (sydbox->config.use_seccomp) {
#if SYDBOX_HAVE_SECCOMP
		if (os_release >= KERNEL_VERSION(3,5,0)) {
			ptrace_options |= PINK_TRACE_OPTION_SECCOMP;
			ptrace_default_step = SYD_STEP_RESUME;
		} else {
			/* say("Linux-3.5.0 required for seccomp support, disabling"); */
			sydbox->config.use_seccomp = false;
		}
#else
		/* say("seccomp not supported, disabling"); */
		sydbox->config.use_seccomp = false;
#endif
	}
	if (sydbox->config.use_seize) {
#if PINK_HAVE_SEIZE
		post_attach_sigstop = 0; /* this sets syd_use_seize to 1 */
#else
		/* say("seize not supported, disabling"); */
		sydbox->config.use_seize = false;
#endif
	}

	sydbox->trace_options = ptrace_options;
	sydbox->trace_step = ptrace_default_step;

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

	/* STARTUP_CHILD must be called before the signal handlers get
	   installed below as they are inherited into the spawned process.
	   Also we do not need to be protected by them as during interruption
	   in the STARTUP_CHILD mode we kill the spawned process anyway.  */
	startup_child(&argv[optind]);
	init_signals();
	r = trace();
	cleanup();
	return r;
}
