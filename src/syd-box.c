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

#include "HELPME.h"
#include "syd-box.h"
#include <syd/compiler.h>
#include "daemon.h"
#include "dump.h"

#include <time.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <getopt.h>
#include <time.h>
#include <pthread.h>
#include <termios.h>
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

#define switch_execve_flags(f) ((f) & ~(SYD_IN_CLONE|SYD_IN_EXECVE))

sydbox_t *sydbox;
static unsigned os_release;
static struct sigaction child_sa;

static char *sydsh_argv[] = {
	"/usr/bin/env",
	"bash",
	"--rcfile",
	DATADIR"/"PACKAGE"/sydbox.bashrc",
	"-i",
	NULL
};

static void
set_sighandler(int signo,
	       void (*sighandler)(int, siginfo_t *, void *),
	       struct sigaction *oldact)
{
	const struct sigaction sa = { .sa_sigaction = sighandler,
				      .sa_flags = SA_SIGINFO };
	sigaction(signo, &sa, oldact);
}

/* Libseccomp Architecture Handling
 *
 * SYD_SECCOMP_ARCH_ARGV_SIZ should include all the architectures,
 * see the manual page seccomp_arch_add(3) for a list and another
 * additional space for the terminating NULL pointer (used to loop
 * over the array to free the strings).
 */
static uint32_t arch_native;
static char *arch_argv[SYD_SECCOMP_ARCH_ARGV_SIZ] = { NULL };
static size_t arch_argv_idx;
#ifdef HAVE_SIG_ATOMIC_T
static volatile sig_atomic_t interrupted, interruptid, interruptcode, interruptstat;
#else
static volatile int interrupted, interruptid, interruptcode, interruptstat;
#endif
static sigset_t empty_set, blocked_set;

static bool child_block_interrupt_signals;
struct termios old_tio, new_tio;

static bool escape_stdout, reset_fds, allow_daemonize;
static bool make_group_leader, keep_sigmask;
static int parent_death_signal;
static uint32_t close_fds[2];

/* unshare option defaults */
int setgrpcmd = SYD_SETGROUPS_NONE;
int unshare_flags = 0;
uid_t mapuser = -1;
gid_t mapgroup = -1;
long mapuser_opt = -1;
long mapgroup_opt = -1;
// int kill_child_signo = 0; /* 0 means --kill-child was not used */
const char *procmnt = NULL;
const char *newroot = NULL;
const char *newdir = NULL;
unsigned long propagation = SYD_UNSHARE_PROPAGATION_DEFAULT;
int force_uid = 0, force_gid = 0;
uid_t uid = 0;
gid_t gid = 0;
/* int keepcaps = 0; */
time_t monotonic = 0;
time_t boottime = 0;
int force_monotonic = 0;
int force_boottime = 0;

static void dump_one_process(syd_process_t *current, bool verbose);
static void sig_usr(int sig);

static void interrupt(int sig, siginfo_t *siginfo, void *context);
static void reap_zombies(void);
#if 0
static inline bool process_is_alive(pid_t pid);
#endif
static inline bool process_is_zombie(pid_t pid);
static inline size_t process_count_alive(void);
static inline pid_t process_find_exec(pid_t pid);
static inline syd_process_t *process_init(pid_t pid, syd_process_t *parent,
					  bool genuine);

SYD_GCC_ATTR((noreturn))
static void usage(FILE *outfp, int code)
{
	fputs("\
syd-"VERSION GITVERSION" -- Syd's secc☮mp bⒶsed ⒶpplicⒶtion sⒶndb☮x\n\
usage: syd [-hvb] [--dry-run] [-d <fd|path|tmp>]\n\
           [--export <bpf|pfc:filename>] [--memaccess 0..1]\n\
           [--arch arch...] [--file pathspec...] [--syd magic-command...]\n\
           [--lock] [--root directory] [--pivot-root new-root:put-old]\n\
           [--wd directory] [--env var...] [--env var=val...]\n\
           [--ionice class:data] [--nice level]\n\
           [--allow-daemonize] [--background]\n\
           [--set-parent-death-signal signal]\n\
           [--stdout logfile] [--stderr logfile]\n\
           [--alias name] [--umask mode]\n\
           [--uid user-id] [--gid group-id] [--add-gid group-id]\n\
           [--unshare-pid] [--unshare-net] [--unshare-mount]\n\
           [--unshare-uts] [--unshare-ipc] [--unshare-user]\n\
           [--unshare-cgroups] [--unshare-time]\n\
           [--close-fds <begin:end>] [--reset-fds] [--escape-stdout]\n\
           [--env-var-with-pid <varname>]\n\
           {command [arg...]}\n", outfp);
       fputs("\
       syd [--export <bpf|pfc:filename>]\n\
           [--arch arch...] [--file pathspec...]\n\
           [--syd magic-command...] {noexec}\n\
       syd --test\n\
       syd dump {syd-args...}\n\
       syd errno [-hv] -|errno-name|errno-number...\n\
       syd format exec [--] {command [arg...]}\n\
       syd hilite [-hv] command args...\n\
       syd test [-hvx]\n\
           [--debug] [--immediate]\n\
           [--long] [--run test]\n\
           [--verbose-only] [--quiet]\n\
           [--verbose-log]\n\
           [--no-color]\n\
           [--dump] [--pfc]\n\
           [--strace] [--valgrind]\n\
           [--root directory]\n\
           [--chain-lint] [--no-chain-lint]\n\
           [--stress] [--stress-jobs jobs]\n\
           [--stress-limit limit]\n\
\n"SYD_HELPME, outfp);
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

static int seccomp_setup(void)
{
	int r;

	/* initialize Secure Computing */
	bool using_arch_native = true; /* Loaded by libseccomp by default. */
	if (sydbox->config.restrict_general > 0)
		sydbox->seccomp_action = SCMP_ACT_ERRNO(EPERM);
	else
		sydbox->seccomp_action = SCMP_ACT_ALLOW;
	if (!(sydbox->ctx = seccomp_init(sydbox->seccomp_action)))
		die_errno("seccomp_init");
	if ((r = seccomp_attr_set(sydbox->ctx, SCMP_FLTATR_CTL_NNP, 1)) < 0)
		say("can't set no-new-privs flag for seccomp filter (%d %s), "
		    "continuing...",
		    -r, strerror(-r));
#if 0
	if ((r = seccomp_attr_set(sydbox->ctx, SCMP_FLTATR_API_TSKIP, 1)) < 0)
		say("can't set tskip attribute for seccomp filter (%d %s), "
		    "continuing...",
		    -r, strerror(-r));
	if ((r = seccomp_attr_set(sydbox->ctx, SCMP_FLTATR_API_SYSRAWRC, 1)) < 0)
		say("can't set sysrawrc attribute for seccomp filter (%d %s), "
		    "continuing...",
		    -r, strerror(-r));
	/* Set system call priorities */
	sysinit(sydbox->ctx);
#endif
	if ((r = seccomp_attr_set(sydbox->ctx, SCMP_FLTATR_CTL_TSYNC, 1)) < 0)
		say("can't set tsync attribute for seccomp filter (%d %s), "
		    "continuing...",
		    -r, strerror(-r));
	if ((r = seccomp_attr_set(sydbox->ctx, SCMP_FLTATR_CTL_OPTIMIZE, 2)) < 0)
		say("can't optimize seccomp filter (%d %s), continuing...",
		    -r, strerror(-r));
#if SYDBOX_HAVE_DUMP_BUILTIN
	if (dump_get_fd() > 0) {
		if ((r = seccomp_attr_set(sydbox->ctx, SCMP_FLTATR_CTL_LOG, 1)) < 0)
			say("can't log attribute for seccomp filter (%d %s), "
			    "continuing...", -r, strerror(-r));
	}
#endif

	/* This is added by default by libseccomp,
	 * so no need to do it manually.
	seccomp_arch_add(sydbox->ctx, SCMP_ARCH_NATIVE);
	 */
	if (arch_argv_idx == 0) {
		/* User has specified no architectures.
		 * use/try all the valid architectures defined at compile-time.
		 */
		SYD_GCC_ATTR((unused))char *in_sydbox_test = getenv("IN_SYDBOX_TEST");
#include "syd_seccomp_arch_default.c"
	} else {
		/* Else, we plan to remove the native architecture of libseccomp.
		 * If the user passes --arch native, we are not going to
		 * remove it.
		 */
		using_arch_native = false;
	}

	size_t i;
	for (i = arch_argv_idx - 1; i; i--) {
		if (arch_argv[i] == NULL)
			continue;
		uint32_t arch = arch_from_string(arch_argv[i]);
		if (arch == UINT32_MAX)
			continue;
		if (arch == SCMP_ARCH_NATIVE ||
		    (uint32_t)arch == arch_native)
			using_arch_native = true;
		if ((r = seccomp_arch_add(sydbox->ctx, (uint32_t)arch)) != 0 &&
		    r != -EEXIST) {
			say("architecture %s: not ok (%d %s), continuing..",
			    arch_argv[i], -r, strerror(-r));
			say("system calls in arch %s may result in process kill, "
			    "hang, or misfunction!", arch_argv[i]);
		}
	}

	if (!using_arch_native &&
	    ((r = seccomp_arch_remove(sydbox->ctx, SCMP_ARCH_NATIVE)) != 0)) {
		errno = -r;
		say_errno("error removing native architecture");
	}

	for (i = 0; arch_argv[i] != NULL; i++)
		sydbox->arch[i] = arch_from_string(arch_argv[i]);
	sydbox->arch[i] = UINT32_MAX;

	return 0;
}

static void new_shared_memory_clone_fs(struct syd_process *p)
{
	p->cwd = NULL;
}

static void new_shared_memory_clone_files(struct syd_process *p)
{
	if (!syd_map_init_64v(&p->sockmap,
			     SYDBOX_SOCKMAP_CAP,
			     SYDBOX_MAP_LOAD_FAC)) {
		errno = -ENOMEM;
		die_errno("failed to initialize sockmap for process %d",
			  p->pid);
	}
}

static void new_shared_memory(struct syd_process *p)
{
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
	if (thread->pidfd < 0) {
		thread->pidfd = syd_pidfd_open(thread->pid, 0);
		if (thread->pidfd < 0)
			say_errno("pidfd_open(%d)", thread->pid);
	}
	thread->ppid = SYD_PPID_NONE;
	thread->tgid = SYD_TGID_NONE;
	thread->abspath = NULL;
	thread->execve_pid = SYD_PPID_NONE;

	thread->comm[0] = '?';
	thread->comm[1] = '\0';
	thread->hash[0] = '?';
	thread->hash[1] = '\0';

	process_add(thread);

	dump(DUMP_THREAD_NEW, pid);
	return thread;
}

static syd_process_t *new_process(pid_t pid)
{
	int r;
	syd_process_t *process;

	process = new_thread(pid);
	if (!process)
		return NULL;
	process->tgid = process->pid;
	new_shared_memory(process);
	if ((r = new_sandbox(&process->box)) < 0) {
		errno = -r;
		die_errno("new_sandbox");
	}

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
	p->subcall = 0;
	p->sysname = NULL;
	p->retval = 0;
#if ENABLE_PSYSCALL
	memset(&p->addr_arg, 0, sizeof(p->addr_arg));
#endif

	memset(p->args, 0, sizeof(p->args));
	for (unsigned short i = 0; i < 6; i++) {
		if (p->repr[i]) {
			free(p->repr[i]);
			p->repr[i] = NULL;
		}
	}
	if (p->abspath)
		free(p->abspath);
	p->abspath = NULL;
}

static void init_shareable_data(syd_process_t *current, syd_process_t *parent,
				bool genuine)
{
	/*
	 * Link together for memory sharing, as necessary
	 * Note: thread in this context is any process which shares memory.
	 * (May not always be a real thread: (e.g. vfork)
	 *
	 * Note: If the parent process has magic lock set, this means the
	 * sandbox information can no longer be edited. Treat such cases as
	 * »threads«. (Threads only share sandbox_t which is constant when
	 * magic_lock is set.)
	 * TODO: We need to simplify the sandbox data structure to take more
	 * advantage of such cases and decrease memory usage.
	 */

	if (parent && genuine) { /* Sharing data needs a genuine parent, check
			  parent_process. */
		current->clone_flags = parent->new_clone_flags;
	} else {
		current->clone_flags = SIGCHLD;
	}

	int r;
	int pfd_cwd = -1;
	char *cwd;

	if (!P_BOX(current))
		new_sandbox(&P_BOX(current));
	if (parent)
		current->execve_pid = parent->execve_pid;
	if (parent && P_BOX(parent)->magic_lock == LOCK_SET) {
		copy_sandbox(P_BOX(current), P_BOX(parent));
	} else {
		copy_sandbox(P_BOX(current), box_current(NULL));
	}

	new_shared_memory_clone_files(current);
	new_shared_memory_clone_fs(current);
	if (!genuine) { /* Child with a non-genuine parent has a
			 completely separate set of shared memory
			 pointers, as the last step we want to
			 read cwd from /proc */
		pfd_cwd = syd_proc_cwd_open(current->pid);
		goto proc_getcwd;
	}

	P_CWD(current) = NULL;
	if (current->pid == sydbox->execve_pid) {
		/* Oh, I know this person, we're in the same directory. */
		P_CWD(current) = xgetcwd();
		copy_sandbox(P_BOX(current), box_current(NULL));
		return;
	} else if (!parent) {
		copy_sandbox(P_BOX(current), box_current(NULL));
		int fd;
proc_getcwd:
		fd = pfd_cwd < 0 ? sydbox->pfd_cwd : pfd_cwd;
		if (fd < 0) {
			if ((fd = syd_proc_cwd_open(current->pid)) >= 0)
				sydbox->pfd_cwd = fd;
		}
		cwd = NULL;
		if (fd >= 0 && (r = syd_proc_cwd(fd,
						 sydbox->config.use_toolong_hack,
						 &cwd)) < 0) {
			errno = -r;
			say_errno("proc_cwd(%d)", fd);
			P_CWD(current) = strdup("/");
		} else {
			P_CWD(current) = cwd;
		}
		if (pfd_cwd >= 0)
			close(pfd_cwd);
		return;
	} else {
		P_CWD(current) = xstrdup(P_CWD(parent));
	}
}

static void init_process_data(syd_process_t *current, syd_process_t *parent,
			      bool genuine)
{
	init_shareable_data(current, parent, genuine);

	if (sydbox->config.allowlist_per_process_directories &&
	    (!parent || current->pid != parent->pid)) {
		procadd(&sydbox->config.proc_pid_auto, current->pid);
	}
}

static syd_process_t *clone_process(syd_process_t *p, pid_t cpid, bool genuine)
{
	int pfd = -1;
	bool new_child;
	syd_process_t *child;

	child = process_lookup(cpid);
	pfd = syd_proc_open(cpid);
	new_child = (child == NULL);

	if (new_child)
		child = new_thread_or_kill(cpid);

	/*
	 * Careful here, the process may still be a thread although new
	 * clone flags is missing CLONE_THREAD
	 */
	if (p && p->pid == sydbox->execve_pid) {
		child->ppid = sydbox->sydbox_pid;
		child->tgid = child->pid;
	} else if (genuine && p && (p->new_clone_flags & SYD_CLONE_THREAD)) {
		child->ppid = p->ppid;
		child->tgid = p->tgid;
	} else if (pfd >= 0 &&
		   syd_proc_parents(pfd, &child->tgid, &child->ppid) < 0) {
		say_errno("proc_parents");
		child->ppid = p->pid;
		child->tgid = child->pid;
	}

	if (pfd >= 0)
		close(pfd);
	if (new_child) {
		init_process_data(child, p, genuine);
		process_add(child);
	}

	if (p && genuine) {
		/* clone OK: p->pid <-> cpid */
		p->new_clone_flags = 0;
		p->flags &= ~SYD_IN_CLONE;
	}

	return child;
}

void bury_process(syd_process_t *p, bool id_is_valid)
{
	pid_t pid;

	if (!p)
		return;
	p->zombie = true;

	pid = p->pid;
	if (pid)
		dump(DUMP_THREAD_FREE, pid);

	if (pid > 0 && p->cwd)
		free(p->cwd);
	p->cwd = NULL;

	/*
	 * We delegate this to reset_process.
	if (p->abspath) {
		free(p->abspath);
		p->abspath = NULL;
	}
	*/
	if (syd_map_size_64v(&p->sockmap)) {
		syd_map_clear_64v(&p->sockmap);
		syd_map_term_64v(&p->sockmap);
	}

	for (unsigned short i = 0; i < 6; i++) {
		if (p->repr[i]) {
			free(p->repr[i]);
			p->repr[i] = NULL;
		}
	}

	if (sydbox->config.allowlist_per_process_directories &&
	    !syd_map_free(&sydbox->config.proc_pid_auto))
		procdrop(&sydbox->config.proc_pid_auto, pid);


	if ((p->pid > 0 && p->pid == sydbox->execve_pid) ||
	    (p->flags & (SYD_IN_EXECVE|SYD_IN_CLONE))) {
		/*
		 * 1. keep the default sandbox available.
		 * 2. prepare for leader switch for multithreaded execve.
		 * 3. prepare for sandboxing rules transfer from parent.
		 */
		return;
	}

	if (p->pidfd > 0) {
		/* Under no circumstances we want the process to linger around
		 * after SydB☮x exits. This is why we send a SIGLOST signal here
		 * to the process which is about to be released from the process
		 * tree. This will be repeated for 3 times every 0.01 seconds.
		 * If this does not succeed, process is sent a SIGKILL...
		 */
		//kill_one(p, SIGLOST);
		close(p->pidfd);
		p->pidfd = 0; /* assume p is deceased, rip. */
	}

	if (id_is_valid) {
		/* Genuine process: There is no other process in the process
		 * table with the same process ID as this process.
		 * This is the case during leader switch in multithreaded.
		 * execve.
		 */
		process_remove(p);
	} else if (!p->zombie || p->pid != 0) {
		free(p); /* good bye, good bye, good bye. */
	}
}

/* Drop leader, switch to the thread, reusing leader's tid */
static void tweak_execve_thread(syd_process_t *leader,
				syd_process_t *execve_thread)
{
	if (sydbox->config.allowlist_per_process_directories)
		procdrop(&sydbox->config.proc_pid_auto, execve_thread->pid);
	if (execve_thread->abspath) {
		free(execve_thread->abspath);
		execve_thread->abspath = NULL;
	}
	process_remove(execve_thread);

	execve_thread->pid = leader->pid;
	execve_thread->flags = switch_execve_flags(leader->flags);

	execve_thread->ppid = leader->ppid;
	execve_thread->tgid = leader->tgid;
	execve_thread->clone_flags = leader->clone_flags;
	execve_thread->abspath = leader->abspath;

	process_add(execve_thread);
}

static void switch_execve_leader(pid_t leader_pid, syd_process_t *execve_thread)
{
	bool update_cwd = false;
	bool clone_fs = false;

	dump(DUMP_EXEC_MT, execve_thread->pid, leader_pid,
	     execve_thread->abspath);

	syd_process_t *leader = process_lookup(leader_pid);
	if (!leader)
		goto out;
	process_remove(leader);

	if (!P_CWD(execve_thread) && P_CWD(leader))
		P_CWD(execve_thread) = strdup(P_CWD(leader));
	else
		update_cwd = true;

	tweak_execve_thread(leader, execve_thread);
	leader->abspath = NULL;
	leader->flags &= ~SYD_IN_EXECVE;
	bury_process(leader, false);

out:
	if (!clone_fs)
		new_shared_memory_clone_fs(execve_thread);
	if (update_cwd)
		sysx_chdir(execve_thread);
}

static syd_process_t *parent_process(pid_t pid_task, bool *genuine)
{
	int pfd = -1;

	/* Try (really) hard to find the parent process. */
	*genuine = true;

	/*
	 * Step 1: Check process Tgid and Ppid.
	 * 1. Is it correct to always prefer Tgid over Ppid?
	 * 2. Is it more reliable to switch steps 1 & 2?
	 */
	pid_t tgid, ppid;
	syd_process_t *node_tgid = NULL, *node_ppid = NULL;
	pfd = syd_proc_open(pid_task);
	if (pfd >= 0) {
		syd_proc_parents(pfd, &ppid, &tgid);
		close(pfd);
		node_tgid = process_lookup(tgid);
		if (node_tgid && node_tgid->flags & (SYD_IN_CLONE|SYD_IN_EXECVE))
			return node_tgid;
		node_ppid = process_lookup(ppid);
		if (node_ppid && node_ppid->flags & (SYD_IN_CLONE|SYD_IN_EXECVE))
			return node_ppid;
	}

	/*
	 * Step 2: Check for IN_CLONE|IN_EXECVE flags and /proc/$pid/task
	 * We need IN_EXECVE for threaded exec -> leader lost case.
	 */
	syd_process_t *node;
	syd_map_foreach_value(&sydbox->tree, node) {
		if (!(node->flags & (SYD_IN_CLONE|SYD_IN_EXECVE)))
			continue;

		int fd = syd_proc_open(node->pid);
		if (fd < 0)
			continue;

		bool ok = !syd_proc_task_find(fd, pid_task);
		close(fd);
		if (ok)
			return node;
	}

	/*
	 * Step 3: We tried really hard to find a parent process
	 * with a IN_CLONE or IN_EXECVE flag but failed.
	 * If available, use the tgid or ppid process entry
	 * even if it is lacking the correct process flag.
	 * If both are absent, use SydB☮x's execve pid which
	 * is guaranteed to be available at all times.
	 */
	*genuine = false;
	if (node_tgid)
		return node_tgid;
	else if (node_ppid)
		return node_ppid;
	else
		return process_lookup(sydbox->execve_pid);
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
	const char *CG, *CB, *CN, *CI, *CE; /* good, bad, important, normal end */
	struct proc_statinfo info;

	pid_t pid = current->pid;
	uint32_t arch = current->arch;
	pid_t ppid = current->ppid;
	pid_t tgid = current->tgid;
	struct acl_node *node;
	struct sockmatch *match;

	if (isatty(STDERR_FILENO)) {
		CG = ANSI_DARK_GREEN;
		CB = ANSI_DARK_MAGENTA;
		CI = ANSI_DARK_CYAN;
		CN = ANSI_DARK_YELLOW;
		CE = ANSI_NORMAL;
	} else {
		CG = CB = CI = CN = CE = "";
	}

	fprintf(stderr, "%s-- Information on Process ID: %u%s\n", CG, pid, CE);
	fprintf(stderr, "\t%sName: »%s«%s\n", CN, current->comm, CE);
	if (current->pid == sydbox->execve_pid)
		fprintf(stderr, "\t%sParent ID: SYDBOX%s\n", CN, CE);
	else if (current->ppid > 0)
		fprintf(stderr, "\t%sParent ID: %u%s\n", CN, ppid > 0 ? ppid : 0, CE);
	else
		fprintf(stderr, "\t%sParent ID: ? (Orphan)%s\n", CN, CE);
	fprintf(stderr, "\t%sThread Group ID: %u%s\n", CN, tgid > 0 ? tgid : 0, CE);
	fprintf(stderr, "\t%sCwd: »%s«%s\n", CN, P_CWD(current), CE);
	fprintf(stderr, "\t%sSyscall: {no:%lu arch:%d name:%s}%s\n", CN,
			current->sysnum, arch, current->sysname, CE);
#if 0
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
#endif

	if (!verbose)
		return;

	if (syd_proc_stat(sydbox->pfd, &info) < 0) {
		fprintf(stderr, "%sproc_stat failed (errno:%d %s)%s\n",
			CB, errno, strerror(errno), CE);
	} else {
		fprintf(stderr, "\t%sproc: pid=%d ppid=%d pgrp=%d%s\n",
			CI,
			info.pid, info.ppid, info.pgrp,
			CE);
		fprintf(stderr, "\t%sproc: comm=»%s« state=»%c«%s\n",
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
		fprintf(stderr, "\t\t%s»%s«%s\n", CN, (char *)node->match, CE);
	fprintf(stderr, "\t%sRead Whitelist:%s\n", CI, CE);
	ACLQ_FOREACH(node, &P_BOX(current)->acl_read)
		fprintf(stderr, "\t\t%s»%s«%s\n", CN, (char *)node->match, CE);
	fprintf(stderr, "\t%sWrite Whitelist:%s\n", CI, CE);
	ACLQ_FOREACH(node, &P_BOX(current)->acl_write)
		fprintf(stderr, "\t\t%s»%s«%s\n", CN, (char *)node->match, CE);
	fprintf(stderr, "\t%sNetwork Whitelist bind():%s\n", CI, CE);
	ACLQ_FOREACH(node, &P_BOX(current)->acl_network_bind) {
		match = node->match;
		if (match->str) {
			fprintf(stderr, "\t\t%s»%s«%s\n", CN, match->str, CE);
		} else {
			fprintf(stderr, "\t\t%s((%p))%s\n", CN, (void *)match, CE);
		}
	}
	fprintf(stderr, "\t%sNetwork Whitelist connect():%s\n", CI, CE);
	ACLQ_FOREACH(node, &P_BOX(current)->acl_network_connect) {
		match = node->match;
		if (match->str) {
			fprintf(stderr, "\t\t%s»%s«%s\n", CN, match->str, CE);
		} else {
			fprintf(stderr, "\t\t%s((%p))%s\n", CN, (void *)match, CE);
		}
	}
}

static void init_signal_sets(void)
{
	sigemptyset(&empty_set);
	sigemptyset(&blocked_set);

	sigaddset(&blocked_set, SIGALRM);
	sigaddset(&blocked_set, SIGCHLD);
	sigaddset(&blocked_set, SIGHUP);
	sigaddset(&blocked_set, SIGINT);
	sigaddset(&blocked_set, SIGQUIT);
	sigaddset(&blocked_set, SIGPIPE);
	sigaddset(&blocked_set, SIGTERM);
	sigaddset(&blocked_set, SIGUSR1);
	sigaddset(&blocked_set, SIGUSR2);
}

static inline void allow_signals(void)
{
	sigprocmask(SIG_SETMASK, &empty_set, NULL);
}
static inline void block_signals(void)
{
	sigprocmask(SIG_BLOCK, &blocked_set, NULL);
}

/* Signals are blocked by default. */
static void init_signals(void)
{
	struct sigaction sa;

	init_signal_sets(); block_signals();

	/* Ign */
	sa.sa_sigaction = interrupt;
	sa.sa_flags = SA_NOCLDSTOP|SA_RESTART|SA_SIGINFO;
	sigaction(SIGCHLD, &sa, &child_sa);

	/* Stop */
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	sigaction(SIGTTOU, &sa, NULL);
	sigaction(SIGTTIN, &sa, NULL);
	sigaction(SIGTSTP, &sa, NULL);

	/* Term */
	set_sighandler(SIGALRM, interrupt, NULL);
	set_sighandler(SIGHUP,	interrupt, NULL);
	set_sighandler(SIGINT,	interrupt, NULL);
	set_sighandler(SIGQUIT, interrupt, NULL);
	set_sighandler(SIGPIPE, interrupt, NULL);
	set_sighandler(SIGTERM, interrupt, NULL);
	set_sighandler(SIGUSR1, interrupt, NULL);
	set_sighandler(SIGUSR2, interrupt, NULL);
}

static void ignore_signals(void)
{
	struct sigaction sa;
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;

	sigaction(SIGTTOU, &sa, NULL);
	sigaction(SIGTTIN, &sa, NULL);
	sigaction(SIGTTOU, &sa, NULL);
	sigaction(SIGTSTP, &sa, NULL);
	sigaction(SIGALRM, &sa, NULL);
	sigaction(SIGHUP,  &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
}

static void reset_signals(void)
{
	struct sigaction sa;

	sa.sa_handler = SIG_DFL;
	sa.sa_flags = 0;

	sigaction(SIGCHLD, &sa, NULL);

	/* Stop */
	sigaction(SIGTTOU, &sa, NULL);
	sigaction(SIGTTIN, &sa, NULL);
	sigaction(SIGTSTP, &sa, NULL);

	/* Term */
	sigaction(SIGHUP,  &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
}

static void interrupt(int sig, siginfo_t *siginfo, void *context)
{
	if (siginfo) {
		interruptid = siginfo->si_pid;
		interruptcode = siginfo->si_code;
		interruptstat = siginfo->si_status;
	}
	interrupted = sig;
}

static int sig_child(void)
{
	int status;
	pid_t pid = interruptid;

	if (pid == sydbox->execve_pid) {
		if (interruptcode == CLD_EXITED)
			sydbox->exit_code = WEXITSTATUS(interruptstat);
		else if (interruptcode == CLD_KILLED ||
			 interruptcode == CLD_DUMPED)
			sydbox->exit_code = 128 + WTERMSIG(interruptstat);
	}

	syd_process_t *p = process_lookup(pid);
	if (p && process_is_zombie(p->pid)) {
		bury_process(p, true);
		return 0;
	}
	// reap_zombies();

	for (;;) {
		pid_t cpid;
		cpid = waitpid(pid, &status, __WALL|WNOHANG);
		if (cpid >= 0)
			return 0;
		switch (errno) {
		case EINTR:
			continue;
		case ECHILD:
			return 0;
		default:
			assert_not_reached();
		}
	}
}

static int handle_interrupt(int sig)
{
	/*
	 * Returning non-zero here terminates
	 * the main notify loop.
	 */
#if 0
#warning TODO: implement signal2name()
	const char *name = signal2name(sig);
#endif
	switch (sig) {
	case SIGALRM:
#if 0
		reap_zombies();
		return (process_count_alive() == 0) ? ECHILD : 0;
#endif
		return 0;
	case SIGCHLD:
		return sig_child();
	case SIGUSR1:
	case SIGUSR2:
#if 0
#warning TODO: nice useful work for statistics, finish up!
		dump(DUMP_INTR, "user.info", sig, name, sig == SIGUSR2);
#endif
		sig_usr(sig);
		return 0;
#if 0
#warning TODO: Give more details about the interrupts below.
	case SIGHUP:
	case SIGINT:
	case SIGPIPE:
	case SIGQUIT:
	case SIGTERM:
#endif
	default:
#if 0
#warning TODO: nice useful work for statistics, finish up!
		dump(DUMP_INTR, "kill.all", sig, name, sig != SIGINT;
#endif
		kill_all(sig);
		return 128 + sig;
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
	syd_map_foreach_value(&sydbox->tree, node) {
		dump_one_process(node, complete_dump);
		count++;
	}
	fprintf(stderr, "Tracing %u process%s\n", count, count > 1 ? "es" : "");
}

static void oops(int sig)
{
	kill_all(sig);
	dump(DUMP_CLOSE);
}

static void reap_zombies(void)
{
#if 0
#warning TODO: nice useful work for statistics, finish up!
#if SYDBOX_HAVE_DUMP_BUILTIN
	size_t zombi = 0;
	size_t death = 0;
	size_t alive = 0;
#endif
#endif
	syd_process_t *node;
	syd_map_foreach_value(&sydbox->tree, node) {
		//if (node->pid == sydbox->execve_pid)
		//	continue;
		/* Zombies includes dead processes too,
		 * so no need to do another round of
		 * pidfd_send_signal here, which
		 * does not detect zombies. */
		if (!node)
			continue;
		if (process_is_zombie(node->pid)) {
			bury_process(node, true);
		}
	}
#if 0
#if !SYDBOX_HAVE_DUMP_BUILTIN
		}
#else
		/* Send an additional 0 signal to the process pidfd
		 * for dump only. Disable with ./configure --disable-dump
		 */
			++zombi;
		} else if (process_is_alive(node->pid) {
			++alive;
		} else {
			++death;
		}
#endif
#endif
#if 0
#warning TODO: nice useful work for statistics, finish up!
#if SYDBOX_HAVE_DUMP_BUILTIN
	dump(DUMP_INTR, "reap.zombies", SIGCHLD, name, true,
	     alive, zombi, death);
#endif
#endif
}

static int process_send_signal(pid_t pid, int sig)
{
	if (kill(pid, sig) < 0)
		return -errno;
	return 0;
}

static inline size_t process_count_alive(void)
{
	size_t count = 0;
	syd_process_t *node;

	syd_map_foreach_value(&sydbox->tree, node) {
		/* See the explanation in reap_zombies */
		if (!process_is_zombie(node->pid))
			continue;
		count += 1;
	}

	return count;
}

static bool process_kill(pid_t pid, int sig)
{
	int r;

	if ((r = process_send_signal(pid, sig)) < 0)
		return r == -ESRCH;
	say_errno("pidfd_send_signal");
	return false;
}

#if 0
static inline bool process_is_alive(pid_t pid)
{
	return process_send_signal(pid, 0) != -1;
}
#endif

static inline bool process_is_zombie(pid_t pid)
{
	int r, fd;
	char state;

	fd = syd_proc_open(pid);
	if (fd < 0)
		return true; /* dead >= zombie */
	r = syd_proc_state(fd, &state);
	close(fd);
	switch (r) {
	case 0:
		return state == 'Z';
	default:
		return true; /* error accessing /proc, assume dead. */
	}
}

static inline syd_process_t *process_find_clone(pid_t child_pid, pid_t ppid,
						pid_t tgid)
{
	syd_process_t *node;

	syd_map_foreach_value(&sydbox->tree, node) {
		if (node->pid != ppid ||
		    node->pid != tgid)
			continue;
		if (node->flags & (SYD_IN_CLONE|SYD_IN_EXECVE))
			return node;
	}

	node = process_lookup(sydbox->execve_pid);
	if (node)
		node->new_clone_flags = 0;
	return node;
}

static inline pid_t process_find_exec(pid_t exec_pid)
{
	syd_process_t *node;

	syd_map_foreach_value(&sydbox->tree, node) {
		if (node->pid != node->tgid)
			continue;
		int fd = syd_proc_open(node->pid);
		if (fd < 0)
			continue;
		bool ok = syd_proc_task_find(fd, exec_pid);
		close(fd);
		if (ok)
			return node->pid;
	}

	return 0;
}

static syd_process_t *process_init(pid_t pid, syd_process_t *parent,
				   bool genuine)
{
	if (parent && pid == parent->pid)
		return process_lookup(pid);

	syd_process_t *current;
	if (parent) {
		current = clone_process(parent, pid, genuine);
		if (genuine)
			parent->clone_flags &= ~SYD_IN_CLONE;
	} else {
		parent = process_lookup(sydbox->execve_pid);
		unsigned int save_new_clone_flags = 0;
		if (parent) {
			save_new_clone_flags = parent->new_clone_flags;
			parent->new_clone_flags = 0;
		}
		current = clone_process(parent, pid, genuine);
		if (parent)
			parent->new_clone_flags = save_new_clone_flags;
	}
	current->pid = pid;
	proc_validate(pid);
	sysx_chdir(current);

#if 0
#if ENABLE_PSYSCALL
	int r;

	/* Allocate remote memory. */
	if ((r = syd_rmem_alloc(current)) < 0) {
		errno = -r;
		say_errno("syd_rmem_alloc");
	} else {
		say("process:%d has addr:%p allocated.",
		    current->pid, (void *)current->addr);
		say("doing a vm read/write sanity check on addr:%p...",
		    (void *)current->addr);
		syd_write_vm_data(current, current->addr, comm, 16);
		syd_read_vm_data(current, current->addr, comm_rem, 16);
		if (streq(comm, comm_rem)) {
			say("vm read/write check succeded: "
			    "»%s« = »%s«", comm, comm_rem);
		} else {
			say("vm read/write check failed: "
			    "»%s« != »%s«", comm, comm_rem);
		}
	}
#endif
#endif

	return current;
}

static void init_early(void)
{
	assert(!sydbox);

	os_release = get_os_release();

	sydbox = xcalloc(1, sizeof(sydbox_t));

	proc_invalidate();

	sydbox->arch[0] = UINT32_MAX;
	sydbox->seccomp_fd = -1;
	sydbox->notify_fd = -1;
	sydbox->export_mode = SYDBOX_EXPORT_NUL;

	sydbox->proc_fd = opendir("/proc");

	if (!syd_map_init_64v(&sydbox->tree,
			     SYDBOX_PROCMAP_CAP,
			     SYDBOX_MAP_LOAD_FAC)) {
		errno = ENOMEM;
		die_errno("failed to allocate hashmap for process tree");
	}

	config_init();
	filter_init();

	syd_abort_func(kill_all);
}

static int event_clone(syd_process_t *current, const char clone_type,
		       long clone_flags)
{
	assert(current);

	if (!current->new_clone_flags) {
		switch (clone_type) {
		case 'c':
		case 'f':
		case 'v':
			current->new_clone_flags = pack_clone_flags(clone_flags);
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

	if (P_BOX(current)->magic_lock == LOCK_PENDING) {
		/* magic commands are locked */
		P_BOX(current)->magic_lock = LOCK_SET;
	}

	current->flags |= SYD_IN_EXECVE;
	current->execve_pid = current->pid;

	if (!current->abspath) /* nothing left to do */
		return 0;

	/* kill_if_match */
	r = 0;
	if (acl_match_path(ACL_ACTION_NONE, &sydbox->config.exec_kill_if_match,
			   current->abspath, &match)) {
		say("kill_if_match pattern=»%s« matches execve path=»%s«",
		    match, current->abspath);
		say("killing process");
		process_kill(current->pid, SIGKILL);
		return -ESRCH;
	}
	/* execve path does not match if_match patterns */

	if (magic_query_violation_raise_safe(current)) {
		//say("execve: %d executed »%s«", current->pid, current->abspath);
		dump(DUMP_EXEC, current->pid, current->abspath);
	}

	//Intentionally not freeing to handle multithreaded execve. */
	//free(current->abspath);
	//current->abspath = NULL;

	return r;
}

static int event_syscall(syd_process_t *current)
{
	return sysnotify(current);
}

static int notify_loop()
{
	int r, intr;
	pid_t pid = -1;
	syd_process_t *current = NULL;

	if ((r = seccomp_notify_alloc(&sydbox->request,
				      &sydbox->response)) < 0) {
		errno = -r;
		die_errno("seccomp_notify_alloc");
	}

	for (;;) {
		/* Let the user-space tracing begin. */
		bool jump = false, reap_my_zombies = false;
		char *name = NULL;
		pid_t execve_pid = 0;
		syd_process_t *parent;

notify_receive:
		memset(sydbox->request, 0, sizeof(struct seccomp_notif));
		allow_signals();
		r = seccomp_notify_receive(sydbox->notify_fd,
					   sydbox->request);
		if (interrupted && (intr = handle_interrupt(interrupted)))
			break;
		interrupted = 0;
		block_signals();
		if (r < 0) {
			if (r == -EINTR)
				goto notify_receive;
			else if (r == -ECANCELED)
				break;
			else if (r == -ENOENT || errno == ENOTTY) {
				/* If we didn't find a notification,
				 * it could be that the task was
				 * interrupted by a fatal signal between
				 * the time we were woken and
				 * when we were able to acquire the rw lock.
				 */
				goto out;
			} else {
				errno = -r;
				say_errno("seccomp_notify_receive");
				say("abnormal error code from seccomp, "
				    "aborting!");
				say("Please submit a bug to "
				    "<"PACKAGE_BUGREPORT">");
				oops(SIGTERM);
				jump = true;
				goto out;
			}
		}

		memset(sydbox->response, 0, sizeof(struct seccomp_notif_resp));
		sydbox->response->id = sydbox->request->id;
		sydbox->response->val = 0;
		sydbox_syscall_deny(EPERM);
		if (sydbox->request->id == 0 && sydbox->request->pid == 0) {
			say("warning: seccomp request with neither id nor pid! "
			    "Denying...");
			goto notify_respond;
		}

		name = seccomp_syscall_resolve_num_arch(sydbox->request->data.arch,
							sydbox->request->data.nr);
		dump(DUMP_SECCOMP_NOTIFY_RECV, name, sydbox->request);
		if (!name) {
			/* TODO: make this a dump call! */
			say("Abnormal return from libseccomp!");
			say("System call name unknown, enable dump for details.");
			say("Denying system call...");
			say("Please submit a bug to "
			    "<"PACKAGE_BUGREPORT">");
			goto pid_validate;
		}
		pid = sydbox->request->pid;
		current = process_lookup(pid);
		if (current) {
			; /* do nothing */
#if 0
			if (current->flags & SYD_IN_CLONE) {
				/* Add premature children to the process tree */
				pid_t pid_task = -1;
				for (;;) {
					syd_proc_pid_next(sydbox->proc_fd,
							  &pid_task);
					if (pid_task == 0)
						break;
					int pfd;
					pfd = syd_proc_open(pid_task);
					if (pfd < 0)
						continue;
					pid_t ppid = -1, tgid = -1;
					if (!syd_proc_parents(pfd, &ppid, &tgid) &&
					    (ppid == current->pid ||
					     tgid == current->pid) &&
					    !process_lookup(pid_task))
						process_init(pid_task,
							     current,
							     false);
					close(pfd);
				}
				if (pid_task >= 0) {
					closedir(sydbox->proc_fd);
					sydbox->proc_fd =
						opendir("/proc");
				}
			}
#endif
		} else {
			int fd;

			/* Here we make an exception and attempt to
			 * open /proc without validation for the sake
			 * of the completeness and aptness of our
			 * process tree.
			 */
			if ((fd = syd_proc_open(pid)) >= 0) {
				pid_t ppid = -1, tgid = -1;
				parent = NULL;
				if (!syd_proc_parents(fd, &ppid, &tgid))
					parent = process_find_clone(pid, ppid, tgid);
				close(fd);
				/* We call process_init regardless of the fact
				 * that parent is NULL. If parent is NULL,
				 * process_init is going to inherit from
				 * sydbox->execve_pid and present the process
				 * with a reasonable sandboxing setup.
				 */
				current = process_init(pid, parent, true);
				if (parent && current != parent)
					parent->clone_flags &=
						~(SYD_IN_CLONE|SYD_IN_EXECVE);
				parent = NULL;
			}
		}
		if (current) {
			current->sysnum = sydbox->request->data.nr;
			current->sysname = name;
			for (unsigned short idx = 0; idx < 6; idx++)
				current->args[idx] = sydbox->request->data.args[idx];
		}

		/*
		 * Handle critical paths early and fast.
		 * Search early for exec before getting a process entry.
		 */
		if (startswith(name, "exec")) {
			pid_t leader_pid = process_find_exec(pid);
			if (!current) {
				parent = process_lookup(leader_pid);
				current = process_init(pid, parent, true);
			}
			if (current)
				execve_pid = current->execve_pid;
			else
				execve_pid = pid;
			if (execve_pid == 0 && pid != leader_pid)
				execve_pid = leader_pid;
			/* The remaining part of exec will be handled as part
			 * of the event_syscall branch after pid_validate */
		}

pid_validate:
		if (name && !current) {
			bool genuine;
			parent = parent_process(pid, &genuine);
			current = process_init(pid, parent, genuine);
		}
		/*
		 * Perform PID validation,
		 * if it succeeds proceed with sandboxing,
		 * if it fails deny the system call with ESRCH.
		 */
		if (current) {
			proc_validate_or_deny(current, notify_respond);
			if (current) {
				current->sysnum = sydbox->request->data.nr;
				current->sysname = name;
				for (unsigned short idx = 0; idx < 6; idx++)
					current->args[idx] =
						sydbox->request->data.args[idx];
				if (current->update_cwd) {
					r = sysx_chdir(current);
					if (r < 0)
						say_errno("sys_chdir");
					current->update_cwd = false;
				}
				dump(DUMP_SECCOMP_PID_VALID, name,
				     sydbox->request);
#if 0
				say("pid:%d execve_pid:%d sydbox_pid:%d name:%s",
				    pid, sydbox->execve_pid, sydbox->sydbox_pid,
				    name);
#endif
			}
		}

		bool not_clone = true;
		bool not_exec = true;
		if (!name) {
			; /* goto notify_respond; */
		} else if (startswith(name, "exit")) {
			sydbox_syscall_allow();
			if (current && current->pid == sydbox->execve_pid)
				sydbox->exit_code = current->args[0];
		} else if (streq(name, "clone")) {
			sydbox_syscall_allow();
			not_clone = false;
			if (current)
				event_clone(current, 'c',
					    current->args[SYD_CLONE_ARG_FLAGS]);
		} else if (streq(name, "clone2")) {
			sydbox_syscall_allow();
			not_clone = false;
			if (current)
				event_clone(current, 'c',
					    current->args[SYD_CLONE_ARG_FLAGS]);
		} else if (streq(name, "clone3")) {
			sydbox_syscall_allow();
			not_clone = false;
			if (current)
				event_clone(current, 'c',
					    current->args[SYD_CLONE_ARG_FLAGS]);
		} else if (streq(name, "fork")) {
			sydbox_syscall_allow();
			not_clone = false;
			if (current)
				event_clone(current, 'f', 0);
		} else if (streq(name, "vfork")) {
			sydbox_syscall_allow();
			not_clone = false;
			if (current)
				event_clone(current, 'v', 0);
		} else {
			/*
			 * All sandboxed system calls end up here.
			 * This includes execve*
			 */
			if (current) {
				sydbox_syscall_allow();
				if (startswith(name, "exec") &&
				    sydbox->execve_wait) {
					/* allow the initial exec */
					not_exec = true;
					sydbox->execve_wait = false;
					/* Since we double fork, we can only
					 * get the process id here. */
					sydbox->execve_pid = current->pid;
				} else if (name) {
					current->sysnum = sydbox->request->data.nr;
					current->sysname = xstrdup(name);
					for (unsigned short idx = 0; idx < 6; idx++)
						current->args[idx] =
							sydbox->request->data.args[idx];
					event_syscall(current);
					free((char *)current->sysname);
					current->sysname = NULL;
				}
			}
			if (execve_pid) {
				if (current) {
					event_exec(current);
#if ENABLE_PSYSCALL
					set_process_name = true;
#endif
				}
				if (pid == execve_pid) {
					if (current)
						current->execve_pid = 0;
				} else {
					current = process_lookup(pid);
					switch_execve_leader(execve_pid,
							     current);
					current->execve_pid = 0;
					/* reap zombies after notify respond
					reap_my_zombies = true; */
				}
				if (current) {
					if (current->abspath) {
						free(current->abspath);
						current->abspath = NULL;
					}
					sysx_chdir(current);
				}
			} else {
				;/*not_exec = false;*/
			}
		}

		if (current && not_clone)
			current->flags &= ~SYD_IN_CLONE;
		if (current && not_exec)
			current->flags &= ~SYD_IN_EXECVE;

notify_respond:
		r = seccomp_notify_respond(sydbox->notify_fd,
					   sydbox->response);
		if (r < 0) {
			if (r == -EINTR || errno == EINTR)
				goto notify_respond;
			else if (r == -ECANCELED)
				break;
			else if (r == -ENOENT || errno == ENOTTY) {
				/* If we didn't find a notification,
				 * it could be that the task was
				 * interrupted by a fatal signal between
				 * the time we were woken and
				 * when we were able to acquire the rw lock.
				 */
				goto out;
			} else {
				errno = -r;
				say_errno("seccomp_notify_receive");
				say("abnormal error code from seccomp, "
				    "aborting!");
				say("Please submit a bug to "
				    "<"PACKAGE_BUGREPORT">");
				oops(SIGTERM);
				jump = true; goto out;
			}
		}
out:
		if (name)
			free(name);
		if (reap_my_zombies) {
			reap_my_zombies = false;
			reap_zombies();
		}
#if 0
#if ENABLE_PSYSCALL
		if (pprctl(current->pid, PR_SET_NAME, (unsigned long)comm,
			   0, 0, 0) < 0)
			say_errno("pprctl");
		else
			say("pprctl: comm:%s", comm);
#endif
#endif
		if (jump) {
			jump = false;
			break;
		}
		/* We handled quick cases, we are permitted to interrupt now. */
		r = 0;
		allow_signals();
		if (interrupted && (r = handle_interrupt(interrupted)))
			break;
		interrupted = 0;
	}

	seccomp_notify_free(sydbox->request, sydbox->response);
	close(sydbox->notify_fd);
	sydbox->notify_fd = -1;

	/*
	 * Sandboxing is over, reset signals to
	 * their original states.
	 */
	reset_signals();

	return r;
}

static syd_process_t *startup_child(int argc, char **argv)
{
	int r, pfd[2];
	char *pathname = NULL;
	pid_t pid = 0;
	syd_process_t *current;

	current = new_process_or_kill(pid);
	/* Happy birthday, child.
	 * Let's validate your PID manually.
	 */
	sydbox->execve_pid = pid;
	sydbox->execve_wait = true;
	sydbox->pid_valid = PID_INIT_VALID;

	bool noexec = streq(argv[0], SYDBOX_NOEXEC_NAME);
	if (!noexec) {
		pathname = path_lookup(argv[0]);
	} else {
		strlcpy(sydbox->hash, "<noexec>", sizeof("<noexec>"));
	}

	/* Initialize Secure Computing */
	seccomp_setup();

	/* All ready, initialise dump */
	dump(DUMP_INIT, pathname, argv[0], get_arg0(), arch_argv);

	/* We may free the elements of arch_argv now,
	 * they are no longer required.
	 * FIXME: Freeing here segfaults, why?
	for (size_t i = 0; arch_argv[i] != NULL; i++)
		free(arch_argv[i]);
	arch_argv[0] = NULL;
	*/

	if (!noexec && !pathname)
		die_errno("can't exec »%s«", argv[0]);
	if (pipe2(pfd, O_CLOEXEC|O_DIRECT) < 0)
		die_errno("can't pipe");

	/*
	 * Mark SydB☮x's process id so that the seccomp filtering can
	 * apply the unconditional restrictions about SydB☮x process
	 * receiving any signal other than SIGCHLD.
	 */
#define SYD_CLONE_FLAGS (CLONE_CLEAR_SIGHAND|\
			 CLONE_PARENT_SETTID)
	sydbox->sydbox_pid = getpid();
startup_child:
	sydbox->execve_pid = syd_clone(SYD_CLONE_FLAGS | unshare_flags,
				       SIGCHLD, &sydbox->execve_pidfd);
	pid = sydbox->execve_pid;
	if (pid < 0) {
		if (errno == EINVAL) {
			/* Filter out unsupported clone flags and retry... */
			for (uint8_t i = 0; i < SYD_UNSHARE_FLAGS_MAX; i++) {
				if (unshare_flags & syd_unshare_flags[i]) {
					say("clone3 failed, retrying without "
					    "flag:%d", syd_unshare_flags[i]);
					unshare_flags &= ~syd_unshare_flags[i];
					goto startup_child;
				}
			}
		}
		die_errno("can't fork");
	} else if (pid == 0) {
		sydbox->execve_pid = getpid();
		sydbox->in_child = true;
		sydbox->seccomp_fd = pfd[1];

		pid = sydbox->execve_pid;
		current->pid = pid;
		proc_validate(pid);
		init_process_data(current, NULL, false); /* calls proc_cwd */
		strlcpy(current->comm, sydbox->program_invocation_name,
			SYDBOX_PROC_MAX);
		syd_proc_cmdline(sydbox->pfd, current->prog, LINE_MAX-1);
		current->prog[LINE_MAX-1] = '\0';
		/* 16 bytes including the terminating NUL byte.
		* syd- is 4 bytes.
		* comm is max 7 bytes.
		* hash is 5..9 bytes.
		*/
		char comm[16];
		syd_proc_comm(sydbox->pfd, current->comm, SYDBOX_PROC_MAX);
		size_t len = strlen(current->comm);
		size_t clen = len;
		strlcpy(comm , current->comm, clen + 1);
		strlcat(comm + clen++, "☮", sizeof("☮"));
		char *proc_exec;
		xasprintf(&proc_exec, "/proc/%u/exe", current->pid);
		if ((r = syd_path_to_sha1_hex(proc_exec, sydbox->hash)) < 0) {
			errno = -r;
			say_errno("can't calculate checksum of file "
				  "»%s«", proc_exec);
		} else {
			strlcat(comm + clen, sydbox->hash, 16);
		}
		comm[15] = '\0';
		set_arg0(comm);

		if (change_umask() < 0)
			say_errno("change_umask");
		if (change_nice() < 0)
			say_errno("change_nice");
		if (change_ionice() < 0)
			say_errno("change_ionice");
		if (change_background() < 0)
			die_errno("change_background");
		cleanup_for_child();

		if (!child_block_interrupt_signals)
			goto seccomp_init;
		ignore_signals();
		new_tio = old_tio;
		new_tio.c_cc[VINTR]    = 25; /* Ctrl-c */
		new_tio.c_cc[VQUIT]    = 3; /* Ctrl-\ */
		new_tio.c_cc[VERASE]   = 0; /* del */
		new_tio.c_cc[VKILL]    = 3; /* @ */
		new_tio.c_cc[VEOF]     = 25/*4*/; /* Ctrl-d */
		new_tio.c_cc[VTIME]    = 0; /* inter-character timer unused */
		new_tio.c_cc[VMIN]     = 1; /* blocking read until 1 character arrives */
		new_tio.c_cc[VSWTC]    = 0; /* '\0' */
		new_tio.c_cc[VSTART]   = 3; /* Ctrl-q */
		new_tio.c_cc[VSTOP]    = 3; /* Ctrl-s */
		new_tio.c_cc[VSUSP]    = 3; /* Ctrl-z */
		new_tio.c_cc[VEOL]     = 0; /* '\0' */
		new_tio.c_cc[VREPRINT] = 0; /* Ctrl-r */
		new_tio.c_cc[VDISCARD] = 0; /* Ctrl-u */
		new_tio.c_cc[VWERASE]  = 0; /* Ctrl-w */
		new_tio.c_cc[VLNEXT]   = 0; /* Ctrl-v */
		new_tio.c_cc[VEOL2]    = 0; /* '\0' */
		tcsetattr(0, TCSANOW, &new_tio);
seccomp_init:
		if ((r = sysinit_seccomp()) < 0) {
			errno = -r;
			if (errno == ENOTTY || errno == ENOENT)
				errno = EINVAL;
			die_errno("seccomp load failed");
		}
		cleanup_for_sydbox();
		free(sydbox);
		if (noexec)
			_exit(getenv(SYDBOX_NOEXEC_ENV) ?
				atoi(getenv(SYDBOX_NOEXEC_ENV)) :
				0);
		struct syd_execv_opt opt;

		opt.verbose = false;
#if SYDBOX_HAVE_DUMP_BUILTIN
		opt.verbose = dump_get_fd() >= 0;
#endif
		opt.alias = get_arg0();
		opt.workdir = get_working_directory();
		opt.chroot = get_root_directory();
		opt.pid_env_var = get_pid_env_var();
		get_pivot_root((char **)&opt.new_root,
			       (char **)&opt.put_old);
		opt.unshare_flags = unshare_flags;
		opt.uid = get_uid();
		opt.gid = get_gid();
		opt.close_fds_beg = close_fds[0];
		opt.close_fds_end = close_fds[1];
		opt.keep_sigmask = keep_sigmask;
		opt.escape_stdout = escape_stdout;
		opt.allow_daemonize = allow_daemonize;
		opt.make_group_leader = make_group_leader;
		opt.parent_death_signal = parent_death_signal;
		opt.supplementary_gids = get_groups();
		r = syd_execv(pathname, argc, argv, &opt);
		if (r < 0) {
			errno = -pid;
			say_errno("Error executing »%s«", pathname);
		}
		free(pathname);
		_exit(127);
	}
	seccomp_release(sydbox->ctx);

	/* write end of the pipe is not used. */
	close(pfd[1]);

	if (sydbox->export_path)
		free(sydbox->export_path);
	if (pathname)
		free(pathname);

	sydbox->seccomp_fd = pfd[0];
	if (!use_notify())
		return current;

	int fd;
	if ((r = parent_read_int(&fd)) < 0) {
		errno = -r;
		say_errno("Failed to load seccomp filters");
		say("Invalid sandbox options given.");
		exit(-r);
	}

	int pidfd;
	if ((pidfd = syd_pidfd_open(pid, 0)) < 0)
		die_errno("Failed to open pidfd for pid:%d", pid);
	if ((fd = syd_pidfd_getfd(pidfd, fd, 0)) < 0)
		 die_errno("Failed to obtain seccomp user fd");
	sydbox->notify_fd = fd;

	close(pfd[0]);
	sydbox->seccomp_fd = -1;

	current->pid = pid;
	sydbox->execve_pid = pid;

	return current;
}

void cleanup_for_child(void)
{
	static bool cleanup_for_child_done = false;

	if (cleanup_for_child_done)
		return;
	else
		cleanup_for_child_done = true;
	assert(sydbox);

	if (sydbox->proc_fd)
		closedir(sydbox->proc_fd);
	if (sydbox->program_invocation_name)
		free(sydbox->program_invocation_name);

	/* FIXME: Why can't we free these? */
#if 0
	if (syd_map_size_64s(&sydbox->config.proc_pid_auto)) {
		syd_map_clear_64s(&sydbox->config.proc_pid_auto);
		syd_map_term_64s(&sydbox->config.proc_pid_auto);
	}
	if (syd_map_size_64v(&sydbox->tree)) {
		syd_map_clear_64v(&sydbox->tree);
		syd_map_term_64v(&sydbox->tree);
	}

	filter_free();
	// reset_sandbox(&sydbox->config.box_static);
#endif

	struct acl_node *acl_node;
	ACLQ_FREE(acl_node, &sydbox->config.exec_kill_if_match, xfree);

	ACLQ_FREE(acl_node, &sydbox->config.filter_exec, xfree);
	ACLQ_FREE(acl_node, &sydbox->config.filter_read, xfree);
	ACLQ_FREE(acl_node, &sydbox->config.filter_write, xfree);
	ACLQ_FREE(acl_node, &sydbox->config.filter_network, free_sockmatch);
}

void cleanup_for_sydbox(void)
{
	assert(sydbox);

	if (sydbox->seccomp_fd >= 0) {
		close(sydbox->seccomp_fd);
		sydbox->seccomp_fd = -1;
	}
	if (sydbox->notify_fd >= 0) {
		close(sydbox->notify_fd);
		sydbox->notify_fd = -1;
	}

	cleanup_for_child();
}

int main(int argc, char **argv)
{
	/*
	 * Act as a multicall binary for
	 * the Syd family of commands.
	 */
	if (argc > 1) {
		if (streq(argv[1], "errno")) {
			execv(BINDIR"/syd-errno", argv + 1);
			exit(ECANCELED);
		}
		if (streq(argv[1], "format")) {
			execv(BINDIR"/syd-format", argv + 1);
			exit(ECANCELED);
		}
		if (streq(argv[1], "hilite")) {
			execv(BINDIR"/syd-hilite", argv + 1);
			exit(ECANCELED);
		}
		if (streq(argv[1], "shoebox")) {
			execv(BINDIR"/syd-shoebox", argv + 1);
			exit(ECANCELED);
		}
		if (streq(argv[1], "test")) {
			execv(BINDIR"/syd-test", argv + 1);
			exit(ECANCELED);
		}
		if (streq(argv[1], "dump")) {
			execv(LIBEXECDIR"/syd-dump", argv + 1);
			exit(ECANCELED);
		}
	}
	enum {
		/* unshare options */
		OPT_MOUNTPROC = CHAR_MAX + 1,
		OPT_PROPAGATION,
		OPT_SETGROUPS,
		OPT_KEEPCAPS,
		OPT_MONOTONIC,
		OPT_BOOTTIME,
		OPT_MAPUSER,
		OPT_MAPGROUP,
		/* syd options */
		OPT_MEMACCESS,
		OPT_PIVOT_ROOT,
		OPT_PROFILE,
		OPT_NICE,
		OPT_IONICE,
		OPT_UID,
		OPT_GID,
		OPT_ADD_GID,
		OPT_CLOSE_FDS,
		OPT_RESET_FDS,
		OPT_KEEP_SIGMASK,
	};

	int arg, opt, r, opt_t[5];
	size_t i;
	char *c, *opt_magic = NULL;
	struct utsname buf_uts;

	uid_t real_euid = geteuid();
	gid_t real_egid = getegid();

	/* Zero-initialise option states */
	enum sydbox_export_mode opt_export_mode = SYDBOX_EXPORT_NUL;
	uint8_t opt_mem_access = SYDBOX_CONFIG_MEMACCESS_MAX;

	/* Early initialisations */
	dump_set_fd(-3); init_early();

	arch_native = seccomp_arch_native();

#if SYDBOX_HAVE_DUMP_BUILTIN
	int dfd = -1;
	char *end;

# if SYDBOX_DUMP
	dfd = STDERR_FILENO;
	dump_fd(STDERR_FILENO);
# endif

	if (strstr(argv[0], "-dump")) {
		dfd = STDERR_FILENO;
		dump_set_fd(STDERR_FILENO);
	}

	const char *shoebox = getenv("SHOEBOX");
	if (shoebox) {
		dfd = open(shoebox, SYDBOX_DUMP_FLAGS, SYDBOX_DUMP_MODE);
		if (dfd < 0)
			die_errno("open(»%s«)", shoebox);
		dump_set_fd(dfd);
	}
#endif

	/* Long options are present for compatibility with sydbox-0.
	 * Thus they are not documented!
	 */
	int options_index;
	char *profile_name;
	struct option long_options[] = {
		/* default options */
		{"help",	no_argument,		NULL,	'h'},
		{"version",	no_argument,		NULL,	'v'},

		/* sydbox-0 & paludis compat. */
		{"profile",	required_argument,	NULL,	OPT_PROFILE},

		/* core options */
		{"arch",	required_argument,	NULL,	'a'},
		{"bpf",		no_argument,		NULL,	'b'},
		{"lock",	no_argument,		NULL,	'l'},
		{"dump",	no_argument,		NULL,	'd'},
		{"export",	required_argument,	NULL,	'e'},
		{"dry-run",	no_argument,		NULL,	'n'},
		{"memaccess",	required_argument,	NULL,	OPT_MEMACCESS},

		/* configuration */
		{"file",	required_argument,	NULL,	'f'},
		{"syd",		required_argument,	NULL,	'y'},

		/* namespaces (containers) */
		{"mount",	optional_argument, NULL, 'm'},
		{"uts",		optional_argument, NULL, 'u'},
		{"ipc",		optional_argument, NULL, 'i'},
		{"net",		optional_argument, NULL, 'N'},
		{"pid",		optional_argument, NULL, 'p'},
		{"user",	optional_argument, NULL, 'U'},
		{"cgroup",	optional_argument, NULL, 'C'},
		{"time",	optional_argument, NULL, 'T'},

		{ "fork",	 no_argument,	    NULL, 'F'		},
		{ "kill-child",  optional_argument, NULL, '!'},
		/*{"set-parent-death-signal",
			required_argument,		NULL,	'!'},*/
		{ "mount-proc",  optional_argument, NULL, OPT_MOUNTPROC},
		{ "map-user",	 required_argument, NULL, OPT_MAPUSER},
		{ "map-group",	 required_argument, NULL, OPT_MAPGROUP},
		{ "map-root-user", no_argument,       NULL, 'r'		},
		{ "map-current-user", no_argument,    NULL, 'c'		},
		{ "propagation",required_argument, NULL, OPT_PROPAGATION},
		{ "setgroups",	required_argument, NULL, OPT_SETGROUPS},
		{ "keep-caps",	no_argument,	   NULL, OPT_KEEPCAPS},
		{ "setuid",	required_argument, NULL, 'S'		},
		{ "setgid",	required_argument, NULL, 'G'		},
		{ "root",	required_argument, NULL, 'R'		},
		{ "pivot-root",	required_argument,	NULL,	OPT_PIVOT_ROOT},
		{ "wd",		required_argument, NULL, 'w'		},
		{ "monotonic",	required_argument, NULL, OPT_MONOTONIC},
		{ "boottime",	required_argument, NULL, OPT_BOOTTIME},

		/* daemon tools */
		{"allow-daemonize", no_argument,	NULL,	'+'},
		{"background",	no_argument,		NULL,	'&'},
		{"stdout",	required_argument,	NULL,	'1'},
		{"stderr",	required_argument,	NULL,	'2'},
		{"alias",	required_argument,	NULL,	'A'},
		{"uid",		required_argument,	NULL,	OPT_UID},
		{"gid",		required_argument,	NULL,	OPT_GID},
		{"add-gid",	required_argument,	NULL,	OPT_ADD_GID},
		{"umask",	required_argument,	NULL,	'K'},

		/* environment */
		{"env",		required_argument,	NULL,	'E'},
		{"env-var-with-pid",required_argument,	NULL,	'V'},

		/* resource management */
		{"nice",	required_argument,	NULL,	OPT_NICE},
		{"ionice",	required_argument,	NULL,	OPT_IONICE},


		/* fd/signal management */
		{"close-fds",	optional_argument,	NULL,	OPT_CLOSE_FDS},
		{"reset-fds",	no_argument,		NULL,	OPT_RESET_FDS},
		{"keep-sigmask", no_argument,		NULL,	OPT_KEEP_SIGMASK},
		{"escape-stdout", no_argument,		NULL,	'O'},

		{"test",	no_argument,		NULL,	't'},

		{NULL,		0,		NULL,	0},
	};

	const struct sigaction sa = { .sa_handler = SIG_DFL };
	if (sigaction(SIGCHLD, &sa, &child_sa) < 0)
		die_errno("sigaction");

	while ((opt = getopt_long(argc, argv,
				  "hva:bld:e:ny:fmuiNpUCTFrcS:G:R:w:+:&:1:2:A:K:E:V:Ot",
				  long_options, &options_index)) != EOF) {
		switch (opt) {
		case 'h':
			usage(stdout, 0);
		case 'v':
			syd_about(stdout);
			return 0;
		case OPT_PROFILE:
			/* special case for backwards compatibility */
			profile_name = xmalloc(sizeof(char) * (strlen(optarg) + 2));
			profile_name[0] = SYDBOX_PROFILE_CHAR;
			strcpy(&profile_name[1], optarg);
			config_parse_spec(profile_name);
			free(profile_name);
			break;
		case 'a':
			if (arch_argv_idx >= SYD_SECCOMP_ARCH_ARGV_SIZ - 1)
				die("too many -a arguments");
			arch_argv[arch_argv_idx++] = xstrdup(optarg);
			arch_argv[arch_argv_idx] = NULL;
			break;
		case 'b':
			sydbox->bpf_only = true;
			break;
		case 'l':
			opt_magic = "core/trace/magic_lock:on";
			break;
#if SYDBOX_HAVE_DUMP_BUILTIN
		case 'd':
			if (!optarg) {
				dump_set_fd(STDERR_FILENO);
			} else if (!strcmp(optarg, "tmp")) {
				dump_set_fd(-42);
			} else {
				errno = 0;
				dfd = strtoul(optarg, &end, 10);
				if ((errno && errno != EINVAL) ||
				    (unsigned long)dfd	> INT_MAX)
				{
					say_errno("Invalid argument for option -d: "
						  "»%s«", optarg);
					usage(stderr, 1);
				} else if (end != strchr(optarg, '\0')) {
					dfd = open(optarg, SYDBOX_DUMP_FLAGS,
						   SYDBOX_DUMP_MODE);
					if (dfd < 0)
						die_errno("Failed to open "
							  "dump file »%s«",
							  optarg);
				}
				dump_set_fd(dfd);
			}
			break;
#else
		case 'd':
			say("dump not supported, compile with --enable-dump");
			usage(stderr, 1);
#endif
		case 'e':
			if (startswith(optarg, "bpf")) {
				opt_export_mode = SYDBOX_EXPORT_BPF;
			} else if (startswith(optarg, "pfc")) {
				opt_export_mode = SYDBOX_EXPORT_PFC;
			} else {
				say("Invalid argument to --export");
				usage(stderr, 1);
			}
			if (strlen(optarg) > 4 && optarg[3] == ':')
				sydbox->export_path = xstrdup(optarg + 4);
			break;
		case OPT_MEMACCESS:
			errno = 0;
			opt = strtoul(optarg, &end, 10);
			if ((errno && errno != EINVAL) ||
			    (unsigned long)opt > SYDBOX_CONFIG_MEMACCESS_MAX)
			{
				say_errno("Invalid argument for option --memory: "
					  "»%s«", optarg);
				usage(stderr, 1);
			}
			opt_mem_access = opt;
			break;
		case 'n':
			sydbox->permissive = true;
			break;
		case 'f':
			config_parse_spec(optarg);
			break;
		case 'y':
			r = magic_cast_string(NULL, optarg, 0);
			if (MAGIC_ERROR(r))
				die("invalid magic: »%s«: %s",
				    optarg, magic_strerror(r));
			break;
		case 'm':
			unshare_flags |= CLONE_NEWNS;
			if (optarg)
				syd_set_ns_target(CLONE_NEWNS, optarg);
			break;
		case 'u':
			unshare_flags |= CLONE_NEWUTS;
			if (optarg)
				syd_set_ns_target(CLONE_NEWUTS, optarg);
			break;
		case 'i':
			unshare_flags |= CLONE_NEWIPC;
			if (optarg)
				syd_set_ns_target(CLONE_NEWIPC, optarg);
			break;
		case 'N':
			unshare_flags |= CLONE_NEWNET;
			if (optarg)
				syd_set_ns_target(CLONE_NEWNET, optarg);
			break;
		case 'p':
			unshare_flags |= CLONE_NEWPID;
			if (optarg)
				syd_set_ns_target(CLONE_NEWPID, optarg);
			break;
		case 'U':
			unshare_flags |= CLONE_NEWUSER;
			if (optarg)
				syd_set_ns_target(CLONE_NEWUSER, optarg);
			break;
		case 'C':
			unshare_flags |= CLONE_NEWCGROUP;
			if (optarg)
				syd_set_ns_target(CLONE_NEWCGROUP, optarg);
			break;
		case 'T':
			unshare_flags |= CLONE_NEWTIME;
			if (optarg)
				syd_set_ns_target(CLONE_NEWTIME, optarg);
			break;
		case OPT_MOUNTPROC:
			unshare_flags |= CLONE_NEWNS;
			procmnt = optarg ? optarg : "/proc";
			break;
		case OPT_MAPUSER:
			errno = 0;
			mapuser_opt = strtoul(optarg, &end, 10);
			if ((errno && errno != EINVAL) ||
			    (unsigned long)mapuser_opt > UID_MAX)
			{
				say_errno("Invalid argument for option --mapuser: "
					  "»%s«", optarg);
				usage(stderr, 1);
			}/* else if (end != strchr(optarg, '\0')) { */
			unshare_flags |= CLONE_NEWUSER;
			mapuser = (uid_t)mapuser_opt;
			break;
		case OPT_MAPGROUP:
			errno = 0;
			mapgroup_opt = strtoul(optarg, &end, 10);
			if ((errno && errno != EINVAL) ||
			    (unsigned long)mapgroup_opt > GID_MAX)
			{
				say_errno("Invalid argument for option --mapgroup: "
					  "»%s«", optarg);
				usage(stderr, 1);
			}/* else if (end != strchr(optarg, '\0')) { */
			unshare_flags |= CLONE_NEWUSER;
			mapgroup = (gid_t)mapgroup_opt;
			break;
		case 'r':
			unshare_flags |= CLONE_NEWUSER;
			mapuser = 0;
			mapgroup = 0;
			break;
		case 'c':
			unshare_flags |= CLONE_NEWUSER;
			mapuser = real_euid;
			mapgroup = real_egid;
			break;
		case OPT_SETGROUPS:
			setgrpcmd = syd_setgroups_toi(optarg);
			break;
		case OPT_PROPAGATION:
			propagation = syd_parse_propagation(optarg);
			break;
#if 0
		case OPT_KEEPCAPS:
			keepcaps = 1;
			cap_last_cap(); /* Force last cap to be cached before we fork. */
			break;
#endif
		case 'S':
			if ((r = safe_atoi(optarg, &arg) < 0)) {
				errno = -r;
				say_errno("Invalid argument for --setuid option: "
					  "»%s«", optarg);
				usage(stderr, 1);
			}
			uid = (uid_t)arg;
			force_uid = 1;
			break;
		case OPT_ADD_GID:
			if ((r = safe_atoi(optarg, &arg) < 0)) {
				errno = -r;
				say_errno("Invalid argument for --setgid option: "
					  "»%s«", optarg);
				usage(stderr, 1);
			}
			gid = (gid_t)arg;
			force_gid = 1;
			break;
		case 'R':
			newroot = optarg;
			set_root_directory(xstrdup(newroot));
			break;
		case 'w':
			newdir = optarg;
			set_working_directory(xstrdup(newdir));
			break;
		case OPT_MONOTONIC:
			if ((r = safe_atou(optarg, (unsigned *)&monotonic) < 0)) {
				errno = -r;
				say_errno("Invalid argument for --monotonic option: "
					  "»%s«", optarg);
				usage(stderr, 1);
			}
			force_monotonic = 1;
			break;
		case OPT_BOOTTIME:
			if ((r = safe_atou(optarg, (unsigned *)&boottime) < 0)) {
				errno = -r;
				say_errno("Invalid argument for --boottime option: "
					  "»%s«", optarg);
				usage(stderr, 1);
			}
			force_boottime = 1;
			break;
		case 'A':
			set_arg0(xstrdup(optarg));
			break;
		case '&':
			set_background(true);
			allow_daemonize = true;
			break;
		case '!':
			parent_death_signal = syd_name2signal(optarg);
			if (parent_death_signal < 0) {
				say("Invalid signal »%s« passed to option "
				    "--parent-death-signal", optarg);
				usage(stderr, 1);
			}
			break;
		case '1':
			set_redirect_stdout(xstrdup(optarg));
			break;
		case '2':
			set_redirect_stderr(xstrdup(optarg));
			break;
		case OPT_PIVOT_ROOT:
			c = strchr(optarg, ':');
			if (!c) {
				say_errno("Invalid argument for option "
					  "--pivot-root »%s«", optarg);
				usage(stderr, 1);
			}
			*c = '\0';
			set_pivot_root(optarg, c + 1);
			break;
		case OPT_IONICE:
			c = strchr(optarg, ':');
			if (!c)
				set_ionice(atoi(optarg), 0);
			else
				set_ionice(atoi(optarg), atoi(c + 1));
			break;
		case OPT_NICE:
			set_nice(atoi(optarg));
			break;
		case 'K':
			set_umask(atoi(optarg));
			break;
		case OPT_UID:
			set_uid(atoi(optarg));
			break;
		case OPT_GID:
			set_gid(atoi(optarg));
			break;
		case 'V':
			set_pid_env_var(optarg);
			break;
		case 'E':
			if (putenv(optarg))
				die_errno("putenv");
			break;
		case 't':
			test_setup();
			say("[>] Checking for libseccomp architectures...");
			/* test_seccomp_arch() returns the number of valid
			 * architectures. */
			opt_t[0] = test_seccomp_arch() == 0 ? EDOM : 0;
			say("[>] Checking for requirements...");
			if (uname(&buf_uts) < 0) {
				say_errno("uname");
			} else {
				say("%s/%s %s %s",
				    buf_uts.sysname,
				    buf_uts.nodename,
				    buf_uts.release,
				    buf_uts.version);
			}
			if (os_release >= KERNEL_VERSION(5,6,0))
				say("[*] Linux kernel is 5.6.0 or newer, good.");
			else
				say("warning: Your Linux kernel is too old "
				    "to support seccomp bpf and seccomp "
				    "user notify. Please update your kernel.");
			opt_t[1] = test_cross_memory_attach(true);
			opt_t[2] = test_proc_mem(true);
			opt_t[3] = test_pidfd(true);
			opt_t[4] = test_seccomp(true);
			r = 0;
			for (i = 0; i < 5; i++) {
				if (opt_t[i] != 0) {
					r = opt_t[i];
					break;
				}
			}
			if (opt_t[0] != 0) {
				say("[!] Failed to detect any valid libseccomp "
				    "architecture.");
				say("[!] This is probably a bug with the "
				    "architecture detection code.");
				say("[!] Please report, thank you.");
			}
			if (opt_t[1] != 0) {
				say("Enable CONFIG_CROSS_MEMORY_ATTACH "
				    "in your kernel configuration "
				    "for cross memory attach to work.");
			}
			if (opt_t[1] != 0 && opt_t[2] != 0) {
				say("warning: Neither cross memory attach "
				    "nor /proc/pid/mem interface is "
				    "available.");
				say("Sandboxing is only supported with bpf "
				    "mode.");
			}
			if (!r)
				say("[>] SydB☮x is supported on this system!");
			exit(r == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
			break;
		case 'F':
			if (!optarg) {
				close_fds[0] = 3;
				close_fds[1] = 0;
			} else if (streq(optarg, ":")) {
				close_fds[0] = 3;
				close_fds[1] = 0;
			} else if (startswith(optarg, ":")) {
				close_fds[0] = 3;
				errno = 0;
				opt = strtoul(optarg, &end, 10);
				if ((errno && errno != EINVAL) ||
				    (unsigned long)opt > SYD_PID_MAX)
				{
					say_errno("Invalid argument for option "
						  "--close-fds: »%s«", optarg);
					usage(stderr, 1);
				}
				close_fds[1] = opt;
			} else {
				errno = 0;
				opt = strtoul(optarg, &end, 10);
				if ((errno && errno != EINVAL) ||
				    (unsigned long)opt > SYD_PID_MAX)
				{
					say_errno("Invalid argument for option "
						  "--close-fds: »%s«", optarg);
					usage(stderr, 1);
				}
				close_fds[0] = opt;
				if (end && end[0] == ':') {
					char *rem = end + 1;
					errno = 0;
					opt = strtoul(rem, &end, 10);
					if ((errno && errno != EINVAL) ||
					    (unsigned long)opt > SYD_PID_MAX)
					{
						say_errno("Invalid argument for option "
							  "--close-fds: »%s«", optarg);
						usage(stderr, 1);
					}
					close_fds[1] = opt;
				} else {
					close_fds[1] = 0;
				}
				break;
			}

			if ((close_fds[0] != 0 && close_fds[0] < 3) ||
			    (close_fds[1] != 0 && close_fds[1] < 3)) {
				say_errno("Invalid argument for option "
					  "--close-fds: »%s«", optarg);
				usage(stderr, 1);
			} else if (close_fds[0] > close_fds[1]) {
				/* XOR swap */
				close_fds[0] ^= close_fds[1];
				close_fds[1] ^= close_fds[0];
				close_fds[0] ^= close_fds[1];
			}
			break;
		case OPT_KEEP_SIGMASK:
			keep_sigmask = true;
			break;
		case 'X':
			reset_fds = true;
			break;
		case '+':
			allow_daemonize = true;
			break;
		case 'O':
			escape_stdout = true;
			break;
		default:
			usage(stderr, 1);
		}
	}

#if 0
	const char *env;
	if ((env = getenv(SYDBOX_CONFIG_ENV)))
		config_parse_spec(env);
#endif

	if (opt_export_mode != SYDBOX_EXPORT_NUL)
		sydbox->export_mode = opt_export_mode;
	if (opt_mem_access < SYDBOX_CONFIG_MEMACCESS_MAX)
		sydbox->config.mem_access = opt_mem_access;

#if SYDBOX_HAVE_DUMP_BUILTIN
	switch (dump_get_fd()) {
	case 0:
	case -1:
		break;
	case -42:
	default:
		sydbox->config.violation_decision = VIOLATION_NOOP;
		magic_set_sandbox_all("dump", NULL);
		break;
	}
#endif

	int my_argc;
	char **my_argv;
	if (optind == argc) {
		config_parse_spec(DATADIR "/" PACKAGE
				  "/default.syd-" STRINGIFY(SYDBOX_API_VERSION));
		set_uid(65534); /* nobody */
		set_gid(65534); /* nobody */
		set_arg0("sydsh");
		set_working_directory(xstrdup("tmp"));
		close_fds[0] = 3;
		close_fds[1] = 0;
		unshare_flags |= (CLONE_NEWPID|\
				  CLONE_NEWNET|\
				  CLONE_NEWNS|\
				  CLONE_NEWUTS|\
				  CLONE_NEWIPC|\
				  CLONE_NEWUSER|\
				  CLONE_NEWTIME|\
				  CLONE_NEWCGROUP);
		my_argc = ELEMENTSOF(sydsh_argv);
		my_argv = sydsh_argv;
		sydbox->program_invocation_name = xstrdup("sydsh");
		child_block_interrupt_signals = true;
	} else {
		my_argv = (char **)(argv + optind);
		my_argc = argc - optind;
		/*
		 * Initial program_invocation_name to be used for P_COMM(current).
		 * Saves one proc_comm() call.
		 */
		sydbox->program_invocation_name = xstrdup(argv[optind]);
	}
	config_done();

	if (opt_magic) {
		r = magic_cast_string(NULL, opt_magic, 0);
		if (MAGIC_ERROR(r))
			die("invalid magic: »%s«: %s",
			    opt_magic, magic_strerror(r));
	}

	/* Late validations for options */
	if (!sydbox->config.restrict_general &&
	    /*
	    !sydbox->config.restrict_ioctl &&
	    !sydbox->config.restrict_mmap &&
	    !sydbox->config.restrict_shm_wr &&
	    */
	    SANDBOX_OFF_ALL()) {
		say("All restrict and sandbox options are off.");
		die("Refusing to run the program »%s«.", my_argv[0]);
	}

	/* Set useful environment variables for children */
	setenv("SYDBOX", SEE_EMILY_PLAY, 1);
	setenv("SYDBOX_VERSION", VERSION, 1);
	setenv("SYDBOX_API_VERSION", STRINGIFY(SYDBOX_API_VERSION), 1);
	setenv("SYDBOX_ACTIVE", THE_PIPER, 1);

	/* STARTUP_CHILD must not be called before the signal handlers get
	   installed below as they are inherited into the spawned process. */
	int status;
	pid_t pid;
	syd_process_t *child;
	if (child_block_interrupt_signals)
		tcgetattr(0, &old_tio);
	if (use_notify()) {
		child = startup_child(my_argc, my_argv);
		pid = child->pid;
		sydbox->execve_pid = pid;
		proc_validate(pid);
		init_process_data(child, NULL, false); /* calls proc_cwd */
		/* Notify the user about the startup. */
		dump(DUMP_STARTUP, pid);
		/* Block signals,
		 * We want to be safe against interrupts. */
		init_signals();
		/* All good.
		 * Tracing starts.
		 * Benediximus.
		 */
		notify_loop();
	} else {
		child = startup_child(my_argc, my_argv);
		pid = child->pid;
	}
	for (;;) {
		errno = 0;
		pid = waitpid(-1, &status, __WALL);
		switch (errno) {
		case 0:
			if (pid == sydbox->execve_pid) {
				if (WIFEXITED(status))
					sydbox->exit_code = WEXITSTATUS(status);
				else if (WIFSIGNALED(status))
					sydbox->exit_code = 128 + WTERMSIG(status);
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
out:
	if (use_notify()) {
		/*
		 * All good, we kill the remaining processes.
		 * First with SIGLOST, then with SIGKILL (in 0.03 seconds)
		 *
		 * Paenitet me.
		 */
		pid_t skip_pid = 0;
		syd_process_t *p = process_lookup(sydbox->execve_pid);
		if (p) {
			skip_pid = p->pid;
			p->flags &= ~(SYD_IN_CLONE|SYD_IN_EXECVE);
			bury_process(p, false);
		}

		kill_all_skip(SIGLOST, skip_pid);
	}
	dump(DUMP_EXIT,
	     sydbox->exit_code/* sydbox->violation_exit_code */,
	     process_count(),
	     process_count_alive());
	dump(DUMP_ALLOC, 0, NULL);
	dump(DUMP_CLOSE);
	//cleanup_for_sydbox();
	if (sydbox->violation) {
		if (sydbox->config.violation_exit_code > 0)
			sydbox->exit_code = sydbox->config.violation_exit_code;
		else if (sydbox->exit_code < 128 &&
			 sydbox->config.violation_exit_code == 0)
			sydbox->exit_code = 128 /* + sydbox->exit_code */;
	}
	//free(sydbox);
	if (child_block_interrupt_signals)
		tcsetattr(0, TCSANOW, &old_tio);
	return sydbox->exit_code;
}
