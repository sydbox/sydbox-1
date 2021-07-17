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
#include <syd/syd.h>
#include "syd-box.h"
#include "syd-ipc.h"
#include "daemon.h"
#include "dump.h"
#include "rc.h"

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
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
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
#include "syd-sys.h"

#include <syd/syd.h>
#ifdef SYDBOX_DEBUG
# define UNW_LOCAL_ONLY
# include <libunwind.h>
#endif

#define switch_execve_flags(f) ((f) & ~(SYD_IN_CLONE|SYD_IN_EXECVE))

sydbox_t *sydbox;
static unsigned os_release;
static uint8_t yama_ptrace_scope;
static struct sigaction child_sa;

static bool plan9;
static bool noexec;
static bool rc, sh;
static int (*command)(int argc, char **argv);
static char *arg0;
#define SYDRC_ARG0 "rc"
static char *sydrc_argv[] = {
	"syd",
	SYDRC_ARG0,
	NULL,
};

static char *sydsh_argv[] = {
	"/bin/bash",
	"--rcfile",
	DATADIR"/"PACKAGE"/sydbox.bashrc",
	"-i",
	"-O","autocd",
	"-O","cdable_vars",
	"-O","cdspell",
	"-O","checkhash",
	"-O","checkjobs",
	"-O","checkwinsize",
	"+O","cmdhist",
	"-O","compat44",
	"-O","direxpand",
	"-O","dirspell",
	"-O","dotglob",
	"-O","execfail",
	"-O","extglob",
	"-O","extquote",
	"-O","globstar",
	"-O","gnu_errfmt",
	"+O","histappend",
	"+O","histreedit",
	"+O","histverify",
	"-O","huponexit",
	"-O","login_shell",
	"+O","mailwarn",
	"-O","nullglob",
	"+O","progcomp",
	"+O","progcomp_alias",
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
static volatile sig_atomic_t debugger_present = -1;
static volatile sig_atomic_t interrupted, interrupted_reload, interrupted_trap;
static volatile sig_atomic_t interruptcode, interruptid, interruptstat;
#else
static volatile int debugger_present = -1;
static volatile int interrupted, interrupted_reload, interrupted_trap;
static volatile int interruptcode, interruptid, interruptstat;
#endif
static sigset_t empty_set, blocked_set, interrupt_set;
static bool debugger_killed;

static pid_t child_pidfd = -1;
static int pidfd_send_signal = -1;

static const char *config_file;

static bool child_block_interrupt_signals;
struct termios old_tio, new_tio;

static bool escape_stdout, reset_fds, allow_daemonize;
static bool make_group_leader, keep_sigmask;
static int parent_death_signal;
static uint32_t close_fds[2];

/* unshare option defaults */
static int setgrpcmd = SYD_SETGROUPS_NONE;
static int unshare_flags;
static long mapuser = -1;
static long mapgroup = -1;
static long mapuser_opt = -1;
static long mapgroup_opt = -1;
// int kill_child_signo = 0; /* 0 means --kill-child was not used */
static const char *procmnt;
static const char *newroot;
static const char *newdir;
static unsigned long propagation = SYD_UNSHARE_PROPAGATION_DEFAULT;
/* static int force_uid, force_gid; */
static uid_t uid;
static gid_t gid;
/* int keepcaps = 0; */
static time_t monotonic;
static time_t boottime;
static int force_monotonic;
static int force_boottime;

static void interrupt(int sig, siginfo_t *siginfo, void *context);
static void interrupt_reload(int sig, siginfo_t *siginfo, void *context);
static void interrupt_rescue(int sig, siginfo_t *siginfo, void *context);
static void interrupt_trap(int sig, siginfo_t *siginfo, void *context);
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
static void usage(FILE *outfp, int exit_code)
{
	fputs("\
syd-"VERSION GITVERSION"\n\
Syd's secc☮mp bⒶsed ⒶpplicⒶtion sⒶndb☮x\n\
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
           <command|rc> {[arg...]}\n", outfp);
       fputs("\
       syd [--export <bpf|pfc:filename>]\n\
           [--arch arch...] [--file pathspec...]\n\
           [--syd magic-command...] {noexec}\n\
       syd --test\n\
       syd book [-hvar] {chapter-number}\n\
       syd draw\n\
       syd dump {syd-args...}\n\
       syd errno [-hv] -|errno-name|errno-number...\n\
       syd format exec [--] {command [arg...]}\n\
       syd hilite [-hv] command args...\n\
       syd hash [-hv]\n\
                [--check {-|file}] [--output {-|file}]\n\
                [--secure] [--sha1dc_partialcoll]\n\
                [--xxh32]\n\
                {-|file...}\n\
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
	exit(exit_code);
}

#ifdef SYDBOX_DEBUG
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
		say("Cannot set no-new-privs flag for seccomp filter (%d %s), "
		    "continuing...",
		    -r, strerror(-r));
#if 0
	if ((r = seccomp_attr_set(sydbox->ctx, SCMP_FLTATR_API_TSKIP, 1)) < 0)
		say("Cannot set tskip attribute for seccomp filter (%d %s), "
		    "continuing...",
		    -r, strerror(-r));
	if ((r = seccomp_attr_set(sydbox->ctx, SCMP_FLTATR_API_SYSRAWRC, 1)) < 0)
		say("Cannot set sysrawrc attribute for seccomp filter (%d %s), "
		    "continuing...",
		    -r, strerror(-r));
	/* Set system call priorities */
	sysinit(sydbox->ctx);
#endif
	if ((r = seccomp_attr_set(sydbox->ctx, SCMP_FLTATR_CTL_TSYNC, 1)) < 0)
		say("Cannot set tsync attribute for seccomp filter (%d %s), "
		    "continuing...",
		    -r, strerror(-r));
	if ((r = seccomp_attr_set(sydbox->ctx, SCMP_FLTATR_CTL_OPTIMIZE, 2)) < 0)
		say("Cannot optimize seccomp filter (%d %s), continuing...",
		    -r, strerror(-r));
#if SYDBOX_HAVE_DUMP_BUILTIN
	if (dump_get_fd() > 0) {
		if ((r = seccomp_attr_set(sydbox->ctx, SCMP_FLTATR_CTL_LOG, 1)) < 0)
			say("Cannot log attribute for seccomp filter (%d %s), "
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
		SYD_GCC_ATTR((unused))char *in_sydbox_test = secure_getenv("IN_SYDBOX_TEST");
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
	if (p->cwd)
		free(p->cwd);
	p->cwd = NULL;
}

static void new_shared_memory_clone_files(struct syd_process *p)
{
	if (!syd_map_free(&p->sockmap)) {
		syd_map_clear_64v(&p->sockmap);
		syd_map_term_64v(&p->sockmap);
	}
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
	int r;
	syd_process_t *process;

	process = syd_calloc(1, sizeof(syd_process_t));
	if (!process)
		return NULL;
	for (size_t i = 0; i <= SYSCALL_ARG_MAX; i++)
		process->repr[i] = NULL;
	new_shared_memory(process);
	if ((r = new_sandbox(&process->box)) < 0) {
		errno = -r;
		say_errno("new_sandbox(%d)", process->pid);
		process->box = NULL;
	}
	if (pid == sydbox->execve_pid)
		process->xxh = sydbox->xxh;
	copy_sandbox(P_BOX(process), box_current(NULL));
	/*
	 * For deny sandbox modes, apply default allow lists.
	 */
	for (size_t i = 0; syd_system_allowlist[i]; i++)
		magic_cast_string(process,
				  syd_system_allowlist[i],
				  0);

	process->pid = pid;
	if (process->pidfd < 0) {
		process->pidfd = syd_pidfd_open(process->pid, 0);
		if (process->pidfd < 0)
			say_errno("pidfd_open(%d)", process->pid);
	}
	process->ppid = SYD_PPID_NONE;
	process->tgid = SYD_TGID_NONE;
	process->abspath = NULL;
	process->execve_pid = SYD_PPID_NONE;

	process->comm[0] = '?';
	process->comm[1] = '\0';
	process->hash[0] = '?';
	process->hash[1] = '\0';

	process_add(process);

	dump(DUMP_THREAD_NEW, pid);
	return process;
}

static syd_process_t *new_thread_or_kill(pid_t pid)
{
	syd_process_t *process;

	process = new_thread(pid);
	if (!process) {
		kill_save_errno(pid, SIGKILL);
		die_errno("malloc() failed, killed %u", pid);
	}

	return process;
}

static syd_process_t *new_process(pid_t pid)
{
	syd_process_t *process;

	process = new_thread_or_kill(pid);
	if (!process)
		return NULL;
	process->tgid = process->pid;

	return process;
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
	p->sysnum = __NR_SCMP_ERROR;
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
	for (size_t i = 0; i <= SYSCALL_ARG_MAX; i++) {
		if (p->repr[i])
			free(p->repr[i]);
		p->repr[i] = NULL;
	}
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
	 */

	if (parent && parent->new_clone_flags) {
		/* Sharing data needs a genuine parent,
		 * check parent_process. */
		current->clone_flags = parent->new_clone_flags;
		genuine = true; /* Assume genuine, allows potential race. */
	} else {
		current->clone_flags = SIGCHLD;
	}

	int r;
	int pfd_cwd = -1;
	char *cwd;

	if (!P_BOX(current))
		new_sandbox(&P_BOX(current));
	if (parent) {
		current->execve_pid = parent->execve_pid;
		current->xxh = parent->xxh;
		syd_strlcpy(current->hash, parent->hash, SYD_SHA1_HEXSZ+1);
		copy_sandbox(P_BOX(current), P_BOX(parent));
	} else {
		current->xxh = sydbox->xxh;
		syd_strlcpy(current->hash, sydbox->hash, SYD_SHA1_HEXSZ+1);
		copy_sandbox(P_BOX(current), box_current(NULL));
	}
	if (P_BOX(current)->magic_lock == LOCK_SET)
		syd_mprotect(P_BOX(current), sizeof(sandbox_t), PROT_READ);

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
		if (P_CWD(parent))
			P_CWD(current) = xstrdup(P_CWD(parent));
		if (P_BOX(parent))
			copy_sandbox(P_BOX(current), P_BOX(parent));
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

	if (new_child) {
		child = new_thread_or_kill(cpid);
		process_add(child);
	}

	/*
	 * Careful here, the process may still be a thread although new
	 * clone flags is missing CLONE_THREAD
	 */
	if (p && p->pid == sydbox->execve_pid) {
		child->ppid = sydbox->sydbox_pid;
		child->tgid = child->pid;
	} else if (p && (p->new_clone_flags & SYD_CLONE_THREAD)) {
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
	} else if (p && p->new_clone_flags & SYD_CLONE_THREAD) {
		copy_sandbox(P_BOX(child), P_BOX(p));
	}

	if (p && p->new_clone_flags) {
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

	if (p->pidfd > 0) {
		/* Under no circumstances we want the process to linger around
		 * after SydB☮x exits. This is why we send a SIGLOST signal here
		 * to the process which is about to be released from the process
		 * tree. This will be repeated for 3 times every 0.01 seconds.
		 * If this does not succeed, process is sent a SIGKILL...
		 */
		kill_one(p, SIGLOST);
		close(p->pidfd);
		p->pidfd = 0; /* assume p is deceased, rip. */
	}

	if ((p->pid > 0 && p->pid == sydbox->execve_pid) ||
	    (p->flags & (SYD_IN_EXECVE|SYD_IN_CLONE))) {
		/*
		 * 1. keep the default sandbox available.
		 * 2. prepare for leader switch for multithreaded execve.
		 * 3. prepare for sandboxing rules transfer from parent.
		 */
		return;
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

SYD_GCC_ATTR((nonnull(1)))
void dump_one_process(syd_process_t *current, bool verbose)
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
	sigemptyset(&interrupt_set);

	sigaddset(&interrupt_set, SIGCHLD);
	sigaddset(&interrupt_set, SIGINT);
	sigaddset(&interrupt_set, SIGUSR1);
	sigaddset(&interrupt_set, SIGUSR2);
	sigaddset(&interrupt_set, SIGTRAP);

	sigaddset(&blocked_set, SIGABRT);
	sigaddset(&blocked_set, SIGALRM);
	sigaddset(&blocked_set, SIGBUS);
	sigaddset(&blocked_set, SIGCHLD);
	sigaddset(&blocked_set, SIGFPE);
	sigaddset(&blocked_set, SIGHUP);
	sigaddset(&blocked_set, SIGINT);
	sigaddset(&blocked_set, SIGILL);
	sigaddset(&blocked_set, SIGIO);
	sigaddset(&blocked_set, SIGIOT);
	sigaddset(&blocked_set, SIGLOST);
	sigaddset(&blocked_set, SIGPIPE);
	sigaddset(&blocked_set, SIGPROF);
	sigaddset(&blocked_set, SIGPWR);
	sigaddset(&blocked_set, SIGSEGV);
	sigaddset(&blocked_set, SIGSTKFLT);
	sigaddset(&blocked_set, SIGTERM);
	sigaddset(&blocked_set, SIGTTOU);
	sigaddset(&blocked_set, SIGTTIN);
	sigaddset(&blocked_set, SIGTRAP);
	sigaddset(&blocked_set, SIGTSTP);
	sigaddset(&blocked_set, SIGUSR1);
	sigaddset(&blocked_set, SIGUSR2);
	sigaddset(&blocked_set, SIGXCPU);
	sigaddset(&blocked_set, SIGXFSZ);
	sigaddset(&blocked_set, SIGWINCH);
}

#if 0
static inline void allow_signals(void)
{
	sigprocmask(SIG_SETMASK, &empty_set, NULL);
}
#endif
static inline void allow_interrupts(void)
{
	sigprocmask(SIG_UNBLOCK, &interrupt_set, NULL);
}
static inline void block_interrupts(int on)
{
	if (on)
		sigprocmask(SIG_BLOCK, &interrupt_set, NULL);
}
static inline void block_signals(int on)
{
	if (on)
		sigprocmask(SIG_BLOCK, &blocked_set, NULL);
}

/* Signals are blocked by default. */
static void init_sigchild(void)
{
	struct sigaction sa;

	/* Ign */
	sa.sa_sigaction = interrupt;
	sa.sa_flags = SA_NOCLDSTOP|SA_RESTART|SA_SIGINFO;
	sigaction(SIGCHLD, &sa, &child_sa);
}

static void init_signals(void)
{
	struct sigaction sa;

	init_signal_sets();

	block_signals(1);

	/* Stop */
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	sigaction(SIGTTOU, &sa, NULL);
	sigaction(SIGTTIN, &sa, NULL);
	sigaction(SIGTSTP, &sa, NULL);
	sigaction(SIGALRM, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);

	/* Interrupt */
	set_sighandler(SIGUSR1, interrupt, NULL);
	set_sighandler(SIGUSR2, interrupt, NULL);

	/* Reload */
	set_sighandler(SIGHUP, interrupt_reload, NULL);

	/* Trap */
	set_sighandler(SIGTRAP, interrupt_rescue, NULL);
	set_sighandler(SIGTSTP, interrupt_rescue, NULL);

	/* Term */
	set_sighandler(SIGALRM, interrupt_rescue, NULL);
	set_sighandler(SIGVTALRM, interrupt_rescue, NULL);
	set_sighandler(SIGBUS,	interrupt_rescue, NULL);
	set_sighandler(SIGINT,	interrupt_rescue, NULL);
	set_sighandler(SIGPIPE, interrupt_rescue, NULL);
	set_sighandler(SIGTERM, interrupt_rescue, NULL);
	set_sighandler(SIGABRT, interrupt_rescue, NULL);
	set_sighandler(SIGFPE, interrupt_rescue, NULL);
	set_sighandler(SIGSEGV, interrupt_rescue, NULL);
	set_sighandler(SIGSTKFLT, interrupt_rescue, NULL);
	set_sighandler(SIGILL, interrupt_rescue, NULL);
	set_sighandler(SIGLOST, interrupt_rescue, NULL);
	set_sighandler(SIGIO, interrupt_rescue, NULL);
	set_sighandler(SIGIOT, interrupt_rescue, NULL);
	set_sighandler(SIGQUIT, interrupt_rescue, NULL);
	set_sighandler(SIGPROF, interrupt_rescue, NULL);
	set_sighandler(SIGPWR, interrupt_rescue, NULL);
	set_sighandler(SIGXCPU,	interrupt_rescue, NULL);
	set_sighandler(SIGXFSZ,	interrupt_rescue, NULL);
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

#if 0
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
#endif

static void interrupt(int sig, siginfo_t *siginfo, void *context)
{
	if (siginfo) {
		interruptid = siginfo->si_pid;
		interruptcode = siginfo->si_code;
		interruptstat = siginfo->si_status;
	}
	interrupted = sig;
}

static void interrupt_reload(int sig, siginfo_t *siginfo, void *context)
{
	/*
	 * Reload configuration file on next interrupt cycle.
	 */
	if (siginfo) {
		interruptid = siginfo->si_pid;
		interruptcode = siginfo->si_code;
		interruptstat = siginfo->si_status;
	}
	interrupted_reload = sig;
}

static void interrupt_trap(int sig, siginfo_t *siginfo, void *context)
{
	if (siginfo) {
		interruptid = siginfo->si_pid;
		interruptcode = siginfo->si_code;
		interruptstat = siginfo->si_status;
	}
	debugger_present = 1;
	interrupted_trap = sig;
}

static int kill_child(void)
{
	if (child_pidfd == -1)
		return 0;
	return syscall(pidfd_send_signal, child_pidfd, SIGKILL, NULL, 0);
}

static void interrupt_rescue(int sig, siginfo_t *siginfo, void *context)
{
	/*
	 * Rescue interrupt handler.
	 * Kills the SydB☮x Execute Process safely using their Pid File Descriptor.
	 */
	kill_child();
	interrupt(sig, siginfo, context);
}

static int sig_child(void)
{
	int status;
	pid_t pid = interruptid;
	syd_process_t *p = process_lookup(pid);

	if (pid == sydbox->execve_pid) {
		const char *op;
		switch (interruptcode) {
		case CLD_EXITED:
			op = "exit";
			break;
		case CLD_KILLED:
			op = "kill";
			break;
		case CLD_DUMPED:
			op = "dump";
			break;
		case CLD_TRAPPED:
			op = "trap";
			break;
		case CLD_STOPPED:
			op = "stop";
			break;
		case CLD_CONTINUED:
			op = "cont";
			break;
		default:
			op = "?";
			break;
		}
		if (interruptcode == CLD_EXITED) {
			sydbox->exit_code = interruptstat <= 128
				? interruptstat
				: WEXITSTATUS(interruptstat);
		} else if (interruptcode == CLD_KILLED ||
			 interruptcode == CLD_DUMPED) {
			sydbox->exit_code = 128 + WTERMSIG(interruptstat);
		}
		if (sydbox->violation || sydbox->exit_code > 7)
			say("SⒶnd☮x Pr☮cess %d»%s« exits with %d, secure:%s%s%s, code:%d»%s«, status:%#lx.",
			    pid,
			    sydbox->program_invocation_name,
			    sydbox->exit_code,
			    sydbox->violation
				? ANSI_DARK_RED
				: ANSI_DARK_GREEN,
			    sydbox->violation
				? "✕"
				: "✓",
			    SYD_WARN,
			    interruptcode, op,
			    (unsigned long)interruptstat);
	}

	if (p && process_is_zombie(p->pid)) {
		bury_process(p, true);
		goto reap;
	}

	for (;;) {
		pid_t cpid;
		cpid = waitpid(pid, &status, __WALL|WNOHANG);
		if (cpid >= 0)
			/* return 0; */
			break; /* see below for reap zombies */
		switch (errno) {
		case EINTR:
			continue;
		case ECHILD:
			break; /* see below for reap zombies */
		default:
			assert_not_reached();
		}
	}

reap:
	reap_zombies();
	return (process_count_alive() == 0) ? ECHILD : 0;
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

static int handle_interrupt_reload(int sig)
{
	syd_process_t *current = process_lookup(sydbox->execve_pid);

	if (!current || !P_BOX(current))
		return 0;
	enum lock_state magic_lock = P_BOX(current)->magic_lock;

	switch (magic_lock) {
	case LOCK_SET:
		warn("SydB☮x Sandbox Lock is set, can not reload configuration.");
		break;
	case LOCK_PENDING:
		warn("SydB☮x Sandbox Lock is pending on next process execution.");
		warn("Can not reload configuration.");
		break;
	case LOCK_UNSET:
		say("Reloading SydB☮x Configuration File »%s«", config_file);
		config_parse_spec(config_file);
		break;
	}

	return 0;
}

static int handle_interrupt_trap(int sig)
{
	bool need_child_kill = false;
	syd_process_t *current = process_lookup(sydbox->execve_pid);

	if (!current || !P_BOX(current))
		return 0;
	enum lock_state magic_lock = P_BOX(current)->magic_lock;

	/*
	 * Check whether magic lock is on and exit if this is the case.
	 * This is to provide integrity for the sandbox.
	 */
	switch (magic_lock) {
	case LOCK_SET:
		need_child_kill = true;
		warn("SydB☮x Sandbox Lock is set.");
		warn("Refusing Trap Request to protect Sandbox Integrity.");
		break;
	case LOCK_PENDING:
		need_child_kill = true;
		warn("SydB☮x Sandbox Lock is pending on next process execution.");
		warn("Refusing Trap Request to protect Sandbox Integrity.");
		break;
	default:
		warn("SydB☮x: Hello TrⒶcer!");
		break;
	}

	int r = 0;
	if (need_child_kill)
		r = kill_child();

	if (debugger_present == -1) {
		debugger_present = 1;
		set_sighandler(SIGTRAP, interrupt_trap, NULL);
		//raise(SIGTRAP);
	}

	return r;
}

void sig_usr(int sig)
{
	bool complete_dump;
	unsigned count;
	syd_process_t *node;

	if (!sydbox)
		return;

	complete_dump= !!(sig == SIGUSR2);

	fprintf(stderr, "\nsydbox: Received SIGUSR%s\n", complete_dump ? "2" : "1");

#ifdef SYDBOX_DEBUG
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

static inline size_t process_count_alive(void)
{
	size_t count = 0;
	syd_process_t *node;

	syd_map_foreach_value(&sydbox->tree, node) {
		if (node->flags & SYD_IN_EXECVE)
			continue;
		/* See the explanation in reap_zombies */
		if (!process_is_zombie(node->pid))
			continue;
		count += 1;
	}

	return count;
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
		if (parent->clone_flags)
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
	if (sydbox)
		return;

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

	assert(current);

	if (P_BOX(current)->magic_lock == LOCK_PENDING) {
		/* magic commands are locked */
		P_BOX(current)->magic_lock = LOCK_SET;
#if 0
#TODO check if this is a good idea.
		syd_mprotect(P_BOX(current), sizeof(sandbox_t),
			     PROT_READ);
#endif
	}

	current->flags |= SYD_IN_EXECVE;
	current->execve_pid = current->pid;

#if 0
	if (!current->abspath) /* nothing left to do */
		return 0;
#endif

	//Intentionally not freeing to handle multithreaded execve. */
	//free(current->abspath);
	//current->abspath = NULL;

	return 0;
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
		allow_interrupts();
		r = seccomp_notify_receive(sydbox->notify_fd,
					   sydbox->request);
		if (interrupted && (intr = handle_interrupt(interrupted)))
			break;
		interrupted = 0;
		block_signals(1);
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
							     true);
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
		if ((current && (current->flags & SYD_IN_EXECVE)) ||
		    startswith(name, "exec")) {
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

		if (current) {
			/*
			 * Check for Tracer (such as Gnu Debugger or Strace)
			 * and the magic SydB☮x sandbox lock to ensure the
			 * integrity of the Sandbox.
			 *
			 * Note: Since we can not distinguish if the EPERM
			 * is due to we being traced or ptrace being unavailable
			 * we only exit the Seccomp Notification loop in case
			 * the Yama Scope is set to 0, ie how ptrace()
			 * traditionally works.
			 */
			if (P_BOX(current)->magic_lock != LOCK_UNSET &&
			    yama_ptrace_scope < 1 &&
			    ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1 &&
			    errno == EPERM) {
				kill_child();
				debugger_killed = true;
				break;
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
				if (((current->flags & SYD_IN_EXECVE) ||
				     startswith(name, "exec")) &&
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
				/* reap zombies after notify respond */
				reap_my_zombies = true;
				if (pid == execve_pid) {
					if (current)
						current->execve_pid = 0;
					current->flags &= ~SYD_IN_EXECVE;
				} else {
					current = process_lookup(pid);
					switch_execve_leader(execve_pid,
							     current);
					current->execve_pid = 0;
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
		allow_interrupts();
		r = seccomp_notify_respond(sydbox->notify_fd,
					   sydbox->response);
		if (interrupted && (intr = handle_interrupt(interrupted)))
			break;
		block_signals(1);
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
				say_errno("seccomp_notify_respond");
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
			/* if (process_count_alive() == 0)
				break; */
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
		allow_interrupts();
		if (interrupted && (r = handle_interrupt(interrupted))) {
			break;
		}
		interrupted = 0;
		if (interrupted_trap) {
			handle_interrupt_trap(interrupted_trap);
			//signal(SIGTRAP, SIG_DFL);
		}
		interrupted_trap = 0;
		block_signals(1);
		if (interrupted_reload)
			handle_interrupt_reload(interrupted_reload);
		interrupted_reload = 0;
	}

	seccomp_notify_free(sydbox->request, sydbox->response);
	close(sydbox->notify_fd);
	sydbox->notify_fd = -1;

	/* Tracing ends, kill any remaining processes,
	 * as otherwise they're going to get »ENOSYS«,
	 * ie. function not implemented, on any call
	 * that SydB☮x is sandboxing such as fork, clone,
	 * vfork et al.
	 */
	kill_all(SIGLOST);

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

	if (!noexec && !command) {
		pathname = strchr(argv[0], '/') ? strdup(argv[0]) : path_lookup(argv[0]);
		if (!pathname)
			die_errno("Path look up for »%s« failed", argv[0]);
		if ((r = syd_path_to_xxh64_hex(pathname, &sydbox->xxh, NULL)) < 0) {
			errno = -r;
			say_errno("Cannot calculate XXH64 checksum of file "
				  "»%s«", pathname);
		} else {
			sayv("Calculated XXH64 checksum of file "
			     "»%s« -> »%#lx«", pathname, sydbox->xxh);
		}

		if ((r = syd_path_to_sha1_hex(pathname, sydbox->hash)) < 0) {
			errno = -r;
			say_errno("Cannot calculate SHA-1DC_PARTIALCOLL checksum of file "
				  "»%s«", pathname);
		} else {
			sayv("Calculated SHA-1DC_PARTIALCOLL checksum of file "
			     "»%s« -> »%s«", pathname, sydbox->hash);
		}
	} else if (noexec) {
		strlcpy(sydbox->hash, "<noexec>", sizeof("<noexec>"));
	} else if (command) {
		strlcpy(sydbox->hash, "<syd-rc>", sizeof("<syd-rc>"));
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

	if (!command && !noexec && !pathname)
		die_errno("Cannot exec »%s«", argv[0]);
	if (pipe2(pfd, O_CLOEXEC|O_DIRECT) < 0)
		die_errno("Cannot pipe");

	if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) < 0)
		say_errno("Cannot set child subreaper attribute, "
			  "continuing...");

	/* Set up the signal handler so that we get exit notification. */
	init_sigchild();
	block_interrupts(1);

	/*
	 * Mark SydB☮x's process id so that the seccomp filtering can
	 * apply the unconditional restrictions about SydB☮x process
	 * receiving any signal other than SIGCHLD.
	 */
	sydbox->sydbox_pid = getpid();
#define SYD_CLONE_FLAGS CLONE_CLEAR_SIGHAND|CLONE_PIDFD
startup_child:
	pid = syd_clone(SYD_CLONE_FLAGS,
			SIGCHLD, &child_pidfd,
			NULL, NULL);
	sydbox->execve_pidfd = child_pidfd;
	if (pid < 0) {
		if (errno == EINVAL) {
			/* Filter out unsupported clone flags and retry... */
			for (uint8_t i = 0; i < SYD_UNSHARE_FLAGS_MAX; i++) {
				if (unshare_flags & syd_unshare_flags[i]) {
					sayv("clone3 failed, retrying without "
					    "flag:%d", syd_unshare_flags[i]);
					unshare_flags &= ~syd_unshare_flags[i];
					goto startup_child;
				}
			}
		}
		die_errno("Cannot clone");
	} else if (pid == 0) {
		/* Reset the SIGCHLD handler. */
		signal(SIGCHLD, SIG_DFL);

		sydbox->execve_pid = getpid();
		sydbox->in_child = true;
		sydbox->seccomp_fd = pfd[1];

		pid = sydbox->execve_pid;
		current->pid = pid;
		strlcpy(current->comm, sydbox->program_invocation_name,
			SYDBOX_PROC_MAX);
#if 0
		proc_validate(pid);
		init_process_data(current, NULL, false); /* calls proc_cwd */
		syd_proc_cmdline(sydbox->pfd, current->prog, LINE_MAX-1);
		current->prog[LINE_MAX-1] = '\0';
#endif

		if (!get_arg0())
			set_arg0(process_comm(NULL, argv[0]));

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
		new_tio.c_cc[VEOF]  = 3; // ^C
		new_tio.c_cc[VINTR] = 4; // ^D
		new_tio.c_lflag &= ~(ICANON | ECHO | ECHOE | ECHOK | ECHONL |
				     ECHOPRT | ECHOKE | ISIG | ICRNL);
#if 0
		new_tio.c_cc[VINTR]    = 25; /* Ctrl-c */
		new_tio.c_cc[VQUIT]    = 3; /* Ctrl-\ */
		new_tio.c_cc[VERASE]   = 0; /* del */
		new_tio.c_cc[VKILL]    = 3; /* @ */
		new_tio.c_cc[VEOF]     = 4/**/; /* Ctrl-d */
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
#endif
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
			_exit(secure_getenv(SYDBOX_NOEXEC_ENV) ?
				atoi(secure_getenv(SYDBOX_NOEXEC_ENV)) :
				0);
		struct syd_exec_opt opt;

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
		opt.proc_mount = procmnt;
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
		opt.supplementary_gids_length = get_groups_length();
		opt.command = command;
		r = syd_execv(pathname, argc, argv, &opt);
		free(pathname);
		if (r < 0) {
			errno = -r;
			say_errno("Error executing »%s«", pathname);
		}
		_exit(127);
	}

	/*
	 * We want to be absolutely safe
	 * against interrupts to the best
	 * we can.
	 * This initialises the signal sets
	 * and blocks all signals.
	 */
	init_signals();

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

	current->flags |= SYD_IN_EXECVE;
	current->pid = pid;
	current->ppid = sydbox->sydbox_pid;
	sydbox->execve_pid = pid;
	process_add(current);

	return current;
}

void cleanup_for_child(void)
{
	static bool cleanup_for_child_done = false;

	if (cleanup_for_child_done)
		return;
	else
		cleanup_for_child_done = true;

	if (!sydbox)
		return;

	if (sydbox->proc_fd)
		closedir(sydbox->proc_fd);
	if (sydbox->program_invocation_name)
		free(sydbox->program_invocation_name);

	if (!syd_map_free(&sydbox->config.proc_pid_auto) &&
	    syd_map_size_64s(&sydbox->config.proc_pid_auto)) {
		syd_map_clear_64s(&sydbox->config.proc_pid_auto);
		syd_map_term_64s(&sydbox->config.proc_pid_auto);
	}
	if (!syd_map_free(&sydbox->tree) &&
	    syd_map_size_64v(&sydbox->tree)) {
		syd_map_clear_64v(&sydbox->tree);
		syd_map_term_64v(&sydbox->tree);
	}

	filter_free();
	reset_sandbox(&sydbox->config.box_static);

	/*
	struct acl_node *acl_node;
	ACLQ_FREE(acl_node, &sydbox->config.exec_kill_if_match, xfree);

	ACLQ_FREE(acl_node, &sydbox->config.filter_exec, xfree);
	ACLQ_FREE(acl_node, &sydbox->config.filter_read, xfree);
	ACLQ_FREE(acl_node, &sydbox->config.filter_write, xfree);
	ACLQ_FREE(acl_node, &sydbox->config.filter_network, free_sockmatch);
	*/
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
	int arg, opt, r, opt_t[5];
	size_t i;
	char *c, *opt_magic = NULL;
	struct utsname buf_uts;

	/* Run IPC Tool if requested. */
	if (argc >= 2 && streq(argv[1], "ipc"))
		return syd_ipc_main(--argc, ++argv);

	int my_argc = argc;
	char **my_argv = argv;

	/* Early initialisations */
	arg0 = argv[0];
	dump_set_fd(-3);
	init_early();

	/*
	 * Resolve pidfd_send_signal system call number.
	 * We use it in rescue interrupt handler so as
	 * not to let the children run unsandboxed.
	 */
	pidfd_send_signal = seccomp_syscall_resolve_name("pidfd_send_signal");
	if (pidfd_send_signal == __NR_SCMP_ERROR ||
	    pidfd_send_signal < 0) {
		if (!errno)
			errno = ENOSYS;
		int save_errno = errno;
		say("pidfd_send_signal system call not available.");
		warn("Can not reliably send signals, exiting...");
		errno = save_errno;
		die_errno("pidfd_send_signal");
	}

	/*
	 * Act as a multicall binary for
	 * the Syd family of commands.
	 */
	if (argc > 1) {
		char *bin;
		if (asprintf(&bin, LIBEXECDIR"/bin/syd-%s", argv[1]) < 0) {
			say_errno("asprintf");
			return ENOMEM;
		}
		if (access(bin, X_OK) == 0) {
			execv(bin, argv + 1);
			free(bin);
			exit(ECANCELED);
		}
		free(bin);
	}

	uid_t real_euid = geteuid();
	gid_t real_egid = getegid();

	/*
	 * Be paranoid about file mode creation mask.
	 */
	umask(077);

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

	/* Zero-initialise option states */
	enum sydbox_export_mode opt_export_mode = SYDBOX_EXPORT_NUL;
	uint8_t opt_mem_access = SYDBOX_CONFIG_MEMACCESS_MAX;

	if ((r = syd_proc_yama_ptrace_scope(&yama_ptrace_scope)) < 0) {
		errno = -r;
		say_errno("syd_proc_yama_ptrace_scope");
		warn("Assuming YAMA Ptrace Scope is 3.");
		yama_ptrace_scope = 3;
	}

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

	const char *shoebox = secure_getenv("SHOEBOX");
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
				  "hva:bld:e:ny:f:muiNpUCTFrcS:G:R:w:+:&:1:2:A:K:E:V:Ot",
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
			config_file = optarg;
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
		case OPT_UID:
			if ((r = safe_atoi(optarg, &arg) < 0)) {
				errno = -r;
				say_errno("Invalid argument for --setuid option: "
					  "»%s«", optarg);
				usage(stderr, 1);
			}
			uid = (uid_t)arg;
			//force_uid = 1;
			break;
		case OPT_ADD_GID:
			if ((r = safe_atoi(optarg, &arg) < 0)) {
				errno = -r;
				say_errno("Invalid argument for --add-gid option: "
					  "»%s«", optarg);
				usage(stderr, 1);
			}
			set_groups(arg);
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
#if 0
		case OPT_UID:
			uid = atoi(optarg);
			set_uid(uid);
			break;
#endif
		case 'G':
		case OPT_GID:
			gid = atoi(optarg);
			set_gid(gid);
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

	if ((force_monotonic || force_boottime) && !(unshare_flags & CLONE_NEWTIME))
		die("options --monotonic and --boottime require "
		    "unsharing of a time namespace (-t)");

#if 0
	const char *env;
	if ((env = secure_getenv(SYDBOX_CONFIG_ENV)))
		config_parse_spec(env);
#endif
	/*
	 * Sanitise the environment for security.
	 */
	const char *user_dbus = secure_getenv("DBUS_SESSION_BUS_ADDRESS");
	const char *user_home = secure_getenv("HOME");
	const char *user_path = secure_getenv("PATH");
	const char *user_shell = secure_getenv("SHELL");
	const char *user_term = secure_getenv("TERM");
	clearenv();
	setenv("ID", SYD_RELEASE_KEY, 1);
	if (user_dbus)
		setenv("DBUS_SESSION_BUS_ADDRESS", user_dbus, 1);
	if (user_home)
		setenv("HOME", user_home, 1);
	setenv("BROWSER", "firefox", 1);
	if (user_path)
		setenv("PATH", user_path, 1);
	if (user_shell)
		setenv("SHELL", user_shell, 1);
	if (user_term)
		setenv("TERM", user_term, 1);
	setenv("TZ", "UTC", 1);
	unsetenv("XAUTHORITY");
	unsetenv("WINDOWID");

	sandbox_t *box = box_current(NULL);
	char box_repr[5] = {0};
	box_repr[0] = sandbox_mode_toc(box->mode.sandbox_read);
	box_repr[1] = sandbox_mode_toc(box->mode.sandbox_write);
	box_repr[2] = sandbox_mode_toc(box->mode.sandbox_exec);
	box_repr[3] = sandbox_mode_toc(box->mode.sandbox_network);
	box_repr[4] = '\0';
	setenv("SYDBOX", box_repr, 1);

	/*
	 * For deny sandbox modes, apply default allow lists.
	 */
	for (i = 0; syd_system_allowlist[i]; i++)
		magic_cast_string(NULL,
				  syd_system_allowlist[i],
				  0);

	if (opt_export_mode != SYDBOX_EXPORT_NUL)
		sydbox->export_mode = opt_export_mode;
	if (opt_mem_access < SYDBOX_CONFIG_MEMACCESS_MAX)
		sydbox->config.mem_access = opt_mem_access;

#if SYDBOX_HAVE_DUMP_BUILTIN
	switch (dump_get_fd()) {
	case 0:
	case -1:
	case -3:
		break;
	case -42:
	default:
		sydbox->config.violation_decision = VIOLATION_NOOP;
		magic_set_sandbox_all("dump", NULL);
		break;
	}
#endif

	my_argc -= optind;
	my_argv += optind;
	argc = my_argc;
	argv = my_argv;
	//say("argc:%d arg0:%s optind:%d", argc, arg0, optind);

	/*
	 * Act as a multicall binary for
	 * the Syd family of commands.
	 */
	plan9 = false;
	sh = false;
	rc = false;
	if (argc == 0) {
		sh = true;
	} else if (argc >= 1) {
		if (streq(argv[0], "rc")) {
			plan9 = true;
			rc = true;
		}
		else if (streq(argv[0], SYDBOX_NOEXEC_NAME))
			noexec = true;
	}

	if (plan9 || rc) {
		close_fds[0] = 4;
		close_fds[1] = 0;

		setenv("SHELL", "syd-rc", 1);
		set_arg0("☮syd-rc");
		sydbox->program_invocation_name = xstrdup("☮syd-rc");
		//FIXME does not work!
		//command = syd_rc_main;
		my_argv[0] = arg0;
		my_argc = ELEMENTSOF(sydrc_argv);
		my_argv = sydrc_argv;
	}

	if (rc || sh) {
		config_parse_spec(DATADIR "/" PACKAGE
				  "/default.syd-" STRINGIFY(SYDBOX_API_VERSION));
		setenv("SHELL", "syd", 1);
		mapuser = 0;
		mapgroup = 0;
		set_uid(0);
		set_gid(0);
		if (sh)
			set_arg0("☮syd-sh");
		else if (rc)
			set_arg0("☮syd-rc");
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
		if (sh) {
			my_argc = ELEMENTSOF(sydsh_argv);
			my_argv = sydsh_argv;
		} else if (rc) {
			my_argc = ELEMENTSOF(sydrc_argv);
			my_argv = sydrc_argv;
		} else {
			assert_not_reached();
		}
		sydbox->program_invocation_name = xstrdup(get_arg0());
		child_block_interrupt_signals = true;
	} else {
		/*
		 * Initial program_invocation_name to be used for P_COMM(current).
		 * Saves one proc_comm() call.
		 */
		if (asprintf(&sydbox->program_invocation_name, "☮%s",
			     argv[0]) < 0) {
			;
		}
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
	setenv("SYDBOX_PLAY", SEE_EMILY_PLAY, 1);
	setenv("SYDBOX_VERSION", VERSION, 1);
	setenv("SYDBOX_API_VERSION", STRINGIFY(SYDBOX_API_VERSION), 1);
	setenv("SYDBOX_ACTIVE", THE_PIPER, 1);

	/* STARTUP_CHILD must not be called before the signal handlers get
	   installed below as they are inherited into the spawned process. */
	int status;
	pid_t pid;
	syd_process_t *child;

	if (unshare_flags != 0 &&
	    (r = syd_unshare(unshare_flags)) < 0 &&
	    r != -ECANCELED) {
		errno = -r;
		die_errno("unshare");
	}

	if (force_boottime)
		syd_settime(boottime, CLOCK_BOOTTIME);

	if (force_monotonic)
		syd_settime(monotonic, CLOCK_MONOTONIC);

	int death_sig;
	switch (parent_death_signal) {
	case 0: /* Default is SIGKILL. */
		death_sig = SIGKILL;
		break;
	default:
		death_sig = parent_death_signal;
		break;
	}

	if ((r = syd_set_death_sig(death_sig)) < 0) {
		errno = -r;
		say_errno("Error setting parent death signal to »%d«", death_sig);
		/* Continue */
	}

	if ((uid_t)mapuser != (uid_t)-1 &&
	    syd_map_id(SYD_PATH_PROC_UIDMAP,
		       mapuser,
		       real_euid) < 0) {
		int save_errno = errno;
		say_errno("Error mapping current user »%d« to root user.", real_euid);
		return -save_errno;
	}

	/* Since Linux 3.19 unprivileged writing of /proc/self/gid_map
	 * has been disabled unless /proc/self/setgroups is written
	 * first to permanently disable the ability to call setgroups
	 * in that user namespace. */
	if ((gid_t)mapgroup != (gid_t)-1) {
		if (setgrpcmd == SYD_SETGROUPS_ALLOW) {
			errno = EINVAL;
			say_errno("options setgroups=allow and "
				      "map-group are mutually exclusive.");
			return -EINVAL;
		}
		syd_setgroups_control(SYD_SETGROUPS_DENY);
		syd_map_id(SYD_PATH_PROC_GIDMAP, mapgroup, real_egid);
	}

	if (setgrpcmd != SYD_SETGROUPS_NONE &&
	    (r = syd_setgroups_control(setgrpcmd)) < 0) {
		errno = -r;
		switch (setgrpcmd) {
		case SYD_SETGROUPS_ALLOW:
			say_errno("Error allowing the »setgroups(2)« system "
				      "call in the user namespace.");
			break;
		case SYD_SETGROUPS_DENY:
			say_errno("Error denying the »setgroups(2)« system "
				      "call in the user namespace.");
			break;
		default:
			abort();
		}
		/* fall through */
	}

	if ((unshare_flags & CLONE_NEWNS) && propagation &&
	    (r = syd_set_propagation(propagation)) < 0) {
		errno = -r;
		say_errno("Error recursively setting the mount propagation "
			      "flag in the new mount namespace.");
		/* fall through */
	}

	if (!use_notify()) {
		/*
		 * Seccomp BPF mode:
		 *
		 * Apply BPF filters and wait.
		 */
		child = startup_child(my_argc, my_argv);
		for (;;) {
			errno = 0;
			pid = waitpid(-1, &status, __WALL);
			switch (errno) {
			case 0:
				if (pid == sydbox->execve_pid) {
					if (WIFEXITED(status)) {
						sydbox->exit_code = status <= 128
							? status
							: WEXITSTATUS(status);
					} else if (WIFSIGNALED(status)) {
						sydbox->exit_code = 128 + WTERMSIG(status);
					}
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
		goto out;
	}

	tcgetattr(0, &old_tio);
	/* Seccomp User Notify Mode */
	child = startup_child(my_argc, my_argv);
	pid = child->pid;
	sydbox->execve_pid = pid;
	proc_validate(pid);
	init_process_data(child, NULL, false); /* calls proc_cwd */
	/* Notify the user about the startup. */
	dump(DUMP_STARTUP, pid, yama_ptrace_scope, unshare_flags);
	/* All good.
	 * Tracing starts.
	 * Benediximus.
	 */
	notify_loop();
	if (debugger_killed) {
		say("G☮☮dbye TrⒶcer!");
		exit(128);
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
	tcsetattr(0, TCSANOW, &old_tio);
	return sydbox->exit_code;
}
