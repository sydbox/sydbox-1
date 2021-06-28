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
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <getopt.h>
#include <time.h>
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

#define switch_execve_flags(f) ((f) & ~(SYD_IN_CLONE|SYD_IN_EXECVE))

sydbox_t *sydbox;
static unsigned os_release;
static struct sigaction child_sa;

static const char *sydsh_argv[] = {
	"/usr/bin/env",
	"bash",
	"--rcfile",
	DATADIR"/"PACKAGE"/sydbox.bashrc",
	"-i",
	NULL
};

static void
set_sighandler(int signo, void (*sighandler)(int), struct sigaction *oldact)
{
	const struct sigaction sa = { .sa_handler = sighandler };
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
static volatile sig_atomic_t interrupted;
#else
static volatile int interrupted;
#endif
static sigset_t empty_set, blocked_set;

static void dump_one_process(syd_process_t *current, bool verbose);
static void sig_usr(int sig);

static void interrupt(int sig);
static void reap_zombies(void);
static inline bool process_is_alive(pid_t pid);
static inline bool process_is_zombie(pid_t pid);
static inline size_t process_count_alive(void);
static inline pid_t process_find_exec(pid_t pid);
static inline syd_process_t *process_init(pid_t pid, syd_process_t *parent,
					  bool genuine);

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

int path_to_hex(const char *pathname)
{
	int fd = open(pathname, O_RDONLY|O_CLOEXEC|O_LARGEFILE);
	if (fd == -1) {
		int save_errno = errno;
		sprintf(sydbox->hash, "<open:%d>", save_errno);
		return -save_errno;
	}

#define PATH_TO_HEX_BUFSIZ (1024*1024)
	char buf[PATH_TO_HEX_BUFSIZ];
	ssize_t nread;
	unsigned char hash[SYD_SHA1_RAWSZ];
	int r = 0;
	syd_hash_sha1_init();
	for (;;) {
		errno = 0;
		nread = read(fd, buf + r, PATH_TO_HEX_BUFSIZ - r);
		if (!nread) {
			r = 0;
			break;
		}
		if (nread > 0)
			r += nread;
		if (errno == EINTR ||
		    (nread > 0 && (size_t)r < PATH_TO_HEX_BUFSIZ)) {
			continue;
		} else if (nread < 0 && r == 0) { /* not partial read */
			int save_errno = errno;
			sprintf(sydbox->hash, "<read:%d>", save_errno);
			r = -save_errno;
			break;
		}
		syd_hash_sha1_update(buf, r);
		r = 0;
	}
	close(fd);
	if (r == 0) {
		syd_hash_sha1_final(hash);
		strlcpy(sydbox->hash, hash_to_hex(hash), SYD_SHA1_HEXSZ);
	}
	return r;
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
	if (sydbox->dump_fd > 0) {
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

	process_add(thread);

#if ENABLE_PSYSCALL
	int r;
	if ((r = pink_regset_alloc(&thread->regset)) < 0) {
		errno = -r;
		say_errno("pink_regset_alloc");
		thread->regset = NULL;
	}
#endif

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
	if (p->abspath) {
		free(p->abspath);
		p->abspath = NULL;
	}
}

static void init_shareable_data(syd_process_t *current, syd_process_t *parent,
				bool genuine)
{
	bool share_thread, share_fs, share_files;

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

	share_thread = share_fs = share_files = false;
	if (genuine) { /* Sharing data needs a genuine parent, check
			  parent_process. */
		if (parent->new_clone_flags & SYD_CLONE_THREAD)
			share_thread = true;
		if (parent->new_clone_flags & SYD_CLONE_FS)
			share_fs = true;
		if (parent->new_clone_flags & SYD_CLONE_FILES)
			share_files = true;
		current->clone_flags = parent->new_clone_flags;
	} else {
		current->clone_flags = SIGCHLD;
	}

	int r;
	char *cwd;
	if (current->pid == sydbox->execve_pid) {
		/* oh, I know this person, we're in the same directory. */
		P_CWD(current) = xgetcwd();
		copy_sandbox(P_BOX(current), box_current(NULL));
		return;
	} else if (!parent) {
proc_getcwd:
		if ((r = syd_proc_cwd(sydbox->pfd_cwd, sydbox->config.use_toolong_hack,
				  &cwd)) < 0) {
			errno = -r;
			/* XXX: Debug */
			sig_usr(SIGUSR2);
			say_errno("proc_cwd");
			P_CWD(current) = strdup("/");
		} else {
			P_CWD(current) = cwd;
		}
		copy_sandbox(P_BOX(current), box_current(NULL));
		return;
	}

	if (share_thread || P_BOX(parent)->magic_lock == LOCK_SET) {
		current->shm.clone_thread = parent->shm.clone_thread;
		P_CLONE_THREAD_RETAIN(current);
	} else {
		new_shared_memory_clone_thread(current);
		copy_sandbox(P_BOX(current), box_current(parent));
	}
	if (share_thread)
		P_EXECVE_PID(current) = P_EXECVE_PID(parent);

	if (share_files) {
		current->shm.clone_files = parent->shm.clone_files;
		P_CLONE_FILES_RETAIN(current);
	} else {
		new_shared_memory_clone_files(current);
	}

	if (share_fs) {
		current->shm.clone_fs = parent->shm.clone_fs;
		P_CLONE_FS_RETAIN(current);
	} else {
		new_shared_memory_clone_fs(current);
		if (!genuine) /* Child with a non-genuine parent has a
				 completely separate set of shared memory
				 pointers, as the last step we want to
				 read cwd from /proc */
			goto proc_getcwd;
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
	if (p->pid == sydbox->execve_pid) {
		child->ppid = sydbox->sydbox_pid;
		child->tgid = child->pid;
	} else if (genuine && (p->new_clone_flags & SYD_CLONE_THREAD)) {
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
	if (new_child)
		init_process_data(child, p, genuine);

	if (genuine) {
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
	dump(DUMP_THREAD_FREE, pid);

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

#if ENABLE_PSYSCALL
	if (p->regset) {
		pink_regset_free(p->regset);
		p->regset = NULL;
	}
#endif

	if (sydbox->config.allowlist_per_process_directories &&
	    !sc_map_freed(&sydbox->config.proc_pid_auto))
		procdrop(&sydbox->config.proc_pid_auto, pid);


	if (p->pid == sydbox->execve_pid ||
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
	}

	/* Release shared memory */
	P_CLONE_THREAD_RELEASE(p);
	P_CLONE_FS_RELEASE(p);
	P_CLONE_FILES_RELEASE(p);
	free(p); /* good bye, good bye, good bye. */
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
	bool clone_thread = false;
	bool clone_fs = false;

	dump(DUMP_EXEC_MT, execve_thread->pid, leader_pid,
	     execve_thread->abspath);

	syd_process_t *leader = process_lookup(leader_pid);
	if (!leader)
		goto out;
	process_remove(leader);

	if (leader->shm.clone_thread && execve_thread->shm.clone_thread &&
	    execve_thread->shm.clone_thread != leader->shm.clone_thread)
		clone_thread = true;
	else if (leader->shm.clone_fs && execve_thread->shm.clone_fs &&
		 execve_thread->shm.clone_fs != leader->shm.clone_fs)
		clone_fs = true;

	if (clone_fs && !P_CWD(execve_thread) && P_CWD(leader))
		P_CWD(execve_thread) = strdup(P_CWD(leader));
	else
		update_cwd = true;

	tweak_execve_thread(leader, execve_thread);
	leader->abspath = NULL;
	leader->flags &= ~SYD_IN_EXECVE;
	bury_process(leader, false);

out:
	if (!clone_thread)
		new_shared_memory_clone_thread(execve_thread);
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
	sc_map_foreach_value(&sydbox->tree, node) {
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
	 * If both are absent, use SydBox's execve pid which
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
		CG = ANSI_GREEN;
		CB = ANSI_DARK_MAGENTA;
		CI = ANSI_CYAN;
		CN = ANSI_YELLOW;
		CE = ANSI_NORMAL;
	} else {
		CG = CB = CI = CN = CE = "";
	}

	fprintf(stderr, "%s-- Information on Process ID: %u%s\n", CG, pid, CE);
	fprintf(stderr, "\t%sName: `%s'%s\n", CN, current->comm, CE);
	if (current->pid == sydbox->execve_pid)
		fprintf(stderr, "\t%sParent ID: SYDBOX%s\n", CN, CE);
	else if (current->ppid > 0)
		fprintf(stderr, "\t%sParent ID: %u%s\n", CN, ppid > 0 ? ppid : 0, CE);
	else
		fprintf(stderr, "\t%sParent ID: ? (Orphan)%s\n", CN, CE);
	fprintf(stderr, "\t%sThread Group ID: %u%s\n", CN, tgid > 0 ? tgid : 0, CE);
	if (current->shm.clone_fs)
		fprintf(stderr, "\t%sCwd: `%s'%s\n", CN, P_CWD(current), CE);
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

static void init_signal_sets(void)
{
	sigemptyset(&empty_set);
	sigemptyset(&blocked_set);

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
	init_signal_sets(); block_signals();

	set_sighandler(SIGCHLD, interrupt, &child_sa);

	/* Stop */
	set_sighandler(SIGTTOU, SIG_IGN,   NULL);
	set_sighandler(SIGTTIN, SIG_IGN,   NULL);
	set_sighandler(SIGTSTP, SIG_IGN,   NULL);

	/* Term */
	set_sighandler(SIGHUP,  interrupt, NULL);
	set_sighandler(SIGINT,  interrupt, NULL);
	set_sighandler(SIGQUIT, interrupt, NULL);
	set_sighandler(SIGPIPE, interrupt, NULL);
	set_sighandler(SIGTERM, interrupt, NULL);
	set_sighandler(SIGUSR1, interrupt, NULL);
	set_sighandler(SIGUSR2, interrupt, NULL);
}

static void reset_signals(void)
{
	set_sighandler(SIGCHLD, SIG_DFL, NULL);

	/* Stop */
	set_sighandler(SIGTTOU, SIG_DFL, NULL);
	set_sighandler(SIGTTIN, SIG_DFL, NULL);
	set_sighandler(SIGTSTP, SIG_DFL, NULL);

	/* Term */
	set_sighandler(SIGHUP,  SIG_DFL, NULL);
	set_sighandler(SIGINT,  SIG_DFL, NULL);
	set_sighandler(SIGQUIT, SIG_DFL, NULL);
	set_sighandler(SIGPIPE, SIG_DFL, NULL);
	set_sighandler(SIGTERM, SIG_DFL, NULL);
	set_sighandler(SIGUSR1, SIG_DFL, NULL);
	set_sighandler(SIGUSR2, SIG_DFL, NULL);
}

static void interrupt(int sig)
{
	interrupted = sig;
}

static int sig_child(void)
{
	int status;
	pid_t pid;

	if (process_is_zombie(sydbox->execve_pid)) {
		bury_process(process_lookup(sydbox->execve_pid), true);
		return ECHILD;
	}
	reap_zombies();
	if (process_count_alive() > 0)
		return 0;

	for (;;) {
		pid = waitpid(-1, &status, __WALL|WNOHANG);
		if (pid >= 0)
			return 0;
		switch (errno) {
		case EINTR:
			continue;
		case ECHILD:
			return 128;
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
	sc_map_foreach_value(&sydbox->tree, node) {
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
	sc_map_foreach_value(&sydbox->tree, node) {
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

	sc_map_foreach_value(&sydbox->tree, node) {
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

static inline bool process_is_alive(pid_t pid)
{
	return process_send_signal(pid, 0) != -1;
}

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
		return true;
	}
}

static inline pid_t process_find_exec(pid_t exec_pid)
{
	syd_process_t *node;

	sc_map_foreach_value(&sydbox->tree, node) {
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
	syd_process_t *current;

	if (parent) {
		current = clone_process(parent, pid, genuine);
		if (genuine)
			parent->clone_flags &= ~SYD_IN_CLONE;
	} else {
		parent = process_lookup(sydbox->execve_pid);
		BUG_ON(parent);
		unsigned int save_new_clone_flags = parent->new_clone_flags;
		parent->new_clone_flags = 0;
		current = clone_process(parent, pid, genuine);
		parent->new_clone_flags = save_new_clone_flags;
		sysx_chdir(current);
	}

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
	sydbox->hash[0] = '\0';
	if (!sc_map_init_64v(&sydbox->tree,
			     SYDBOX_PROCMAP_CAP,
			     SYDBOX_MAP_LOAD_FAC)) {
		errno = ENOMEM;
		die_errno("failed to allocate hashmap for process tree");
	}
	config_init();
	filter_init();
	sc_map_init_64v(&sydbox->tree, 0, 0);
	//syd_abort_func(kill_all);
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

	/* kill_if_match */
	r = 0;
	if (acl_match_path(ACL_ACTION_NONE, &sydbox->config.exec_kill_if_match,
			   current->abspath, &match)) {
		say("kill_if_match pattern=`%s' matches execve path=`%s'",
		    match, current->abspath);
		say("killing process");
		process_kill(current->pid, SIGKILL);
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

static int notify_loop()
{
	int r, intr;
	pid_t pid;
	syd_process_t *current;

	if ((r = seccomp_notify_alloc(&sydbox->request,
				      &sydbox->response)) < 0) {
		errno = -r;
		die_errno("seccomp_notify_alloc");
	}

	for (;;) {
		/* Let the user-space tracing begin. */
		bool jump = false, reap_my_zombies = false;
		char *name = NULL;
		syd_process_t *parent;

notify_receive:
		memset(sydbox->request, 0, sizeof(struct seccomp_notif));
		allow_signals();
		r = seccomp_notify_receive(sydbox->notify_fd,
					   sydbox->request);
		if (interrupted && (intr = handle_interrupt(interrupted)))
			break;
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

		//if (sydbox->request->id == 0 && sydbox->request->pid == 0)
		//	goto out;
		memset(sydbox->response, 0, sizeof(struct seccomp_notif_resp));
		sydbox->response->id = sydbox->request->id;
		sydbox->response->val = 0;
		sydbox_syscall_deny();

		name = seccomp_syscall_resolve_num_arch(sydbox->request->data.arch,
							sydbox->request->data.nr);
		pid = sydbox->request->pid;
		current = process_lookup(pid);

		/*
		 * Handle critical paths early and fast.
		 * Search early for ex{it,ecve} before getting a process entry.
		 */
		if (name && startswith(name, "exit")) {
			if (current)
				bury_process(current, true);
			/* reap zombies after notify respond */
			reap_my_zombies = true;
			sydbox_syscall_allow();
			goto notify_respond;
		} else if (name && (streq(name, "execve") || streq(name, "execveat"))) {
			/* memfd is no longer valid, reopen next turn,
			 * reading /proc/pid/mem on a process stopped
			 * for execve returns EPERM! */
			if (sydbox->execve_wait) { /* allow the initial exec */
				sydbox->execve_wait = false;
				sydbox_syscall_allow();
				goto notify_respond;
			}
			pid_t execve_pid = 0;
			pid_t leader_pid = process_find_exec(pid);
			if (!current) {
				parent = process_lookup(leader_pid);
				current = process_init(pid, parent, true);
			}
			execve_pid = P_EXECVE_PID(current);
			if (execve_pid == 0 && pid != leader_pid) {
				execve_pid = leader_pid;
				current->sysnum = sydbox->request->data.nr;
				current->sysname = name;
			}

			if (execve_pid) {
				if (pid != execve_pid) {
					current = process_lookup(pid);
					switch_execve_leader(execve_pid,
							     current);
					sydbox_syscall_allow();
					goto notify_respond;
				}
				P_EXECVE_PID(current) = 0;
			}
			event_exec(current);
		}

		if (!current) {
			bool genuine;
			parent = parent_process(pid, &genuine);
			current = process_init(pid, parent, genuine);
		}
		/*
		 * Perform PID validation,
		 * if it succeeds proceed with sandboxing,
		 * if it fails deny the system call with ESRCH.
		 */
		proc_validate_or_deny(current, notify_respond);
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

		if (!name) {
			;
		} else if (streq(name, "clone")) {
			sydbox_syscall_allow();
			event_clone(current, 'c', current->args[SYD_CLONE_ARG_FLAGS]);
		} else if (streq(name, "clone2")) {
			sydbox_syscall_allow();
			event_clone(current, 'c', current->args[SYD_CLONE_ARG_FLAGS]);
		} else if (streq(name, "clone3")) {
			sydbox_syscall_allow();
			event_clone(current, 'c', current->args[SYD_CLONE_ARG_FLAGS]);
		} else if (streq(name, "fork")) {
			sydbox_syscall_allow();
			event_clone(current, 'f', 0);
		} else if (streq(name, "vfork")) {
			sydbox_syscall_allow();
			event_clone(current, 'v', 0);
		} else if (streq(name, "chdir") || !strcmp(name, "fchdir")) {
			sydbox_syscall_allow();
			current->flags &= ~(SYD_IN_CLONE|SYD_IN_EXECVE);
			current->update_cwd = true;
		} else { /* all system calls including exec end up here. */
			sydbox_syscall_allow();
			current->flags &= ~SYD_IN_CLONE;
			if (!startswith(name, "execve"))
				current->flags &= ~SYD_IN_EXECVE;
			event_syscall(current);
		}

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
		if (jump)
			break;
		/* We handled quick cases, we are permitted to interrupt now. */
		r =  0;
		allow_signals();
		if (interrupted && (r = handle_interrupt(interrupted)))
			break;
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

static pid_t startup_child(char **argv)
{
	int r, pfd[2];
	char *pathname = NULL;
	pid_t pid = 0;

	bool noexec = streq(argv[0], SYDBOX_NOEXEC_NAME);
	if (!noexec) {
		pathname = path_lookup(argv[0]);
	} else {
		strlcpy(sydbox->hash, "<noexec>", sizeof("<noexec>"));
	}

	/* Initialize Secure Computing */
	seccomp_setup();

	/* All ready, initialise dump */
	dump(DUMP_INIT, argv[0], pathname, get_startas(), arch_argv);
	/* We may free the elements of arch_argv now,
	 * they are no longer required. */
	for (size_t i = 0; arch_argv[i] != NULL; i++)
		free(arch_argv[i]);
	arch_argv[0] = NULL;

	if (!noexec && !pathname)
		die_errno("can't exec `%s'", argv[0]);
	if (pipe2(pfd, O_CLOEXEC|O_DIRECT) < 0)
		die_errno("can't pipe");

	/*
	 * Mark SydBox's process id so that the seccomp filtering can
	 * apply the unconditional restrictions about SydBox process
	 * receiving any signal other than SIGCHLD.
	 */
	sydbox->sydbox_pid = getpid();
	pid = fork();
	if (pid < 0)
		die_errno("can't fork");
	else if (pid == 0) {
		sydbox->execve_pid = getpid();
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
		if (change_group() < 0) {
			say_errno("change_group");
			say("continuing...");
		}
		if (change_user() < 0) {
			say_errno("change_user");
			say("continuing...");
		}
		if (change_background() < 0)
			die_errno("change_background");
		cleanup_for_child();

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
		if (get_startas())
			argv[0] = (char *)get_startas();
		execv(pathname, argv);
		fprintf(stderr, PACKAGE": execv path:\"%s\" failed (errno:%d %s)\n",
			pathname, errno, strerror(errno));
		free(pathname); /* not NULL because noexec is handled above. */
		_exit(EXIT_FAILURE);
	}
	seccomp_release(sydbox->ctx);

	/* write end of the pipe is not used. */
	close(pfd[1]);

	if (sydbox->export_path)
		free(sydbox->export_path);
	if (pathname)
		free(pathname);

	sydbox->execve_pid = pid;
	sydbox->execve_wait = true;

	sydbox->seccomp_fd = pfd[0];
	if (!use_notify())
		return pid;

	int fd;
	if ((r = parent_read_int(&fd)) < 0) {
		errno = -r;
		say_errno("failed to load seccomp filters");
		say("Invalid sandbox options given.");
		exit(-r);
	}

	int pidfd;
	if ((pidfd = syd_pidfd_open(pid, 0)) < 0)
		die_errno("failed to open pidfd for pid:%d", pid);
	if ((fd = syd_pidfd_getfd(pidfd, fd, 0)) < 0)
		 die_errno("failed to obtain seccomp user fd");
	sydbox->notify_fd = fd;

	close(pfd[0]);
	sydbox->seccomp_fd = -1;

	sydbox->notify_fd = fd;

	return pid;
}

void cleanup_for_child(void)
{
	static bool cleanup_for_child_done = false;

	if (cleanup_for_child_done)
		return;
	else
		cleanup_for_child_done = true;
	assert(sydbox);

	if (sydbox->program_invocation_name)
		free(sydbox->program_invocation_name);

	/* FIXME: Why can't we free these? */
#if 0
	if (sc_map_size_64s(&sydbox->config.proc_pid_auto)) {
		sc_map_clear_64s(&sydbox->config.proc_pid_auto);
		sc_map_term_64s(&sydbox->config.proc_pid_auto);
	}
	if (sc_map_size_64v(&sydbox->tree)) {
		sc_map_clear_64v(&sydbox->tree);
		sc_map_term_64v(&sydbox->tree);
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
	int opt, r, opt_t[5];
	size_t i;
	char *c;
	struct utsname buf_uts;

	arch_native = seccomp_arch_native();

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
		{"test",	no_argument,		NULL,	't'},
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
			if (arch_argv_idx >= SYD_SECCOMP_ARCH_ARGV_SIZ - 1)
				die("too many -a arguments");
			arch_argv[arch_argv_idx++] = xstrdup(optarg);
			arch_argv[arch_argv_idx] = NULL;
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

#if 0
	const char *env;
	if ((env = getenv(SYDBOX_CONFIG_ENV)))
		config_parse_spec(env);
#endif

	const char *const *my_argv;
	if (optind == argc) {
		config_parse_spec(DATADIR "/" PACKAGE
				  "/default.syd-" STRINGIFY(SYDBOX_API_VERSION));
		set_uid(getuid());
		set_gid(getgid());
		set_startas("sydsh");
		my_argv = sydsh_argv;
		sydbox->program_invocation_name = xstrdup("sydsh");
	} else {
		my_argv = (const char *const *)(argv + optind);
		/*
		 * Initial program_invocation_name to be used for P_COMM(current).
		 * Saves one proc_comm() call.
		 */
		sydbox->program_invocation_name = xstrdup(argv[optind]);
	}
	config_done();

	/* Late validations for options */
	if (!sydbox->config.restrict_general &&
	    /*
	    !sydbox->config.restrict_ioctl &&
	    !sydbox->config.restrict_mmap &&
	    !sydbox->config.restrict_shm_wr &&
	    */
	    SANDBOX_OFF_ALL()) {
		say("All restrict and sandbox options are off.");
		die("Refusing to run the program `%s'.", my_argv[0]);
	}

	/* Set useful environment variables for children */
	setenv("SYDBOX", SEE_EMILY_PLAY, 1);
	setenv("SYDBOX_VERSION", VERSION, 1);
	setenv("SYDBOX_API_VERSION", STRINGIFY(SYDBOX_API_VERSION), 1);
	setenv("SYDBOX_ACTIVE", THE_PIPER, 1);

	/* STARTUP_CHILD must not be called before the signal handlers get
	   installed below as they are inherited into the spawned process. */
	int exit_code;
	int status;
	pid_t pid;
	syd_process_t *child;
	if (use_notify()) {
		pid = startup_child((char **)my_argv);
		child = new_process_or_kill(pid);
		init_process_data(child, NULL, false);
		/* Happy birthday, child.
		 * Let's validate your PID manually.
		 */
		sydbox->pid_valid = PID_INIT_VALID;
		proc_validate(pid);
		/* Notify the user about the startup. */
		dump(DUMP_STARTUP, pid);
		/* Block signals,
		 * We want to be safe against interrupts. */
		init_signals();
		/* All good.
		 * Tracing starts.
		 * Benediximus.
		 */
		exit_code = notify_loop();
		if (exit_code >= 128) {
			/*
			 * Notify loop got a termination signal, and
			 * delivered it to all processes.
			 * Nothing left to do.
			 */
			exit(exit_code);
		}
	} else {
		pid = startup_child((char **)my_argv);
	}
	for (;;) {
		errno = 0;
		pid = waitpid(-1, &status, __WALL);
		switch (errno) {
		case 0:
			if (pid == sydbox->execve_pid) {
				if (WIFEXITED(status))
					exit_code = WEXITSTATUS(status);
				else if (WIFSIGNALED(status))
					exit_code = 128 + WTERMSIG(status);
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
	dump(DUMP_EXIT,
	     exit_code/* sydbox->violation_exit_code */,
	     process_count(),
	     process_count_alive());
	dump(DUMP_ALLOC, 0, NULL);
	dump(DUMP_CLOSE);
	cleanup_for_sydbox();
	if (sydbox->violation) {
		if (sydbox->config.violation_exit_code > 0)
			exit_code = sydbox->config.violation_exit_code;
		else if (exit_code < 128 &&
			 sydbox->config.violation_exit_code == 0)
			exit_code = 128 /* + sydbox->exit_code */;
	}
	free(sydbox);
	return exit_code;
}

/*************** CHECKSUM CALCULATION *****************************************/
inline void syd_hash_sha1_init(void)
{
	syd_SHA1_Init(&sydbox->sha1);
}

inline void syd_hash_sha1_update(const void *data, size_t len)
{
	syd_SHA1_Update(&sydbox->sha1, data, len);
}

inline void syd_hash_sha1_final(unsigned char *hash)
{
	syd_SHA1_Final(hash, &sydbox->sha1);
}
/*********** END OF CHECKSUM CALCULATION **************************************/
