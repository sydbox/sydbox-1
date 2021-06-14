/*
 * sydbox/sydbox.h
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2018, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SYDBOX_GUARD_SYDBOX_H
#define SYDBOX_GUARD_SYDBOX_H 1

#include "sydconf.h"

#ifndef _ATFILE_SOURCE
#define _ATFILE_SOURCE 1
#endif /* !_ATFILE_SOURCE */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif /* !_GNU_SOURCE */

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <limits.h>
#include <errno.h>
#include <sched.h>
#include <seccomp.h>
#include "pink.h"
#include "acl-queue.h"
#include "procmatch.h"
#include "sockmatch.h"
#include "sockmap.h"
#include "util.h"
#include "xfunc.h"
#include "arch.h"
#include "compiler.h"

/* Definitions */
#ifdef KERNEL_VERSION
#undef KERNEL_VERSION
#endif
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

/* System call numbers */
#include "config.h"
#ifdef HAVE_ASM_UNISTD_H
# include <asm/unistd.h>
#endif
#if !(defined(__NR_pidfd_open) && defined(__NR_pidfd_getfd))
# ifndef __NR_pidfd_open
#  define __NR_pidfd_open 434
# endif
# ifndef __NR_pidfd_getfd
#  define __NR_pidfd_getfd 438
# endif
#endif

#define strbool(arg)	((arg) ? "yes" : "no")

/* Process flags */
#define SYD_STARTUP		00001 /* process attached, needs to be set up */
#define SYD_IGNORE_ONE_SIGSTOP	00002 /* initial sigstop is to be ignored */
#define SYD_IN_CLONE		00004 /* process called clone(2) */
#define SYD_IN_EXECVE		00010 /* process called execve(2) */
#define SYD_KILLED		00020 /* process is dead, keeping entry for child. */
#define SYD_DETACHED		00040 /* process is detached, not sandboxed. */

#define SYD_PPID_NONE		0      /* no parent PID (yet) */
#define SYD_TGID_NONE		0      /* no thread group ID (yet) */

/* ANSI colour codes */
#define ANSI_NORMAL		"[00;00m"
#define ANSI_MAGENTA		"[00;35m"
#define ANSI_DARK_MAGENTA	"[01;35m"
#define ANSI_GREEN		"[00;32m"
#define ANSI_YELLOW		"[00;33m"
#define ANSI_CYAN		"[00;36m"

/* Type declarations */
enum sandbox_mode {
	SANDBOX_OFF,
	SANDBOX_BPF,
	SANDBOX_ALLOW,
	SANDBOX_DENY,
};
static const char *const sandbox_mode_table[] = {
	[SANDBOX_OFF] = "off",
	[SANDBOX_BPF] = "bpf",
	[SANDBOX_DENY] = "deny",
	[SANDBOX_ALLOW] = "allow",
};
DEFINE_STRING_TABLE_LOOKUP(sandbox_mode, int)

static const char *const addrfams_table[] = {
	"AF_UNSPEC",
	"AF_UNIX",
	"AF_INET",
	"AF_AX25",
	"AF_IPX",
	"AF_APPLETALK",
	"AF_NETROM",
	"AF_BRIDGE",
	"AF_ATMPVC",
	"AF_X25",
	"AF_INET6",
	"AF_ROSE",
	"AF_DECnet",
	"AF_NETBEUI",
	"AF_SECURITY",
	"AF_KEY",
	"AF_NETLINK",
	"AF_PACKET",
	"AF_ASH",
	"AF_ECONET",
	"AF_ATMSVC",
	"AF_RDS",
	"AF_SNA",
	"AF_IRDA",
	"AF_PPPOX",
	"AF_WANPIPE",
	"AF_LLC",
	"AF_IB",
	"AF_MPLS",
	"AF_CAN",
	"AF_TIPC",
	"AF_BLUETOOTH",
	"AF_IUCV",
	"AF_RXRPC",
	"AF_ISDN",
	"AF_PHONET",
	"AF_IEEE802154",
	"AF_CAIF",
	"AF_ALG",
	"AF_NFC",
	"AF_VSOCK",
	"AF_KCM",
	"AF_QIPCRTR",
	"AF_SMC",
	"AF_XDP",
};
DEFINE_STRING_TABLE_LOOKUP(addrfams, int)

enum lock_state {
	LOCK_UNSET,
	LOCK_SET,
	LOCK_PENDING,
};
static const char *const lock_state_table[] = {
	[LOCK_UNSET] = "off",
	[LOCK_SET] = "on",
	[LOCK_PENDING] = "exec",
};
DEFINE_STRING_TABLE_LOOKUP(lock_state, int)

enum violation_decision {
	VIOLATION_NOOP,
	VIOLATION_DENY,
	VIOLATION_KILL,
	VIOLATION_KILLALL,
};
static const char *const violation_decision_table[] = {
	[VIOLATION_NOOP] = "noop",
	[VIOLATION_DENY] = "deny",
	[VIOLATION_KILL] = "kill",
	[VIOLATION_KILLALL] = "killall",
};
DEFINE_STRING_TABLE_LOOKUP(violation_decision, int)

#include "rule.h"
static const char *const syd_action_table[] = {
	[SYD_ACTION_KILL_PROCESS] = "kill_process",
	[SYD_ACTION_KILL_THREAD] = "kill_thread",
	[SYD_ACTION_FAULT] = "fault",
	[SYD_ACTION_TRAP] = "trap",
	[SYD_ACTION_LOG] = "log",
	[SYD_ACTION_ALLOW] = "allow",
	[SYD_ACTION_USER] = "user",
};
DEFINE_STRING_TABLE_LOOKUP(syd_action, int)

enum magic_op {
	MAGIC_OP_SET,
	MAGIC_OP_APPEND,
	MAGIC_OP_REMOVE,
	MAGIC_OP_QUERY,
	MAGIC_OP_EXEC,
};

enum magic_type {
	MAGIC_TYPE_NONE,

	MAGIC_TYPE_OBJECT,
	MAGIC_TYPE_BOOLEAN,
	MAGIC_TYPE_INTEGER,
	MAGIC_TYPE_STRING,
	MAGIC_TYPE_STRING_ARRAY,
	MAGIC_TYPE_COMMAND,

	MAGIC_TYPE_INVALID,
};

enum magic_key {
	MAGIC_KEY_NONE,

	MAGIC_KEY_VERSION,

	MAGIC_KEY_CORE,

	MAGIC_KEY_CORE_MATCH,
	MAGIC_KEY_CORE_MATCH_CASE_SENSITIVE,
	MAGIC_KEY_CORE_MATCH_NO_WILDCARD,

	MAGIC_KEY_CORE_SANDBOX,
	MAGIC_KEY_CORE_SANDBOX_EXEC,
	MAGIC_KEY_CORE_SANDBOX_READ,
	MAGIC_KEY_CORE_SANDBOX_WRITE,
	MAGIC_KEY_CORE_SANDBOX_NETWORK,

	MAGIC_KEY_CORE_RESTRICT,
	MAGIC_KEY_CORE_RESTRICT_GENERAL,
	MAGIC_KEY_CORE_RESTRICT_IO_CONTROL,
	MAGIC_KEY_CORE_RESTRICT_MEMORY_MAP,
	MAGIC_KEY_CORE_RESTRICT_SHARED_MEMORY_WRITABLE,

	MAGIC_KEY_CORE_ALLOWLIST,
	MAGIC_KEY_CORE_ALLOWLIST_PER_PROCESS_DIRECTORIES,
	MAGIC_KEY_CORE_ALLOWLIST_SUCCESSFUL_BIND,
	MAGIC_KEY_CORE_ALLOWLIST_UNSUPPORTED_SOCKET_FAMILIES,

	MAGIC_KEY_CORE_VIOLATION,
	MAGIC_KEY_CORE_VIOLATION_DECISION,
	MAGIC_KEY_CORE_VIOLATION_EXIT_CODE,
	MAGIC_KEY_CORE_VIOLATION_RAISE_FAIL,
	MAGIC_KEY_CORE_VIOLATION_RAISE_SAFE,

	MAGIC_KEY_CORE_TRACE,
	MAGIC_KEY_CORE_TRACE_MAGIC_LOCK,
	MAGIC_KEY_CORE_TRACE_INTERRUPT,
	MAGIC_KEY_CORE_TRACE_USE_TOOLONG_HACK,

	MAGIC_KEY_EXEC,
	MAGIC_KEY_EXEC_KILL_IF_MATCH,
	MAGIC_KEY_EXEC_RESUME_IF_MATCH,

	MAGIC_KEY_ALLOWLIST,
	MAGIC_KEY_ALLOWLIST_EXEC,
	MAGIC_KEY_ALLOWLIST_READ,
	MAGIC_KEY_ALLOWLIST_WRITE,
	MAGIC_KEY_ALLOWLIST_NETWORK,
	MAGIC_KEY_ALLOWLIST_NETWORK_BIND,
	MAGIC_KEY_ALLOWLIST_NETWORK_CONNECT,

	MAGIC_KEY_DENYLIST,
	MAGIC_KEY_DENYLIST_EXEC,
	MAGIC_KEY_DENYLIST_READ,
	MAGIC_KEY_DENYLIST_WRITE,
	MAGIC_KEY_DENYLIST_NETWORK,
	MAGIC_KEY_DENYLIST_NETWORK_BIND,
	MAGIC_KEY_DENYLIST_NETWORK_CONNECT,

	MAGIC_KEY_FILTER,
	MAGIC_KEY_FILTER_EXEC,
	MAGIC_KEY_FILTER_READ,
	MAGIC_KEY_FILTER_WRITE,
	MAGIC_KEY_FILTER_NETWORK,

	MAGIC_KEY_CMD,
	MAGIC_KEY_CMD_EXEC,

	MAGIC_KEY_INVALID,
};

enum magic_ret {
	MAGIC_RET_NOOP = 1,
	MAGIC_RET_OK,
	MAGIC_RET_TRUE,
	MAGIC_RET_FALSE,
	MAGIC_RET_ERROR_0,
	MAGIC_RET_NOT_SUPPORTED,
	MAGIC_RET_INVALID_KEY,
	MAGIC_RET_INVALID_TYPE,
	MAGIC_RET_INVALID_VALUE,
	MAGIC_RET_INVALID_QUERY,
	MAGIC_RET_INVALID_COMMAND,
	MAGIC_RET_INVALID_OPERATION,
	MAGIC_RET_NOPERM,
	MAGIC_RET_OOM,
	MAGIC_RET_PROCESS_TERMINATED,
};

#define MAGIC_BOOL(b)	((b) ? MAGIC_RET_TRUE : MAGIC_RET_FALSE)
#define MAGIC_ERROR(r)	((r) < 0 || (r) >= MAGIC_RET_ERROR_0)

enum syd_stat {
	SYD_STAT_NONE = 0, /* no stat() information necessary */
	SYD_STAT_LSTAT = 1, /* call lstat() instead of stat() */
	SYD_STAT_NOEXIST = 2, /* EEXIST */
	SYD_STAT_ISDIR = 4, /* ENOTDIR */
	SYD_STAT_NOTDIR = 8, /* EISDIR */
	SYD_STAT_NOFOLLOW = 16, /* ELOOP */
	SYD_STAT_EMPTYDIR = 32, /* ENOTDIR or ENOTEMPTY */
};

enum sys_access_mode {
	ACCESS_0,
	ACCESS_ALLOWLIST,
	ACCESS_DENYLIST
};
static const char *const sys_access_mode_table[] = {
	[ACCESS_0]         = "0",
	[ACCESS_ALLOWLIST] = "allowlist",
	[ACCESS_DENYLIST] = "denylist"
};
DEFINE_STRING_TABLE_LOOKUP(sys_access_mode, int)

enum sydbox_export_mode {
	SYDBOX_EXPORT_NUL,
	SYDBOX_EXPORT_BPF,
	SYDBOX_EXPORT_PFC,
	SYDBOX_EXPORT_MAX,
};

struct sandbox_mode_struct {
	enum sandbox_mode sandbox_exec:2;
	enum sandbox_mode sandbox_read:2;
	enum sandbox_mode sandbox_write:2;
	enum sandbox_mode sandbox_network:2;
};

struct sandbox {
	struct sandbox_mode_struct mode;
	enum lock_state magic_lock:2;

	aclq_t acl_exec;
	aclq_t acl_read;
	aclq_t acl_write;

	aclq_t acl_network_bind;
	aclq_t acl_network_connect;
};
typedef struct sandbox sandbox_t;

struct syd_process_shared_clone_thread {
	/* Per-process sandbox */
	sandbox_t *box;

	/* Execve process ID */
	pid_t execve_pid;

	/* Reference count */
	unsigned refcnt;
};

/* Shared items when CLONE_FS is set. */
struct syd_process_shared_clone_fs {
	/* Current working directory */
	char *cwd;

	/* Reference count */
	unsigned refcnt;
};

/* Shared items when CLONE_FILES is set. */
struct syd_process_shared_clone_files {
	/*
	 * Inode socket address mapping for bind allowlist
	 */
	struct sockmap *sockmap;

	/* Reference count */
	unsigned refcnt;
};

/* Per-thread shared data */
struct syd_process_shared {
	struct syd_process_shared_clone_thread *clone_thread;
	struct syd_process_shared_clone_fs *clone_fs;
	struct syd_process_shared_clone_files *clone_files;
};

/* process information */
struct syd_process {
	/* Process/Thread ID */
	pid_t pid;

	/* Parent process ID */
	pid_t ppid;

	/* Thread group ID */
	pid_t tgid;

	/* Pid file descriptor */
	int pidfd;

	/* System call ABI */
	uint32_t arch;

	/* SYD_* flags */
	int flags;

	/* Update current working directory, next step */
	bool update_cwd;

	/* Last system call */
	unsigned long sysnum;

	/* Last (socket) subcall */
	long subcall;

	/* Denied system call will return this value */
	long retval;

	/* clone(2) flags used to spawn *this* thread */
	unsigned long clone_flags;

	/* Last clone(2) flags (used to spawn a *new* thread) */
	unsigned long new_clone_flags;

	/* Last system call name */
	const char *sysname;

	/* Resolved path argument for specially treated system calls like execve() */
	char *abspath;

	/* Arguments of last system call */
	long args[6];

	/* String representation of arguments, used by dump. */
	char *repr[6];

	/* Per-thread shared data */
	struct syd_process_shared shm;

	/* Process hash table via sydbox->proctab */
	UT_hash_handle hh;
};
typedef struct syd_process syd_process_t;

#define P_BOX(p) ((p)->shm.clone_thread->box)
#define P_EXECVE_PID(p) ((p)->shm.clone_thread->execve_pid)
#define P_CLONE_THREAD_REFCNT(p) ((p)->shm.clone_thread->refcnt)
#define P_CLONE_THREAD_RETAIN(p) ((p)->shm.clone_thread->refcnt++)
#define P_CLONE_THREAD_RELEASE(p) \
	do { \
		if ((p)->shm.clone_thread != NULL) { \
			(p)->shm.clone_thread->refcnt--; \
			if ((p)->shm.clone_thread->refcnt == 0) { \
				if ((p)->shm.clone_thread->box) { \
					free_sandbox((p)->shm.clone_thread->box); \
				} \
				free((p)->shm.clone_thread); \
				(p)->shm.clone_thread = NULL; \
			} \
		} \
	} while (0)

#define P_CWD(p) ((p)->shm.clone_fs->cwd)
#define P_CLONE_FS_REFCNT(p) ((p)->shm.clone_fs->refcnt)
#define P_CLONE_FS_RETAIN(p) ((p)->shm.clone_fs->refcnt++)
#define P_CLONE_FS_RELEASE(p) \
	do { \
		if ((p)->shm.clone_fs != NULL) { \
			(p)->shm.clone_fs->refcnt--; \
			if ((p)->shm.clone_fs->refcnt == 0) { \
				if ((p)->shm.clone_fs->cwd) { \
					free((p)->shm.clone_fs->cwd); \
				} \
				free((p)->shm.clone_fs); \
				(p)->shm.clone_fs = NULL; \
			} \
		} \
	} while (0)

#define P_SOCKMAP(p) ((p)->shm.clone_files->sockmap)
#define P_CLONE_FILES_REFCNT(p) ((p)->shm.clone_files->refcnt)
#define P_CLONE_FILES_RETAIN(p) ((p)->shm.clone_files->refcnt++)
#define P_CLONE_FILES_RELEASE(p) \
	do { \
		if ((p)->shm.clone_files != NULL) { \
			(p)->shm.clone_files->refcnt--; \
			if ((p)->shm.clone_files->refcnt == 0) { \
				if ((p)->shm.clone_files->sockmap) { \
					sockmap_destroy(&(p)->shm.clone_files->sockmap); \
					free((p)->shm.clone_files->sockmap); \
				} \
				free((p)->shm.clone_files); \
				(p)->shm.clone_files = NULL; \
			} \
		} \
	} while (0)

struct filter {
	enum syd_action action:3;

	int fd; /* seccomp notify fd */

	int num;
	uint32_t arch;

	int sig;

	bool ok; /* if true use ret or use ret */
	union {
		int err;
		int ret;
	} u;
};

struct config {
	/* magic access to core.*  */
	bool magic_core_allow;

	bool allowlist_per_process_directories;
	bool allowlist_successful_bind;
	bool allowlist_unsupported_socket_families;

	/* restrict knobs are not inherited, they're global config */
	bool restrict_ioctl;
	bool restrict_mmap;
	bool restrict_shm_wr;
	unsigned int restrict_general;

	/* same for these, not inherited: global */
	bool use_seize;
	bool use_toolong_hack;

	/* Per-process sandboxing data */
	sandbox_t box_static;

	/***
	 * Non-inherited, "global" configuration data
	 ***/
	enum violation_decision violation_decision;
	int violation_exit_code;
	bool violation_raise_fail;
	bool violation_raise_safe;

	aclq_t exec_kill_if_match;
	aclq_t exec_resume_if_match;

	aclq_t filter_exec;
	aclq_t filter_read;
	aclq_t filter_write;
	aclq_t filter_network;

	proc_pid_t *hh_proc_pid_auto;
	aclq_t acl_network_connect_auto;
};
typedef struct config config_t;

struct sydbox {
	/* This is true if an access violation has occured, false otherwise. */
	bool violation;

	bool execve_wait;
	bool permissive;
	bool bpf_only;

	int exit_code;
	int execve_pidfd;

#if SYDBOX_HAVE_DUMP_BUILTIN
	int dump_fd;
#endif
	int seccomp_fd;
	int notify_fd;

	/* Export mode, BPF/PFC */
	enum sydbox_export_mode export;

	uint32_t seccomp_action;
	pid_t execve_pid;

	/* Program invocation name (for the child) */
	char *program_invocation_name;

	/* SecComp Request & Response */
	struct seccomp_notif *request;
	struct seccomp_notif_resp *response;

	syd_process_t *proctab;

	/* SecComp Context */
	scmp_filter_ctx ctx;
	struct filter *filter;

	/* Global configuration */
	config_t config;
};
typedef struct sydbox sydbox_t;

typedef int (*sysfunc_t) (syd_process_t *current);
typedef int (*sysfilter_t) (void);

struct sysentry {
	const char *name;
	long no; /* Used only if `name' is NULL.
		  * May be used to implement virtual system calls.
		  */
	sysfunc_t notify;
	sysfunc_t exit;

	/* XXX: Debug */
	bool user_notif:1;

	/* Apply a simple seccomp filter (bpf-only, no ptrace) */
	sysfilter_t filter;

	/*
	 * If this is >0 this system call is an f?access*() system call with
	 * `access_mode' member below pointing to the index of the flags argument.
	 */
	unsigned short access_mode;

	/*
	 * If this is >0 this system call is an open*() system call with
	 * `open_flag' member below pointing to the index of the flags argument.
	 */
	unsigned short open_flag;

	/*
	 * The sandbox group of the given system call.
	 */
	bool sandbox_read:1;
	bool sandbox_write:1;
	bool sandbox_exec:1;
	bool sandbox_network:1;
	bool magic_lock_off:1; /* used for magic stat() */
};
typedef struct sysentry sysentry_t;

struct syscall_info {
	/* Argument index */
	unsigned arg_index;

	/* `at' suffixed function */
	bool at_func;

	/* NULL argument does not cause -EFAULT (only valid for `at_func') */
	bool null_ok;
	/* Safe system call, deny silently (w/o raising access violation) */
	bool safe;
	/* Decode socketcall() into subcall */
	bool decode_socketcall;
	/* Socket address is in msg_name member of struct msg_hdr */
	bool sockaddr_in_msghdr;
	/* Mode for realpath_mode() */
	unsigned rmode;
	/* Stat mode */
	enum syd_stat syd_mode;
	/* Access control mode (allowlist, denylist) */
	enum sys_access_mode access_mode;

	/* Deny errno */
	int deny_errno;

	/* Access control lists (per-process, global) */
	aclq_t *access_list;
	aclq_t *access_list_global;
	/* Access filter lists (only global) */
	aclq_t *access_filter;

	/* Pointer to the data to be returned */
	int *ret_fd;
	char **ret_abspath;
	struct stat *ret_statbuf;
	struct pink_sockaddr **ret_addr;

	/* Cached data (to be reused by another sandboxing (read,write etc.) */
	const char *cache_abspath;
	const struct stat *cache_statbuf;
};
typedef struct syscall_info syscall_info_t;

/* Global variables */
extern sydbox_t *sydbox;

#define OPEN_READONLY_FLAG_MAX 1024
extern const int open_readonly_flags[OPEN_READONLY_FLAG_MAX];

#if SYDBOX_HAVE_DUMP_BUILTIN
# define inspecting() ((sydbox->dump_fd) != 0)
#else
# define inspecting() (0)
#endif

#define tracing() (0)
#define bpf_only() (sydbox->bpf_only)

#define sysdeny(p) ((p)->retval)
#define hasparent(p) ((p)->ppid >= 0)

#define SANDBOX_OFF(box) (!!(sydbox->config.box_static.mode.sandbox_ ## box == SANDBOX_OFF))
#define SANDBOX_OFF_READ() (SANDBOX_OFF(read))
#define SANDBOX_OFF_WRITE() (SANDBOX_OFF(write))
#define SANDBOX_OFF_EXEC() (SANDBOX_OFF(exec))
#define SANDBOX_OFF_NETWORK() (SANDBOX_OFF(network))
#define SANDBOX_OFF_ALL() (SANDBOX_OFF_READ() &&\
			   SANDBOX_OFF_WRITE() &&\
			   SANDBOX_OFF_EXEC() &&\
			   SANDBOX_OFF_NETWORK())

#define sandbox_allow(p, box) (!!(P_BOX(p)->mode.sandbox_ ## box == SANDBOX_ALLOW))
#define sandbox_deny(p, box) (!!(P_BOX(p)->mode.sandbox_ ## box == SANDBOX_DENY))
#define sandbox_off(p, box) (!!(P_BOX(p)->mode.sandbox_ ## box == SANDBOX_OFF))

#define sandbox_allow_exec(p) (sandbox_allow((p), exec))
#define sandbox_allow_read(p) (sandbox_allow((p), read))
#define sandbox_allow_write(p) (sandbox_allow((p), write))
#define sandbox_allow_network(p) (sandbox_allow((p), network))
#define sandbox_allow_file(p) (sandbox_allow_exec((p)) && sandbox_allow_read((p)) && sandbox_allow_write((p)))

#define sandbox_off_exec(p) (sandbox_off((p), exec))
#define sandbox_off_read(p) (sandbox_off((p), read))
#define sandbox_off_write(p) (sandbox_off((p), write))
#define sandbox_off_network(p) (sandbox_off((p), network))
#define sandbox_off_file(p) (sandbox_off_exec((p)) && sandbox_off_read((p)) && sandbox_off_write((p)))

#define sandbox_deny_exec(p) (sandbox_deny((p), exec))
#define sandbox_deny_read(p) (sandbox_deny((p), read))
#define sandbox_deny_write(p) (sandbox_deny((p), write))
#define sandbox_deny_network(p) (sandbox_deny((p), network))
#define sandbox_deny_file(p) (sandbox_deny_exec((p)) && sandbox_deny_read((p)) && sandbox_deny_write((p)))

#define process_count() HASH_COUNT(sydbox->proctab)
#define process_iter(p, tmp) HASH_ITER(hh, sydbox->proctab, (p), (tmp))
#define process_add(p) HASH_ADD(hh, sydbox->proctab, pid, sizeof(pid_t), (p))
#define process_remove(p) HASH_DEL(sydbox->proctab, (p))

static inline unsigned int process_count_alive(void)
{
	unsigned int r;
	syd_process_t *node, *tmp;

	r = 0;
	process_iter(node, tmp) {
		if (node->flags & SYD_KILLED)
			continue;
		r += 1;
	}
	return r;
}

/* Global functions */
int syd_kill(pid_t pid, pid_t tgid, int sig);
int syd_read_syscall(syd_process_t *current, long *sysnum);
int syd_read_retval(syd_process_t *current, long *retval, int *error);
int syd_read_argument(syd_process_t *current, unsigned arg_index, long *argval);
int syd_read_argument_int(syd_process_t *current, unsigned arg_index, int *argval);
ssize_t syd_read_string(syd_process_t *current, long addr, char *dest, size_t len);
int syd_write_syscall(syd_process_t *current, long sysnum);
int syd_write_retval(syd_process_t *current, long retval, int error);
ssize_t syd_write_data(syd_process_t *current, long addr, const void *buf, size_t count);
int syd_read_socket_argument(syd_process_t *current, unsigned arg_index,
			     unsigned long *argval);
int syd_read_socket_subcall(syd_process_t *current, long *subcall);
int syd_read_socket_address(syd_process_t *current, bool sockaddr_in_msghdr,
			    unsigned arg_index, int *fd,
			    struct pink_sockaddr *sockaddr);
int syd_read_vm_data(syd_process_t *current, long addr, char *dest, size_t len);
int syd_read_vm_data_full(syd_process_t *current, long addr, unsigned long *argval);
ssize_t syd_write_vm_data(syd_process_t *current, long addr, const char *src,
			  size_t len);

int test_cross_memory_attach(bool report);
int test_proc_mem(bool report);
int test_pidfd(bool report);
int test_seccomp(bool report);

void reset_process(syd_process_t *p);
void bury_process(syd_process_t *p);
void remove_process_node(syd_process_t *p);

static inline syd_process_t *lookup_process(pid_t pid)
{
	syd_process_t *process;

	HASH_FIND(hh, sydbox->proctab, &pid, sizeof(pid_t), process);
	return process;
}

void cleanup(void);

int parent_read_int(int *message);
int parent_write_int(int message);

void kill_all(int fatal_sig);
int kill_one(syd_process_t *current, int fatal_sig);
int deny(syd_process_t *current, int err_no);
int restore(syd_process_t *current);
int panic(syd_process_t *current);
int violation(syd_process_t *current, const char *fmt, ...)
	SYD_GCC_ATTR((format (printf, 2, 3)));

int filter_init(void);
int filter_free(void);
int filter_push(struct filter filter);

void config_init(void);
void config_done(void);
void config_parse_file(const char *filename) SYD_GCC_ATTR((nonnull(1)));
void config_parse_spec(const char *filename) SYD_GCC_ATTR((nonnull(1)));

void callback_init(void);

int box_resolve_path(const char *path, const char *prefix, pid_t pid,
		     unsigned rmode, char **res);
int box_check_path(syd_process_t *current, syscall_info_t *info);
int box_check_socket(syd_process_t *current, syscall_info_t *info);

static inline sandbox_t *box_current(syd_process_t *current)
{
	return current ? P_BOX(current) : &sydbox->config.box_static;
}

static inline void init_sandbox(sandbox_t *box)
{
	box->mode.sandbox_exec = SANDBOX_OFF;
	box->mode.sandbox_read = SANDBOX_OFF;
	box->mode.sandbox_write = SANDBOX_OFF;
	box->mode.sandbox_network = SANDBOX_OFF;

	box->magic_lock = LOCK_UNSET;

	ACLQ_INIT(&box->acl_exec);
	ACLQ_INIT(&box->acl_read);
	ACLQ_INIT(&box->acl_write);
	ACLQ_INIT(&box->acl_network_bind);
	ACLQ_INIT(&box->acl_network_connect);
}

static inline void copy_sandbox(sandbox_t *box_dest, sandbox_t *box_src)
{
	struct acl_node *node, *newnode;

	if (!box_src)
		return;

	assert(box_dest);

	box_dest->mode.sandbox_exec = box_src->mode.sandbox_exec;
	box_dest->mode.sandbox_read = box_src->mode.sandbox_read;
	box_dest->mode.sandbox_write = box_src->mode.sandbox_write;
	box_dest->mode.sandbox_network = box_src->mode.sandbox_network;

	box_dest->magic_lock = box_src->magic_lock;

	ACLQ_COPY(node, &box_src->acl_exec, &box_dest->acl_exec, newnode, xstrdup);
	ACLQ_COPY(node, &box_src->acl_read, &box_dest->acl_read, newnode, xstrdup);
	ACLQ_COPY(node, &box_src->acl_write, &box_dest->acl_write, newnode, xstrdup);
	ACLQ_COPY(node, &box_src->acl_network_bind, &box_dest->acl_network_bind, newnode, sockmatch_xdup);
	ACLQ_COPY(node, &box_src->acl_network_connect, &box_dest->acl_network_connect, newnode, sockmatch_xdup);
}

static inline void reset_sandbox(sandbox_t *box)
{
	struct acl_node *node;

	ACLQ_RESET(node, &box->acl_exec, free);
	ACLQ_RESET(node, &box->acl_read, free);
	ACLQ_RESET(node, &box->acl_write, free);
	ACLQ_RESET(node, &box->acl_network_bind, free_sockmatch);
	ACLQ_RESET(node, &box->acl_network_connect, free_sockmatch);
}

static inline int new_sandbox(sandbox_t **box_ptr)
{
	sandbox_t *box;

	box = malloc(sizeof(sandbox_t));
	if (!box)
		return -errno;
	init_sandbox(box);

	*box_ptr = box;
	return 0;
}

static inline void free_sandbox(sandbox_t *box)
{
	reset_sandbox(box);
	free(box);
}

static inline bool use_notify(void)
{
	if (sydbox->bpf_only)
		return false;

	sandbox_t *box = box_current(NULL);
	enum sandbox_mode mode[] = {
		box->mode.sandbox_read,
		box->mode.sandbox_write,
		box->mode.sandbox_exec,
		box->mode.sandbox_network,
	};

	for (unsigned short i = 0; i < ELEMENTSOF(mode); i++) {
		switch (mode[i]) {
		case SANDBOX_ALLOW:
		case SANDBOX_DENY:
			return true;
		default:
			continue;
		}
	}

	return false;
}

void systable_init(void);
void systable_free(void);
void systable_add_full(long no, uint32_t arch, const char *name,
		       sysfunc_t fenter, sysfunc_t fexit);
void systable_add(const char *name, sysfunc_t fenter, sysfunc_t fexit);
const sysentry_t *systable_lookup(long no, uint32_t arch);

size_t syscall_entries_max(void);
void sysinit(void);
int sysinit_seccomp(void);
int sysinit_seccomp_load(void);
int sysnotify(syd_process_t *current);
int sysexit(syd_process_t *current);

enum magic_ret magic_check_call(int rval);
const char *magic_strerror(int error);
const char *magic_strkey(enum magic_key key);
unsigned magic_key_type(enum magic_key key);
unsigned magic_key_parent(enum magic_key key);
unsigned magic_key_lookup(enum magic_key key, const char *nkey, ssize_t len);
int magic_cast(syd_process_t *current, enum magic_op op, enum magic_key key,
	       const void *val);
int magic_cast_string(syd_process_t *current, const char *magic, int prefix);

int magic_set_panic_exit_code(const void *val, syd_process_t *current);
int magic_set_violation_exit_code(const void *val, syd_process_t *current);
int magic_set_violation_raise_fail(const void *val, syd_process_t *current);
int magic_query_violation_raise_fail(syd_process_t *current);
int magic_set_violation_raise_safe(const void *val, syd_process_t *current);
int magic_query_violation_raise_safe(syd_process_t *current);
int magic_set_trace_use_toolong_hack(const void *val, syd_process_t *current);
int magic_query_trace_use_toolong_hack(syd_process_t *current);
int magic_set_restrict_general(const void *val, syd_process_t *current);
int magic_query_restrict_general(syd_process_t *current);
int magic_set_restrict_mmap(const void *val, syd_process_t *current);
int magic_query_restrict_mmap(syd_process_t *current);
int magic_set_restrict_ioctl(const void *val, syd_process_t *current);
int magic_query_restrict_ioctl(syd_process_t *current);
int magic_set_restrict_shm_wr(const void *val, syd_process_t *current);
int magic_query_restrict_shm_wr(syd_process_t *current);
int magic_set_allowlist_ppd(const void *val, syd_process_t *current);
int magic_query_allowlist_ppd(syd_process_t *current);
int magic_set_allowlist_sb(const void *val, syd_process_t *current);
int magic_query_allowlist_sb(syd_process_t *current);
int magic_set_allowlist_usf(const void *val, syd_process_t *current);
int magic_query_allowlist_usf(syd_process_t *current);
int magic_append_allowlist_exec(const void *val, syd_process_t *current);
int magic_remove_allowlist_exec(const void *val, syd_process_t *current);
int magic_append_allowlist_read(const void *val, syd_process_t *current);
int magic_remove_allowlist_read(const void *val, syd_process_t *current);
int magic_append_allowlist_write(const void *val, syd_process_t *current);
int magic_remove_allowlist_write(const void *val, syd_process_t *current);
int magic_append_denylist_exec(const void *val, syd_process_t *current);
int magic_remove_denylist_exec(const void *val, syd_process_t *current);
int magic_append_denylist_read(const void *val, syd_process_t *current);
int magic_remove_denylist_read(const void *val, syd_process_t *current);
int magic_append_denylist_write(const void *val, syd_process_t *current);
int magic_remove_denylist_write(const void *val, syd_process_t *current);
int magic_append_filter_exec(const void *val, syd_process_t *current);
int magic_remove_filter_exec(const void *val, syd_process_t *current);
int magic_append_filter_read(const void *val, syd_process_t *current);
int magic_remove_filter_read(const void *val, syd_process_t *current);
int magic_append_filter_write(const void *val, syd_process_t *current);
int magic_remove_filter_write(const void *val, syd_process_t *current);
int magic_append_allowlist_network_bind(const void *val, syd_process_t *current);
int magic_remove_allowlist_network_bind(const void *val, syd_process_t *current);
int magic_append_allowlist_network_connect(const void *val, syd_process_t *current);
int magic_remove_allowlist_network_connect(const void *val, syd_process_t *current);
int magic_append_denylist_network_bind(const void *val, syd_process_t *current);
int magic_remove_denylist_network_bind(const void *val, syd_process_t *current);
int magic_append_denylist_network_connect(const void *val, syd_process_t *current);
int magic_remove_denylist_network_connect(const void *val, syd_process_t *current);
int magic_append_filter_network(const void *val, syd_process_t *current);
int magic_remove_filter_network(const void *val, syd_process_t *current);
int magic_set_violation_decision(const void *val, syd_process_t *current);
int magic_set_trace_magic_lock(const void *val, syd_process_t *current);
int magic_query_sandbox_exec(syd_process_t *current);
int magic_query_sandbox_read(syd_process_t *current);
int magic_query_sandbox_write(syd_process_t *current);
int magic_query_sandbox_network(syd_process_t *current);
int magic_set_sandbox_exec(const void *val, syd_process_t *current);
int magic_set_sandbox_read(const void *val, syd_process_t *current);
int magic_set_sandbox_write(const void *val, syd_process_t *current);
int magic_set_sandbox_network(const void *val, syd_process_t *current);
int magic_set_sandbox_all(const void *val, syd_process_t *current);
int magic_append_exec_kill_if_match(const void *val, syd_process_t *current);
int magic_remove_exec_kill_if_match(const void *val, syd_process_t *current);
int magic_append_exec_resume_if_match(const void *val, syd_process_t *current);
int magic_remove_exec_resume_if_match(const void *val, syd_process_t *current);
int magic_query_match_case_sensitive(syd_process_t *current);
int magic_set_match_case_sensitive(const void *val, syd_process_t *current);
int magic_set_match_no_wildcard(const void *val, syd_process_t *current);

int magic_cmd_exec(const void *val, syd_process_t *current);

static inline void init_sysinfo(syscall_info_t *info)
{
	memset(info, 0, sizeof(syscall_info_t));
}

bool filter_includes(int sysnum);
int filter_general(void);
int filter_open(void);
int filter_openat(void);
int filter_mmap(void);
int filter_mmap2(void);
int filter_mprotect(void);
int filter_ioctl(void);
int sys_fallback_mmap(syd_process_t *current);

int sys_access(syd_process_t *current);
int sys_faccessat(syd_process_t *current);
int sys_faccessat2(syd_process_t *current);

int sys_chmod(syd_process_t *current);
int sys_fchmodat(syd_process_t *current);
int sys_chown(syd_process_t *current);
int sys_lchown(syd_process_t *current);
int sys_fchownat(syd_process_t *current);
int sys_open(syd_process_t *current);
int sys_openat(syd_process_t *current);
int sys_openat2(syd_process_t *current);
int sys_creat(syd_process_t *current);
int sys_close(syd_process_t *current);
int sys_mkdir(syd_process_t *current);
int sys_mkdirat(syd_process_t *current);
int sys_mknod(syd_process_t *current);
int sys_mknodat(syd_process_t *current);
int sys_rmdir(syd_process_t *current);
int sys_truncate(syd_process_t *current);
int sys_mount(syd_process_t *current);
int sys_umount(syd_process_t *current);
int sys_umount2(syd_process_t *current);
int sys_utime(syd_process_t *current);
int sys_utimes(syd_process_t *current);
int sys_utimensat(syd_process_t *current);
int sys_futimesat(syd_process_t *current);
int sys_unlink(syd_process_t *current);
int sys_unlinkat(syd_process_t *current);
int sys_link(syd_process_t *current);
int sys_linkat(syd_process_t *current);
int sys_rename(syd_process_t *current);
int sys_renameat(syd_process_t *current);
int sys_symlink(syd_process_t *current);
int sys_symlinkat(syd_process_t *current);
int sys_listxattr(syd_process_t *current);
int sys_llistxattr(syd_process_t *current);
int sys_setxattr(syd_process_t *current);
int sys_lsetxattr(syd_process_t *current);
int sys_removexattr(syd_process_t *current);
int sys_lremovexattr(syd_process_t *current);

int sys_dup(syd_process_t *current);
int sys_dup3(syd_process_t *current);

int sys_fork(syd_process_t *current);
int sys_vfork(syd_process_t *current);
int sys_clone(syd_process_t *current);
int sys_execve(syd_process_t *current);
int sys_execveat(syd_process_t *current);
int sys_stat(syd_process_t *current);
int sys_fstatat(syd_process_t *current);
int sys_statx(syd_process_t *current);

int sys_socketcall(syd_process_t *current);
int sys_bind(syd_process_t *current);
int sys_connect(syd_process_t *current);
int sys_sendto(syd_process_t *current);
int sys_listen(syd_process_t *current);
int sys_accept(syd_process_t *current);
int sys_getsockname(syd_process_t *current);
int sys_sendmsg(syd_process_t *current);
int sys_recvmsg(syd_process_t *current);

int sysx_chdir(syd_process_t *current);

#endif
