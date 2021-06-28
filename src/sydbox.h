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
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <limits.h>
#include <errno.h>
#include <sched.h>
#include <seccomp.h>
#include <linux/sched.h>
#include "pink.h"
#include "acl-queue.h"
#include "bsd-compat.h"
#include "procmatch.h"
#include "sc_map.h"
#include "sockmatch.h"
#include "sockmap.h"
#include "util.h"
#include "xfunc.h"
#include "arch.h"
#include "compiler.h"

#include "sc_map_syd.h"
#include "sha1dc_syd.h"
#include "hex.h"

/* Definitions */
#ifdef KERNEL_VERSION
#undef KERNEL_VERSION
#endif
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

/* System call numbers */
#include "config.h"
#include <asm/unistd.h>
#if !defined(__NR_process_vm_readv)
# define __NR_process_vm_readv 310
#endif
#if !defined(__NR_process_vm_writev)
# define __NR_process_vm_writev 311
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
#define SYD_IN_CLONE		00002 /* process called clone(2) */
#define SYD_IN_EXECVE		00004 /* process called execve(2) */

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
	MAGIC_KEY_CORE_RESTRICT_IDENTITY_CHANGE,
	MAGIC_KEY_CORE_RESTRICT_SYS_INFO,
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
	MAGIC_KEY_CORE_TRACE_MEMORY_ACCESS,
	MAGIC_KEY_CORE_TRACE_PROGRAM_CHECKSUM,
	MAGIC_KEY_CORE_TRACE_USE_TOOLONG_HACK,

	MAGIC_KEY_EXEC,
	MAGIC_KEY_EXEC_KILL_IF_MATCH,

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
	struct sc_map_64v sockmap;

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
	/*
	 * SECURITY:
	 * No process ID based actions if valid is false!
	 */
	bool valid:1;

	/*
	 * Process exited but we're keepin the entry
	 * for bookkeeping of the sandbox.
	 */
	bool zombie:1;

	/* Update current working directory, next step */
	bool update_cwd:1;

	/* SYD_* flags */
	unsigned int flags:7;

#define SYD_CLONE_THREAD	00001
#define SYD_CLONE_FS		00002
#define SYD_CLONE_FILES		00004
	/* clone(2) flags used to spawn *this* thread */
	unsigned int clone_flags:12;

	/* Last clone(2) flags (used to spawn a *new* thread) */
	unsigned int new_clone_flags:12;

	/* Process/Thread ID */
	pid_t pid;

	/* Parent process ID */
	pid_t ppid;

	/* Thread group ID */
	pid_t tgid;

	/*
	 * memfd & pidfd have three states:
	 * -1: Init. Waiting to be initialised.
	 * >0: Valid file descriptor.
	 *  0: File closed, indicates process is dead.
	 *
	 *  at sydbox.c:process_proc we try to open these files and on failure
	 *  we set them back to -1 so that the main loop may retry to open the
	 *  files once's the /proc directory of the process becomes available.
	 *
	 *  There is a macro which checks process aliveness with pidfd > 0
	 *  and pidfd == 0 may be used to check if the process has exited.
	 */

	/* System call ABI */
	uint32_t arch;

	/* Last system call */
	uint64_t sysnum;

	/* Subcall of the last system call */
	uint8_t subcall;

#ifdef ENABLE_PSYSCALL
	long addr; /* Read-only allocated address in child's address space. */
	bool addr_arg[6];
	struct pink_regset *regset;
#endif

	/* Denied system call will return this value */
	long retval;

	/* Arguments of last system call */
	long args[6];

	/* String representation of arguments, used by dump. */
	char *repr[6];

	/* Per-thread shared data */
	struct syd_process_shared shm;

	/* Last system call name */
	const char *sysname;

	/* Resolved path argument for specially treated system calls like execve() */
	char *abspath;
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
				sockmap_destroy(&(p)->shm.clone_files->sockmap); \
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
	bool restrict_id;
	bool restrict_sysinfo;
	bool restrict_ioctl;
	bool restrict_mmap;
	bool restrict_shm_wr;
	unsigned int restrict_general;

	/* same for these, not inherited: global */
	bool use_seize;
	bool use_toolong_hack;
#define SYDBOX_CONFIG_MEMACCESS_MAX 2
	uint8_t mem_access:1;
	uint8_t prog_hash:2; /* 0: disabled, 1: initial execve, 2: all execves */

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

	aclq_t filter_exec;
	aclq_t filter_read;
	aclq_t filter_write;
	aclq_t filter_network;

	struct sc_map_64s proc_pid_auto;
	aclq_t acl_network_connect_auto;
};
typedef struct config config_t;

struct sydbox {
	/* This is true if an access violation has occured, false otherwise. */
	bool violation:1;

	bool execve_wait:1;
	bool permissive:1;
	bool bpf_only:1;
	bool in_child:1;

	/*
	 * File descriptors used by SydBox:
	 * 1. pidfd: Process ID fd acquired from:
	 *	pidfd_open(pid)
	 * 2. pfd: /proc fd acquired from
	 *	open("/proc/$pid", O_PATH)
	 * 3. pfd_fd: /proc fd acquired from
	 *	open("/proc/$pid/fd", O_PATH)
	 * 3..4 File descriptors for seccomp user notifications.
	 * 5. dump_fd is used by dump to output informational JSON lines.
	 *
	 * NOTE ABOUT SECURITY: proc_* fds require seccomp identity validation
	 * after receiving each seccomp notification!
	 * The lifetime of the file descriptors 1..3 is a single seccomp
	 * notification. See: kernel/samples/seccomp/user-trap.c
	 */
	int pidfd;
	int pfd;
	int pfd_fd;

	/* Only the proc_validate() function is permitted
	 * to set this entry. Only and only this process
	 * pointer is valid.
	 * TODO(SECURITY): no sandbox-critical actions
	 * must be done on any other process! This
	 * should already not be the case but it's
	 * best to check.
	 */
	syd_process_t *p;
	pid_t pid_valid;

/***************************************/
/* Start of Process ID SAFE interface: *
****************************************/
	int pfd_cwd;
	int pfd_mem;

	int notify_fd;
	int seccomp_fd;
#if SYDBOX_HAVE_DUMP_BUILTIN
	int dump_fd;
#endif

	/* Export mode, BPF/PFC */
	enum sydbox_export_mode export_mode;
	char *export_path;

	uint32_t seccomp_action;
	pid_t sydbox_pid; /* Process ID of the SydBox process. */
	pid_t execve_pid; /* Process ID of the process SydBox executes. */

	/* Program invocation name (for the child) */
	char *program_invocation_name;

	/* SecComp Request & Response */
	struct seccomp_notif *request;
	struct seccomp_notif_resp *response;

	/* The Process Tree */
	struct sc_map_64v tree;

	/* SecComp Context */
	scmp_filter_ctx ctx;
	struct filter *filter;
	uint16_t filter_count;
	uint32_t arch[SYD_SECCOMP_ARCH_ARGV_SIZ];

	/* SHA-1 Context and Hash */
	syd_SHA_CTX sha1;
	char hash[SYD_SHA1_HEXSZ];

	/* Global configuration */
	config_t config;
};
typedef struct sydbox sydbox_t;

typedef int (*sysfunc_t) (syd_process_t *current);
typedef int (*sysfilter_t) (uint32_t arch);

struct sysentry {
	const char *name;
	long no;

	/* Seccomp Notify callback */
	sysfunc_t notify;

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
	bool rule_rewrite:1; /* used for socketcall(), bind(), connect() et al. */

	/* Sandboxing depends on the return value of the given function. */
	int (*sandbox_opt)(syd_process_t *current);
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

#if SYDBOX_HAVE_DUMP_BUILTIN
# define inspecting() ((sydbox) && (sydbox->dump_fd) != 0)
#else
# define inspecting() (0)
#endif

#define tracing() (0)
#define bpf_only() ((sydbox) && sydbox->bpf_only)

#define use_cross_memory_attach() \
		(((sydbox)->config.mem_access == 0) || \
		 ((sydbox)->config.mem_access == 2))

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

#define proc_esrch(err_no)   ((err_no) == ENOENT || (err_no) == ESRCH)

#define action_bpf_default(action) ((action) != SCMP_ACT_NOTIFY &&\
				    (action) == sydbox->seccomp_action)

static inline uint32_t process_count(void)
{
	return sc_map_size_64v(&sydbox->tree);
}

static inline void process_add(syd_process_t *p)
{
	sc_map_put_64v(&sydbox->tree, p->pid, p);
}

static inline void process_remove(syd_process_t *p)
{
	sc_map_del_64v(&sydbox->tree, p->pid);
}

static inline syd_process_t *process_lookup(pid_t pid)
{
	syd_process_t *p = sc_map_get_64v(&sydbox->tree, pid);
	if (sc_map_found(&sydbox->tree))
		return p;
	return NULL;
}

/*************************************/
/* Security Functions */
static inline void sydbox_syscall_deny(void)
{
	sydbox->response->error = -EPERM;
	sydbox->response->flags = 0;
}

static inline void sydbox_syscall_allow(void)
{
	sydbox_syscall_deny();
	sydbox->response->error = 0;
	sydbox->response->flags |= SECCOMP_USER_NOTIF_FLAG_CONTINUE;
}

static inline bool syd_seccomp_request_is_valid(void)
{
	return seccomp_notify_id_valid(sydbox->notify_fd, sydbox->request->id) == 0;
}

static inline void proc_invalidate(void)
{
	if (sydbox->pidfd > 0)
		close(sydbox->pidfd);
	if (sydbox->pfd > 0)
		close(sydbox->pfd);
	if (sydbox->pfd_cwd > 0)
		close(sydbox->pfd_cwd);
	if (sydbox->pfd_fd > 0)
		close(sydbox->pfd_fd);
	if (sydbox->pfd_mem > 0)
		close(sydbox->pfd_mem);

	sydbox->pidfd = -1;
	sydbox->pfd = -1;
	sydbox->pfd_cwd = -1;
	sydbox->pfd_fd = -1;
	sydbox->pfd_mem = -1;

	sydbox->pid_valid = -1;
	sydbox->p = NULL;
}

#define PID_INIT_VALID (-42)
static inline bool proc_validate(pid_t pid)
{
	/* TODO: Is this check a security risk?
	 * Ponder! */
	if (sydbox->pid_valid != PID_INIT_VALID) {
		proc_invalidate();
		if (!syd_seccomp_request_is_valid())
			goto err;
	} else {
		/* This is unnecessary but let's be safe. */
		sydbox->pid_valid = -1;
	}

	int fd;

	if ((fd = sydbox->pidfd = syd_pidfd_open(pid, 0)) < 0)
		goto err;
	sydbox->pidfd = fd;

	if ((fd = syd_proc_open(pid)) < 0)
		goto err;
	sydbox->pfd = fd;

	if ((fd = syd_proc_fd_open(pid)) < 0)
		goto err;
	sydbox->pfd_fd = fd;

	if ((fd = syd_proc_cwd_open(pid)) < 0)
		goto err;
	sydbox->pfd_cwd = fd;

	sydbox->pid_valid = pid;
	sydbox->p = process_lookup(sydbox->pid_valid);
	goto validation_done;
err:
	proc_invalidate();
	return false;
validation_done:

	/* Validations are done,
	 * the remaining file descriptors
	 * are dependent on the above
	 * to be valid.
	 */
	sydbox->pfd_mem = syd_proc_mem_open(sydbox->pfd);

	return true;
}

#define proc_valid(p) ((p) == sydbox->p)
#define proc_validate_or_deny(_p,  label) do {\
	if (!proc_validate(_p->pid)) { \
		sydbox->response->error = -ESRCH; \
		sydbox->response->val = 0; \
		sydbox->response->flags = 0; \
		goto label; \
	} (_p) = sydbox->p; \
} while(0)

static inline int reopen_proc_mem(pid_t pid)
{
	if (sydbox->pfd_mem >= 0) {
		close(sydbox->pfd_mem);
		sydbox->pfd_mem = -1;
	}
	sydbox->pfd_mem = syd_proc_mem_open(sydbox->pid_valid);
	if (sydbox->pfd_mem < 0)
		return -errno;
	return 0;
}

/*************************/

/* Global functions */
int syd_kill(pid_t pid, pid_t tgid, int sig);
int syd_read_syscall(syd_process_t *current, long *sysnum);
int syd_read_retval(syd_process_t *current, long *retval, int *error);
int syd_read_argument(syd_process_t *current, unsigned arg_index, long *argval);
int syd_read_argument_int(syd_process_t *current, unsigned arg_index, int *argval);
ssize_t syd_read_string(syd_process_t *current, long addr, char *dest, size_t len);
int syd_write_syscall(syd_process_t *current, long sysnum);
int syd_write_retval(syd_process_t *current, long retval, int error);
ssize_t syd_write_data(syd_process_t *current, long addr, void *buf, size_t count);
int syd_read_socket_argument(syd_process_t *current, unsigned arg_index,
			     unsigned long *argval);
int syd_read_socket_subcall(syd_process_t *current, long *subcall);
int syd_read_socket_address(syd_process_t *current, bool sockaddr_in_msghdr,
			    unsigned arg_index, int *fd,
			    struct pink_sockaddr *sockaddr);
int syd_read_vm_data(syd_process_t *current, long addr, char *dest, size_t len);
int syd_read_vm_data_full(syd_process_t *current, long addr, unsigned long *argval);
ssize_t syd_write_vm_data(syd_process_t *current, long addr, char *src,
			  size_t len);
int syd_rmem_alloc(syd_process_t *current);
int syd_rmem_write(syd_process_t *current);

int syd_seccomp_arch_is_valid(uint32_t arch, bool *result);
void test_setup(void);
uint8_t test_seccomp_arch(void);
int test_cross_memory_attach(bool report);
int test_proc_mem(bool report);
int test_pidfd(bool report);
int test_seccomp(bool report);

void reset_process(syd_process_t *p);
void bury_process(syd_process_t *p, bool force);

void cleanup_for_child(void);
void cleanup_for_sydbox(void);

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

	if (box->acl_exec.tqh_last)
		ACLQ_RESET(node, &box->acl_exec, free);
	if (box->acl_read.tqh_last)
		ACLQ_RESET(node, &box->acl_read, free);
	if (box->acl_write.tqh_last)
		ACLQ_RESET(node, &box->acl_write, free);
	if (box->acl_network_bind.tqh_last)
		ACLQ_RESET(node, &box->acl_network_bind, free_sockmatch);
	if (box->acl_network_connect.tqh_last)
		ACLQ_RESET(node, &box->acl_network_connect, free_sockmatch);
}

static inline int new_sandbox(sandbox_t **box_ptr)
{
	sandbox_t *box;

	box = syd_malloc(sizeof(sandbox_t));
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

static inline unsigned short pack_clone_flags(long clone_flags)
{
	unsigned short f = 0;

	if (clone_flags & CLONE_THREAD)
		f |= SYD_CLONE_THREAD;
	if (clone_flags & CLONE_FS)
		f |= SYD_CLONE_FS;
	if (clone_flags & CLONE_FILES)
		f |= SYD_CLONE_FILES;

	return f;
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

void syd_hash_sha1_init(void);
void syd_hash_sha1_update(const void *data, size_t len);
void syd_hash_sha1_final(unsigned char *hash);
int path_to_hex(const char *pathname);

int sysinit(scmp_filter_ctx scmp_ctx);
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
int magic_set_trace_memory_access(const void *val, syd_process_t *current);
int magic_query_trace_memory_access(syd_process_t *current);
int magic_set_trace_program_checksum(const void *val, syd_process_t *current);
int magic_query_trace_program_checksum(syd_process_t *current);
int magic_set_trace_use_toolong_hack(const void *val, syd_process_t *current);
int magic_query_trace_use_toolong_hack(syd_process_t *current);
int magic_set_restrict_general(const void *val, syd_process_t *current);
int magic_query_restrict_general(syd_process_t *current);
int magic_set_restrict_id(const void *val, syd_process_t *current);
int magic_query_restrict_id(syd_process_t *current);
int magic_set_restrict_sysinfo(const void *val, syd_process_t *current);
int magic_query_restrict_sysinfo(syd_process_t *current);
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
int filter_mmap(uint32_t arch);
int filter_mmap2(uint32_t arch);
int filter_mprotect(uint32_t arch);
int filter_ioctl(uint32_t arch);
int sys_fallback_mmap(syd_process_t *current);
int filter_bind(uint32_t arch);
int filter_connect(uint32_t arch);
int filter_sendto(uint32_t arch);
int filter_recvmsg(uint32_t arch);
int filter_sendmsg(uint32_t arch);
int filter_uname(uint32_t arch);

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
int sys_uname(syd_process_t *current);

int sys_bind(syd_process_t *current);
int sys_connect(syd_process_t *current);
int sys_sendto(syd_process_t *current);
int sys_listen(syd_process_t *current);
int sys_accept(syd_process_t *current);
int sys_getsockname(syd_process_t *current);
int sys_sendmsg(syd_process_t *current);
int sys_recvmsg(syd_process_t *current);
int sys_socketcall(syd_process_t *current);

int sysx_chdir(syd_process_t *current);

int rule_add_action(uint32_t action, int sysnum);
int rule_add_open_rd(uint32_t action, int sysnum, int open_flag);

#endif
