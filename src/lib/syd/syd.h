/*
 * syd.h -- Syd's utility library
 *
 * Copyright (c) 2014, 2015, 2016 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is:
 *   Copyright 2010 Lennart Poettering
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef LIBSYD_SYD_H
#define LIBSYD_SYD_H 1

#ifndef _XOPEN_SOURCE
# define _XOPEN_SOURCE 700
#endif

#ifdef __STDC_NO_ATOMICS__
# error this implementation needs atomics
#endif

#include <errno.h>
#include <sys/types.h>
#include <linux/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>

#include <asm/unistd.h>
#include <sched.h>
#include <linux/sched.h>
#ifndef CLONE_CLEAR_SIGHAND
# define CLONE_CLEAR_SIGHAND 0x100000000ULL /* Clear any signal handler and
					       reset to SIG_DFL. */
#endif
#ifndef CLONE_NEWTIME
# define CLONE_NEWTIME	      0x00000080      /* New time namespace */
#endif
#ifndef CLONE_PIDFD
# define CLONE_PIDFD 0x00001000
#endif

#ifdef __NR_clone3
# define SYD_clone3 __NR_clone3
#else
# define SYD_clone3 435
#endif
pid_t syd_clone3(struct clone_args *args);

#include <seccomp.h>

#include <syd/compiler.h>
#include <syd/confname.h>
#include <syd/hex.h>
#include <syd/sc_map.h>
#include <syd/sha1dc_syd.h>

/***
 * LibSyd: Interface to the Book of the Way
 ***/
const char *syd_tao_rand(void);
const char *syd_tao_pick(uint8_t pick);
uint8_t syd_tao_max(void);

/***
 * LibSyd: Interface to the Tarot Decks
 ***/
int syd_tarot_draw(char **tarot_card);

/***
 * LibSyd: SHA1 Interface
 ***/

/* The length in bytes and in hex digits of an object name (SHA-1 value). */
#define SYD_SHA1_RAWSZ 20
#define SYD_SHA1_HEXSZ (2 * SYD_SHA1_RAWSZ + 1)
/* The block size of SHA-1. */
#define SYD_SHA1_BLKSZ 64
#define SYD_MAX_HEXSZ SYD_SHA1_HEXSZ

char *syd_hash_to_hex_r(char *buffer, const unsigned char *hash);
char *syd_hash_to_hex(const unsigned char *hash); /* static buffer result! */
int syd_hex_to_bytes(unsigned char *binary, const char *hex, size_t len);

int syd_file_to_sha1_hex(FILE *file, char *hex);
int syd_path_to_sha1_hex(const char *pathname, char *hex);

#define SYD_XXH32_BUFSZ 4
#define SYD_XXH64_BUFSZ 8
#define SYD_XXH128_BUFSZ 16
#define SYD_XXH32_HEXSZ 8
#define SYD_XXH64_HEXSZ 16
#define SYD_XXH128_HEXSZ 32

uint32_t syd_name_to_xxh32_hex(const void *restrict buffer, size_t size,
			       uint32_t seed, char *hex);
SYD_GCC_ATTR((nonnull(1,4)))
bool syd_vrfy_xxh32_hex(const void *restrict buffer, size_t size,
			uint32_t seed, const char *hex);
SYD_GCC_ATTR((nonnull(1)))
int syd_file_to_xxh32_hex(FILE *file, uint32_t *digest, char *hex);
SYD_GCC_ATTR((nonnull(1)))
int syd_path_to_xxh32_hex(const char *restrict, uint32_t *digest, char *hex);

uint64_t syd_name_to_xxh64_hex(const void *restrict buffer, size_t size,
			       uint64_t seed, char *hex);
SYD_GCC_ATTR((nonnull(1,4)))
bool syd_vrfy_xxh64_hex(const void *restrict buffer, size_t size,
			uint64_t seed, const char *hex);
SYD_GCC_ATTR((nonnull(1)))
int syd_file_to_xxh64_hex(FILE *file, uint64_t *digest, char *hex);
SYD_GCC_ATTR((nonnull(1)))
int syd_path_to_xxh64_hex(const char *restrict pathname, uint64_t *digest, char *hex);

#if 0
#TODO implement!
uint128_t syd_name_to_xxh128_hex(const char *restrict buffer, size_t size, uint128_t seed, char *hex);
int syd_file_to_xxh128_hex(FILE *file, char *hex);
int syd_path_to_xxh128_hex(FILE *file, char *hex);
#endif

#define syd_ptr_to_u64(ptr) ((__u64)((uintptr_t)(ptr)))
#define syd_str2(x) #x
#define syd_str(X) syd_str2(X)
#define syd_algo_name SYD_XXH32_HEXSZ
#define syd_seed_orig 12345698
#define syd_seed_name 19430419
#define syd_seed_uid 1000

/* ANSI colour codes */
#define SYD_ANSI_NORMAL		"[00;00m"
#define SYD_ANSI_DARK_MAGENTA	"[01;35m"
#define SYD_ANSI_MAGENTA	"[00;35m"
#define SYD_ANSI_GREEN		"[00;32m"
#define SYD_ANSI_YELLOW		"[00;33m"
#define SYD_ANSI_CYAN		"[00;36m"

/*
 * 16 is sufficient since the largest number we will ever convert
 * will be 2^32-1, which is 10 digits.
 */
#define SYD_INT_MAX 16
#define SYD_PID_MAX SYD_INT_MAX
#define SYD_PROC_MAX (sizeof("/proc/%u") + SYD_PID_MAX)
#define SYD_PROC_FD_MAX (SYD_PROC_MAX + sizeof("/fd") + SYD_PID_MAX)
#define SYD_PROC_CWD_MAX (SYD_PROC_MAX + sizeof("/cwd") + SYD_PID_MAX)
#define SYD_PROC_TASK_MAX (SYD_PROC_MAX + sizeof("/task") + SYD_PID_MAX)
#define SYD_PROC_STATUS_LINE_MAX sizeof("Tgid:") + SYD_INT_MAX + 16 /* padding */

/*
Print SydB☮x version and build details to the given FILE.
 */
int syd_about(FILE *report_fd);

/***
 * Syd's Simple Debug Logging
 ***/
int syd_vsay(const char *fmt, va_list ap)
	SYD_GCC_ATTR((format (printf, 1, 0)))
	SYD_GCC_ATTR((nonnull(1)));
int syd_say(const char *fmt, ...)
	SYD_GCC_ATTR((format (printf, 1, 2)));
int syd_say_errno(const char *fmt, ...)
	SYD_GCC_ATTR((format (printf, 1, 2)));
bool syd_debug_get(void);
void syd_debug_set(const bool val);
int syd_debug_set_fd(const int fd);
#define syd_dsay(...) do { if (syd_debug_get()) { syd_say(__VA_ARGS__); }} while (0)
#define syd_dsay_errno(...) do { if (syd_debug_get()) { syd_say_errno(__VA_ARGS__); }} while (0)

/***
 * libsyd: Stringify constants
 ***/
const char *syd_name_arch(uint32_t arch);
const char *syd_name_errno(int err_no);
int syd_name2errno(const char *errname);
const char *syd_name_namespace(int namespace);
int syd_name2signal(const char *signame);

/***
 * libsyd: Interface for Linux namespaces (containers)
 ***/
#ifndef _GNU_SOURCE
# define _GNU_SOURCE /* setns() */
#endif
#include "syd.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <linux/sched.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <grp.h>
#include <sys/mount.h>

pid_t syd_clone3(struct clone_args *args);

#define SYD_UNSHARE_FLAGS_MAX 8
static const int syd_unshare_flags[SYD_UNSHARE_FLAGS_MAX] = {
	CLONE_NEWCGROUP,
	CLONE_NEWTIME,
	CLONE_NEWIPC,
	CLONE_NEWUTS,
	CLONE_NEWNS,
	CLONE_NEWNET,
	CLONE_NEWUSER,
	CLONE_NEWPID,
};

/*
Clone & Execute a process under various restrictions and options.
 */
struct syd_exec_opt {
	const char *alias;
	const char *workdir;
	bool verbose;
	uid_t uid;
	gid_t gid;
	const char *chroot;
	const char *new_root;
	const char *put_old;
	const char *proc_mount;
	int unshare_flags;
	unsigned long propagation;
	int32_t close_fds_beg;
	int32_t close_fds_end;
	bool reset_fds;
	bool keep_sigmask;
	bool escape_stdout;
	bool allow_daemonize;
	bool make_group_leader;
	int parent_death_signal;
	const uint32_t *supplementary_gids;
	size_t supplementary_gids_length;
	const char *pid_env_var;
	int (*command)(int argc, char **argv);
};

SYD_GCC_ATTR((warn_unused_result,nonnull(1,3,4)))
int syd_execf(int (*command)(int argc, char **argv),
	      size_t argc, char **argv,
	      struct syd_exec_opt *opt);

SYD_GCC_ATTR((warn_unused_result))
int syd_execv(const char *command,
	      size_t argc, char **argv,
	      struct syd_exec_opt *opt);

/* 'private' is kernel default */
#define SYD_UNSHARE_PROPAGATION_DEFAULT  (MS_REC | MS_PRIVATE)
SYD_GCC_ATTR((warn_unused_result))
pid_t syd_clone(unsigned long long flags,
		int exit_signal,
		int *pidfd_out,
		pid_t *ptid_out,
		pid_t *ctid_out);;

enum {
	SYD_SETGROUPS_NONE = -1,
	SYD_SETGROUPS_DENY = 0,
	SYD_SETGROUPS_ALLOW = 1,
};

int syd_set_death_sig(int signal);
int syd_pivot_root(const char *new_root, const char *put_old);

/*
 * Unshare using the given file descriptors.
 */
int syd_unshare(int namespace_flags);
int syd_unshare_pid(void);
int syd_unshare_net(void);
int syd_unshare_ns(void);
int syd_unshare_uts(void);
int syd_unshare_ipc(void);
int syd_unshare_usr(void);
int syd_unshare_cgroup(void);
int syd_unshare_time(void);

int syd_setgroups_toi(const char *str);
long long syd_parse_propagation(const char *str);

int syd_setgroups_control(int action);
int syd_map_id(const char *file, uint32_t from, uint32_t to);
int syd_set_propagation(unsigned long flags);
int syd_set_ns_target(int type, const char *path);
int syd_bind_ns_files(pid_t pid);
ino_t syd_get_mnt_ino(pid_t pid);
int syd_settime(time_t offset, clockid_t clk_id);
int syd_bind_ns_files_from_child(pid_t *child, int fds[2]);

/***
 * libsyd: Utilities for EXT* File Systems
 ***/

/*
 * Inode flags
 */
#define SYD_EXT2_SECRM_FL		0x00000001 /* Secure deletion */
#define SYD_EXT2_UNRM_FL		0x00000002 /* Undelete */
#define SYD_EXT2_COMPR_FL		0x00000004 /* Compress file */
#define SYD_EXT2_SYNC_FL		0x00000008 /* Synchronous updates */
#define SYD_EXT2_IMMUTABLE_FL		0x00000010 /* Immutable file */
#define SYD_EXT2_APPEND_FL		0x00000020 /* writes to file may only append */
#define SYD_EXT2_NODUMP_FL		0x00000040 /* do not dump file */
#define SYD_EXT2_NOATIME_FL		0x00000080 /* do not update atime */
/* Reserved for compression usage... */
#define SYD_EXT2_DIRTY_FL		0x00000100
#define SYD_EXT2_COMPRBLK_FL		0x00000200 /* One or more compressed clusters */
#define SYD_EXT2_NOCOMPR_FL		0x00000400 /* Access raw compressed data */
	/* nb: was previously EXT2_ECOMPR_FL */
#define SYD_EXT4_ENCRYPT_FL		0x00000800 /* encrypted inode */
/* End compression flags --- maybe not all used */
#define SYD_EXT2_BTREE_FL		0x00001000 /* btree format dir */
#define SYD_EXT2_INDEX_FL		0x00001000 /* hash-indexed directory */
#define SYD_EXT2_IMAGIC_FL		0x00002000
#define SYD_EXT3_JOURNAL_DATA_FL	0x00004000 /* file data should be journaled */
#define SYD_EXT2_NOTAIL_FL		0x00008000 /* file tail should not be merged */
#define SYD_EXT2_DIRSYNC_FL 		0x00010000 /* Synchronous directory modifications */
#define SYD_EXT2_TOPDIR_FL		0x00020000 /* Top of directory hierarchies*/
#define SYD_EXT4_HUGE_FILE_FL		0x00040000 /* Set to each huge file */
#define SYD_EXT4_EXTENTS_FL 		0x00080000 /* Inode uses extents */
#define SYD_EXT4_VERITY_FL		0x00100000 /* Verity protected inode */
#define SYD_EXT4_EA_INODE_FL	        0x00200000 /* Inode used for large EA */
/* EXT4_EOFBLOCKS_FL 0x00400000 was here */
#define FS_NOCOW_FL			0x00800000 /* Do not cow file */
#define SYD_EXT4_SNAPFILE_FL		0x01000000  /* Inode is a snapshot */
#define FS_DAX_FL			0x02000000 /* Inode is DAX */
#define SYD_EXT4_SNAPFILE_DELETED_FL	0x04000000  /* Snapshot is being deleted */
#define SYD_EXT4_SNAPFILE_SHRUNK_FL	0x08000000  /* Snapshot shrink has completed */
#define SYD_EXT4_INLINE_DATA_FL		0x10000000 /* Inode has inline data */
#define SYD_EXT4_PROJINHERIT_FL		0x20000000 /* Create with parents projid */
#define SYD_EXT4_CASEFOLD_FL		0x40000000 /* Casefolded file */
#define SYD_EXT2_RESERVED_FL		0x80000000 /* reserved for ext2 lib */

#define SYD_EXT2_FL_USER_VISIBLE	0x604BDFFF /* User visible flags */
#define SYD_EXT2_FL_USER_MODIFIABLE	0x604B80FF /* User modifiable flags */

#define SYD_EXT2_IOC_GETFLAGS		_IOR('f', 1, long)
#define SYD_EXT2_IOC_SETFLAGS		_IOW('f', 2, long)

int syd_extfs_get_flags(int fd, unsigned long *flags);
int syd_extfs_set_flags(int fd, unsigned long flags);

int syd_extfs_get_undeletable(const char *filename, bool *undeletable);
int syd_extfs_set_undeletable(const char *filename, bool on);
int syd_extfs_get_secure_delete(const char *filename, bool *secure_delete);
int syd_extfs_set_secure_delete(const char *filename, bool on);
int syd_extfs_get_immutable(const char *filename, bool *immutable);
int syd_extfs_set_immutable(const char *filename, bool on);
int syd_extfs_get_append_only(const char *filename, bool *appendonly);
int syd_extfs_set_append_only(const char *filename, bool on);
int syd_extfs_get_compression(const char *filename, bool *compress);
int syd_extfs_set_compression(const char *filename, bool on);

/***
 * libsyd: Interface to SydB☮x Magic IPC
 ***/
int syd_ipc_api(uint8_t *api)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_check(bool *check)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_lock(void);

/* Return the hash embedded in the modification time
 * of the /dev/sydbox magic device node. This hash is
 * currently an XXH64 hash.
 */
int syd_ipc_hash(uint64_t *digest)
	SYD_GCC_ATTR((nonnull(1)));

#define SYD_IPC_STATUS_MAX 6
int syd_ipc_status(char const **status)
	SYD_GCC_ATTR((nonnull(1)));

int syd_ipc_exec_lock(void);
int syd_ipc_exec(int argc, const char *const*restrict argv)
	SYD_GCC_ATTR((nonnull(2)));
int syd_ipc_use_toolong_hack(bool on);
int syd_ipc_kill(uint8_t signum);
int syd_ipc_kill_if_match(const char *pattern, char addrem)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_set_exec(bool on);
int syd_ipc_set_read(bool on);
int syd_ipc_set_write(bool on);
int syd_ipc_set_network(bool on);
int syd_ipc_get_exec(bool *on)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_get_read(bool *on)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_get_write(bool *on)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_get_network(bool *on)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_allow_exec(const char *pattern, char addrem)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_deny_exec(const char *pattern, char addrem)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_allow_read(const char *pattern, char addrem)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_deny_read(const char *pattern, char addrem)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_allow_write(const char *pattern, char addrem)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_deny_write(const char *pattern, char addrem)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_allow_network(const char *pattern, char addrem)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_deny_network(const char *pattern, char addrem)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_filter_exec(const char *pattern, char addrem)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_filter_read(const char *pattern, char addrem)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_filter_write(const char *pattern, char addrem)
	SYD_GCC_ATTR((nonnull(1)));
int syd_ipc_filter_network(const char *pattern, char addrem)
	SYD_GCC_ATTR((nonnull(1)));

/***
 * libsyd: Interfaces to statically allocated hash tables.
 ***/
#define SYD_MAP_CLR ROBINHOOD_HASH_CLEAR
#define SYD_MAP_GET ROBINHOOD_HASH_GET
#define SYD_MAP_SET ROBINHOOD_HASH_SET
#define SYD_MAP_DEL ROBINHOOD_HASH_DEL

#if 0
/*
Execute a process under various restrictions and options.
 */
SYD_GCC_ATTR((warn_unused_result))
int32_t syd_execv(const char *command,
		size_t argc,
		const char *const *argv,
		const char *alias,
		const char *workdir,
		bool verbose SYD_GCC_ATTR((unused)),
		uint32_t uid,
		uint32_t gid,
		const char *chroot,
		const char *new_root,
		const char *put_old,
		bool unshare_pid,
		bool unshare_net,
		bool unshare_mount,
		bool unshare_uts,
		bool unshare_ipc,
		bool unshare_user,
		bool unshare_time,
		bool unshare_cgroups,
		int32_t close_fds_beg,
		int32_t close_fds_end,
		bool reset_fds,
		bool keep_sigmask,
		bool escape_stdout,
		bool allow_daemonize,
		bool make_group_leader,
		const char *parent_death_signal,
		const uint32_t *supplementary_gids,
		const char *pid_env_var)
#endif

/* TODO: Any usage of the constants above in src/ is an indication to move
 * the respective functions to syd/, mostly some leftover /proc stuff and
 * they have already been hardened to validate with seccomp request id
 * so this is not urgent.
 */

int syd_opendir(const char *dirname);
int syd_fchdir(int fd);
int syd_fstat(int fd, struct stat *buf);
int syd_fstatat(int fd, struct stat *buf, int flags);

ssize_t syd_readlink_alloc(const char *path, char **buf);

int syd_path_root_check(const char *path);
int syd_path_stat(const char *path, int mode, bool last_node, struct stat *buf);

#define SYD_REALPATH_EXIST	0 /* all components must exist */
#define SYD_REALPATH_NOLAST	1 /* all but last component must exist */
#define SYD_REALPATH_NOFOLLOW	4 /* do not dereference symbolic links */
#define SYD_REALPATH_MASK	(SYD_REALPATH_EXIST|SYD_REALPATH_NOLAST)
int syd_realpath_at(int fd, const char *pathname, char **buf, int mode);

/* SECURITY:
 * Validate these calls AFTER EACH AND EVERY
 * seccomp user notification.
 */
int syd_proc_open(pid_t pid);
int syd_proc_fd_open(pid_t pid);
int syd_proc_cwd_open(pid_t pid);

/***************************************/
/* Start of Process ID SAFE interface: *
****************************************/

int syd_proc_ppid(int pfd, pid_t *ppid);
int syd_proc_parents(int pfd, pid_t *ppid, pid_t *tgid);
int syd_proc_comm(int pfd, char *dst, size_t siz);
int syd_proc_cmdline(int pfd, char *dst, size_t siz);

int syd_proc_state(int pfd, char *state);
int syd_proc_mem_open(int pfd);
ssize_t syd_proc_mem_read(int mem_fd, off_t addr, void *buf, size_t count);
ssize_t syd_proc_mem_write(int mem_fd, off_t addr, const void *buf, size_t len);

int syd_proc_environ(int pfd);

int syd_proc_fd_path(int pfd_fd, int fd, char **dst);

int syd_proc_task_find(int pfd, pid_t task_pid);
int syd_proc_task_open(int pfd, DIR **task_dir);
int syd_proc_task_next(DIR *task_dir, pid_t *task_pid);
/********************************/
/********************************/
/********************************/

/*
 * Function for traversing all processes under /proc.
 * You really should have a good reason to use this..
 */
int syd_proc_pid_next(DIR *proc, pid_t *pid_task);

/*
 * Check value of the setting YAMA Ptrace Scope.
 */
int syd_proc_yama_ptrace_scope(uint8_t *yama_ptrace_scope);

/* Wrappers for pidfd utilities */
int syd_pidfd_open(pid_t pid, unsigned int flags);
int syd_pidfd_getfd(int pidfd, int targetfd, unsigned int flags);
/* Returns true if signal is succesfuly delivered or
 * is the process is already dead, returns false
 * otherwise. */
int syd_pidfd_send_signal(int pidfd, int sig, siginfo_t *info,
			  unsigned int flags);

bool syd_get_state(const volatile atomic_bool *state);
bool syd_set_state(volatile atomic_bool *state, bool value);
int syd_get_int(const volatile atomic_int *state);
bool syd_set_int(volatile atomic_int *state, int value);

typedef void (*syd_time_prof_func_t) (void);
struct timespec syd_time_diff(const struct timespec *t1, const struct timespec *t2);

/***
 * libsyd: Hash Table by sc_map:
 * Used transparently as syd_map.
 ***/
static inline void free_safe(void *ptr) {
	if (ptr)
		free(ptr);
}
#define sc_map_calloc calloc
#define sc_map_free free_safe
#include "sc_map.h"

/***
 * LibSyd identical interface to fit the naming convention.
 ***/
#define syd_map_dec_strkey sc_map_dec_strkey
#define syd_map_dec_scalar sc_map_dec_scalar
#define syd_map_of sc_map_of

#define syd_map_found sc_map_found
#define syd_map_oom sc_map_oom
#define syd_map_free(map) (!(map)->alloc)
#define syd_map_foreach sc_map_foreach
#define syd_map_foreach_value sc_map_foreach_value

#define syd_map_32 sc_map_32
#define syd_map_init_32 sc_map_init_32
#define syd_map_term_32 sc_map_term_32
#define syd_map_clear_32 sc_map_clear_32
#define syd_map_put_32 sc_map_put_32
#define syd_map_get_32 sc_map_get_32
#define syd_map_del_32 sc_map_del_32
#define syd_map_size_32 sc_map_size_32

#define syd_map_64 sc_map_64
#define syd_map_init_64 sc_map_init_64
#define syd_map_term_64 sc_map_term_64
#define syd_map_clear_64 sc_map_clear_64
#define syd_map_put_64 sc_map_put_64
#define syd_map_get_64 sc_map_get_64
#define syd_map_del_64 sc_map_del_64
#define syd_map_size_64 sc_map_size_64

#define syd_map_64v sc_map_64v
#define syd_map_init_64v sc_map_init_64v
#define syd_map_term_64v sc_map_term_64v
#define syd_map_clear_64v sc_map_clear_64v
#define syd_map_put_64v sc_map_put_64v
#define syd_map_get_64v sc_map_get_64v
#define syd_map_del_64v sc_map_del_64v
#define syd_map_size_64v sc_map_size_64v

#define syd_map_64s sc_map_64s
#define syd_map_init_64s sc_map_init_64s
#define syd_map_term_64s sc_map_term_64s
#define syd_map_clear_64s sc_map_clear_64s
#define syd_map_put_64s sc_map_put_64s
#define syd_map_get_64s sc_map_get_64s
#define syd_map_del_64s sc_map_del_64s
#define syd_map_size_64s sc_map_size_64s

#define syd_map_str sc_map_str
#define syd_map_init_str sc_map_init_str
#define syd_map_term_str sc_map_term_str
#define syd_map_clear_str sc_map_clear_str
#define syd_map_put_str sc_map_put_str
#define syd_map_get_str sc_map_get_str
#define syd_map_del_str sc_map_del_str
#define syd_map_size_str sc_map_size_str

#define syd_map_sv sc_map_sv
#define syd_map_init_sv sc_map_init_sv
#define syd_map_term_sv sc_map_term_sv
#define syd_map_clear_sv sc_map_clear_sv
#define syd_map_put_sv sc_map_put_sv
#define syd_map_get_sv sc_map_get_sv
#define syd_map_del_sv sc_map_del_sv
#define syd_map_size_sv sc_map_size_sv

#define syd_map_s64 sc_map_s64
#define syd_map_init_s64 sc_map_init_s64
#define syd_map_term_s64 sc_map_term_s64
#define syd_map_clear_s64 sc_map_clear_s64
#define syd_map_put_s64 sc_map_put_s64
#define syd_map_get_s64 sc_map_get_s64
#define syd_map_del_s64 sc_map_del_s64
#define syd_map_size_s64 sc_map_size_s64

#if !defined(SPARSE) && defined(__GNUC__) && __GNUC__ >= 3
__attribute__((sentinel))
#endif
void syd_time_prof(unsigned loop, ...);

#if !defined(SPARSE) &&\
	defined(__GNUC__) && __GNUC__ >= 4 && \
	defined(__GNUC_MINOR__) && __GNUC_MINOR__ > 5
#define assert_unreachable	__builtin_unreachable()
#else
#include <assert.h>
#ifdef NDEBUG
#undef NDEBUG
#endif
#define assert_unreachable	assert(0);
#endif

/***
 * Syd's String Functions
 ***/
size_t syd_strlcat(char *restrict dst, const char *restrict src, size_t siz);
size_t syd_strlcpy(char *restrict dst, const char *restrict src, size_t siz);

int syd_str_startswith(const char *s, const char *prefix, bool *ret_bool);

/***
 * Syd's UTF-8 Functions
 ***/
bool syd_utf8_nul(int c);
bool syd_utf8_valid(int c);
int syd_utf8_safe(const char *restrict p, size_t length, char **res)
	SYD_GCC_ATTR((nonnull(1,3)));

/***
 * Syd's Path Names for Linux Systems
 ***/
#include <paths.h>

/* used by kernel in /proc (e.g. /proc/swaps) for deleted files */
#define SYD_PATH_DELETED_SUFFIX	" (deleted)"

/* DEFPATHs from <paths.h> don't include /usr/local */
#undef _PATH_DEFPATH

#ifdef USE_USRDIR_PATHS_ONLY
# define SYD_PATH_DEFPATH	        "/usr/local/bin:/usr/bin"
#else
# define SYD_PATH_DEFPATH	        "/usr/local/bin:/bin:/usr/bin"
#endif

#undef _PATH_DEFPATH_ROOT

#ifdef USE_USRDIR_PATHS_ONLY
# define SYD_PATH_DEFPATH_ROOT	"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
#else
# define SYD_PATH_DEFPATH_ROOT	"/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin"
#endif

#define SYD_PATH_HUSHLOGIN	".hushlogin"
#define SYD_PATH_HUSHLOGINS	"/etc/hushlogins"

#define SYD_PATH_NOLOGIN_TXT	"/etc/nologin.txt"

# define SYD_PATH_MAILDIR	"/var/spool/mail"
#define SYD_PATH_MOTDFILE	"/usr/share/misc/motd:/run/motd:/etc/motd"
# define SYD_PATH_NOLOGIN	"/etc/nologin"
#define SYD_PATH_VAR_NOLOGIN	"/var/run/nologin"

#define SYD_PATH_LOGIN		"/bin/login"
#define SYD_PATH_SHUTDOWN	"/sbin/shutdown"
#define SYD_PATH_POWEROFF	"/sbin/poweroff"

#define SYD_PATH_TERMCOLORS_DIRNAME "terminal-colors.d"
#define SYD_PATH_TERMCOLORS_DIR	"/etc/" _PATH_TERMCOLORS_DIRNAME

/* login paths */
#define SYD_PATH_PASSWD		"/etc/passwd"
#define SYD_PATH_GSHADOW	"/etc/gshadow"
#define SYD_PATH_GROUP		"/etc/group"
#define SYD_PATH_SHADOW_PASSWD	"/etc/shadow"
#define SYD_PATH_SHELLS		"/etc/shells"

#ifdef _PATH_TMP
# define SYD_PATH_TMP	_PATH_TMP
#else
# define SYD_PATH_TMP	"/tmp/"
#endif

#ifdef _PATH_BTMP
# define SYD_PATH_BTMP		_PATH_BTMP
# else
# define SYD_PATH_BTMP		"/var/log/btmp"
#endif

#define SYD_PATH_ISSUE_FILENAME	"issue"
#define SYD_PATH_ISSUE_DIRNAME	_PATH_ISSUE_FILENAME ".d"

#define SYD_PATH_ISSUE		"/etc/" _PATH_ISSUE_FILENAME
#define SYD_PATH_ISSUEDIR	"/etc/" _PATH_ISSUE_DIRNAME

#define SYD_PATH_OS_RELEASE_ETC	"/etc/os-release"
#define SYD_PATH_OS_RELEASE_USR	"/usr/lib/os-release"
#define SYD_PATH_NUMLOCK_ON	_PATH_RUNSTATEDIR "/numlock-on"
#define SYD_PATH_LOGINDEFS	"/etc/login.defs"

/* misc paths */
#define SYD_PATH_WORDS             "/usr/share/dict/words"
#define SYD_PATH_WORDS_ALT         "/usr/share/dict/web2"

/* mount paths */
#define SYD_PATH_FILESYSTEMS	"/etc/filesystems"
#define SYD_PATH_PROC_SWAPS	"/proc/swaps"
#define SYD_PATH_PROC_FILESYSTEMS	"/proc/filesystems"
#define SYD_PATH_PROC_MOUNTS	"/proc/mounts"
#define SYD_PATH_PROC_PARTITIONS	"/proc/partitions"
#define SYD_PATH_PROC_DEVICES	"/proc/devices"
#define SYD_PATH_PROC_MOUNTINFO	"/proc/self/mountinfo"
#define SYD_PATH_PROC_LOCKS        "/proc/locks"
#define SYD_PATH_PROC_CDROMINFO	"/proc/sys/dev/cdrom/info"

#define SYD_PATH_PROC_UIDMAP	"/proc/self/uid_map"
#define SYD_PATH_PROC_GIDMAP	"/proc/self/gid_map"
#define SYD_PATH_PROC_SETGROUPS	"/proc/self/setgroups"

#define SYD_PATH_PROC_FDDIR	"/proc/self/fd"

#define SYD_PATH_PROC_ATTR_CURRENT	"/proc/self/attr/current"
#define SYD_PATH_PROC_ATTR_EXEC	"/proc/self/attr/exec"
#define SYD_PATH_PROC_CAPLASTCAP	"/proc/sys/kernel/cap_last_cap"


#define SYD_PATH_SYS_BLOCK	"/sys/block"
#define SYD_PATH_SYS_DEVBLOCK	"/sys/dev/block"
#define SYD_PATH_SYS_DEVCHAR	"/sys/dev/char"
#define SYD_PATH_SYS_CLASS	"/sys/class"
#define SYD_PATH_SYS_SCSI	"/sys/bus/scsi"

#define SYD_PATH_SYS_SELINUX	"/sys/fs/selinux"
#define SYD_PATH_SYS_APPARMOR	"/sys/kernel/security/apparmor"

#ifdef _PATH_MOUNTED
# ifdef MOUNTED			/* deprecated */
#  define SYD_PATH_MOUNTED	MOUNTED
# else
#  define SYD_PATH_MOUNTED	_PATH_MOUNTED
# endif
#else
# define SYD_PATH_MOUNTED	"/etc/mtab"
#endif

# ifdef MNTTAB			/* deprecated */
#  define SYD_PATH_MNTTAB	MNTTAB
# elif defined(_PATH_MNTTAB)
#  define SYD_PATH_MNTTAB	_PATH_MNTTAB
# else
#  define SYD_PATH_MNTTAB	"/etc/fstab"
#endif

#ifdef _PATH_DEV
  /*
   * The tailing '/' in _PATH_DEV is there for compatibility with libc.
   */
# define SYD_PATH_DEV	_PATH_DEV
#else
# define SYD_PATH_DEV	"/dev/"
#endif

#define SYD_PATH_DEV_MAPPER	"/dev/mapper"

#define SYD_PATH_DEV_MEM	"/dev/mem"

#define SYD_PATH_DEV_LOOP	"/dev/loop"
#define SYD_PATH_DEV_LOOPCTL	"/dev/loop-control"

/* udev paths */
#define SYD_PATH_DEV_BYLABEL	"/dev/disk/by-label"
#define SYD_PATH_DEV_BYUUID	"/dev/disk/by-uuid"
#define SYD_PATH_DEV_BYID	"/dev/disk/by-id"
#define SYD_PATH_DEV_BYPATH	"/dev/disk/by-path"
#define SYD_PATH_DEV_BYPARTLABEL	"/dev/disk/by-partlabel"
#define SYD_PATH_DEV_BYPARTUUID	"/dev/disk/by-partuuid"

/* hwclock paths */
#ifdef CONFIG_ADJTIME_PATH
# define SYD_PATH_ADJTIME	CONFIG_ADJTIME_PATH
#else
# define SYD_PATH_ADJTIME	"/etc/adjtime"
#endif

#ifdef __ia64__
# define SYD_PATH_RTC_DEV	"/dev/efirtc"
#else
# define SYD_PATH_RTC_DEV	"/dev/rtc0"
#endif

/* raw paths*/
#define SYD_PATH_RAWDEVDIR	"/dev/raw/"
#define SYD_PATH_RAWDEVCTL	_PATH_RAWDEVDIR "rawctl"
/* deprecated */
#define SYD_PATH_RAWDEVCTL_OLD	"/dev/rawctl"

#define SYD_PATH_PROC_KERNEL	"/proc/sys/kernel"

/* ipc paths */
#define SYD_PATH_PROC_SYSV_MSG	"/proc/sysvipc/msg"
#define SYD_PATH_PROC_SYSV_SEM	"/proc/sysvipc/sem"
#define SYD_PATH_PROC_SYSV_SHM	"/proc/sysvipc/shm"
#define SYD_PATH_PROC_IPC_MSGMAX	SYD_PATH_PROC_KERNEL "/msgmax"
#define SYD_PATH_PROC_IPC_MSGMNB	SYD_PATH_PROC_KERNEL "/msgmnb"
#define SYD_PATH_PROC_IPC_MSGMNI	_PATH_PROC_KERNEL "/msgmni"
#define SYD_PATH_PROC_IPC_SEM		_PATH_PROC_KERNEL "/sem"
#define SYD_PATH_PROC_IPC_SHMALL	_PATH_PROC_KERNEL "/shmall"
#define SYD_PATH_PROC_IPC_SHMMAX	_PATH_PROC_KERNEL "/shmmax"
#define SYD_PATH_PROC_IPC_SHMMNI	_PATH_PROC_KERNEL "/shmmni"

/* util clamp */
#define SYD_PATH_PROC_UCLAMP_MIN	_PATH_PROC_KERNEL "/sched_util_clamp_min"
#define SYD_PATH_PROC_UCLAMP_MAX	_PATH_PROC_KERNEL "/sched_util_clamp_max"

/* irqtop paths */
#define SYD_PATH_PROC_INTERRUPTS	"/proc/interrupts"
#define SYD_PATH_PROC_SOFTIRQS		"/proc/softirqs"
#define SYD_PATH_PROC_UPTIME		"/proc/uptime"

/* kernel command line */
#define SYD_PATH_PROC_CMDLINE	"/proc/cmdline"

/* logger paths */
#define SYD_PATH_DEVLOG		"/dev/log"

/* ctrlaltdel paths */
#define SYD_PATH_PROC_CTRL_ALT_DEL	"/proc/sys/kernel/ctrl-alt-del"

/* lscpu paths */
#define SYD_PATH_PROC_CPUINFO	"/proc/cpuinfo"

/* rfkill paths */
#define SYD_PATH_DEV_RFKILL	"/dev/rfkill"
#define SYD_PATH_SYS_RFKILL	"/sys/class/rfkill"

#endif
