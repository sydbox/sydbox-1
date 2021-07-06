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

#include <syd/compiler.h>

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
const char *syd_name_errno(int err_no);
const char *syd_name_namespace(int namespace);

/***
 * libsyd: Interface for Linux namespaces (containers)
 ***/
int syd_set_death_sig(int signal);
int syd_pivot_root(const char *new_root, const char *put_old);

/*
 * Unshare using the given file descriptors.
 */
int syd_unshare_pid(int fd);
int syd_unshare_net(int fd);
int syd_unshare_ns(int fd);
int syd_unshare_uts(int fd);
int syd_unshare_ipc(int fd);
int syd_unshare_usr(int fd);

int syd_setgroups_control(int action);
int syd_map_id(const char *file, uint32_t from, uint32_t to);
int syd_set_propagation(unsigned long flags);
int syd_set_ns_target(int type, const char *path);
int syd_bind_ns_files(pid_t pid);
ino_t syd_get_mnt_ino(pid_t pid);
int syd_settime(time_t offset, clockid_t clk_id);
int syd_bind_ns_files_from_child(pid_t *child, int fds[2]);


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
                  bool _verbose,
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
                  int32_t close_fds_beg,
                  int32_t close_fds_end,
                  bool reset_fds,
                  bool keep_sigmask,
                  bool escape_stdout,
                  bool allow_daemonize,
                  bool make_group_leader,
                  const char *parent_death_signal,
                  const uint32_t *supplementary_gids,
                  const char *pid_env_var);
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

#define syd_map_32 sc_map_32
#define syd_map_init_32 sc_map_init_32
#define syd_map_term_32 sc_map_term_32
#define syd_map_clear_32 sc_map_clear_32
#define syd_map_put_32 sc_map_put_32
#define syd_map_get_32 sc_map_get_32
#define syd_map_del_32 sc_map_del_32

#define syd_map_64 sc_map_64
#define syd_map_init_64 sc_map_init_64
#define syd_map_term_64 sc_map_term_64
#define syd_map_clear_64 sc_map_clear_64
#define syd_map_put_64 sc_map_put_64
#define syd_map_get_64 sc_map_get_64
#define syd_map_del_64 sc_map_del_64

#define syd_map_64v sc_map_64v
#define syd_map_init_64v sc_map_init_64v
#define syd_map_term_64v sc_map_term_64v
#define syd_map_clear_64v sc_map_clear_64v
#define syd_map_put_64v sc_map_put_64v
#define syd_map_get_64v sc_map_get_64v
#define syd_map_del_64v sc_map_del_64v

#define syd_map_64s sc_map_64s
#define syd_map_init_64s sc_map_init_64s
#define syd_map_term_64s sc_map_term_64s
#define syd_map_clear_64s sc_map_clear_64s
#define syd_map_put_64s sc_map_put_64s
#define syd_map_get_64s sc_map_get_64s
#define syd_map_del_64s sc_map_del_64s

#define syd_map_str sc_map_str
#define syd_map_init_str sc_map_init_str
#define syd_map_term_str sc_map_term_str
#define syd_map_clear_str sc_map_clear_str
#define syd_map_put_str sc_map_put_str
#define syd_map_get_str sc_map_get_str
#define syd_map_del_str sc_map_del_str

#define syd_map_sv sc_map_sv
#define syd_map_init_sv sc_map_init_sv
#define syd_map_term_sv sc_map_term_sv
#define syd_map_clear_sv sc_map_clear_sv
#define syd_map_put_sv sc_map_put_sv
#define syd_map_get_sv sc_map_get_sv
#define syd_map_del_sv sc_map_del_sv

#define syd_map_s64 sc_map_s64
#define syd_map_init_s64 sc_map_init_s64
#define syd_map_term_s64 sc_map_term_s64
#define syd_map_clear_s64 sc_map_clear_s64
#define syd_map_put_s64 sc_map_put_s64
#define syd_map_get_s64 sc_map_get_s64
#define syd_map_del_s64 sc_map_del_s64

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

inline int syd_str_startswith(const char *s, const char *prefix,
			      bool ret_bool)
{
	size_t sl, pl;

	if (!s)
		return -EINVAL;
	if (!prefix)
		return -EINVAL;

	sl = strlen(s);
	pl = strlen(prefix);

	if (pl == 0)
		return true;

	if (sl < pl)
		return false;

	return memcmp(s, prefix, pl) == 0;
}

#endif
