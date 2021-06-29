/*
 * syd.h -- Syd's utility library
 *
 * Copyright (c) 2014, 2015, 2016 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the GNU General Public License v3 (or later)
 */

#ifndef LIBSYD_SYD_H
#define LIBSYD_SYD_H 1

#ifndef _XOPEN_SOURCE
# define _XOPEN_SOURCE 700
#endif

#ifdef __STDC_NO_ATOMICS__
# error this implementation needs atomics
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <stdatomic.h>
#include <stdbool.h>
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
/* TODO: Any usage of the constants above in src/ is an indication to move
 * the respective functions to syd/, mostly some leftover /proc stuff and
 * they have already been hardened to validate with seccomp request id
 * so this is not urgent.
 */

size_t syd_strlcat(char *dst, const char *src, size_t siz);
size_t syd_strlcpy(char *dst, const char *src, size_t siz);

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

#endif
