/*
 * sydbox/daemon.c
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon openrc/src/rc/start-stop-daemon.c which is
 *   Copyright (c) 2007-2015 The OpenRC Authors.
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "syd-box.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>

static bool background;
static const char *redirect_stdout;
static const char *redirect_stderr;

static uid_t uid = -1;
static gid_t gid = -1;
#define GID_ADD_MAX 32
static size_t gid_add_index;
static gid_t gid_add[GID_ADD_MAX];
static int nice_inc;
static int ionicec = -1, ioniced = 0;
static mode_t file_mode_creation_mask = 077;
static const char *root_directory;
static const char *working_directory;
static char *pid_env_var;
static const char *arg0;
static char *pivot_new_root;
static char *pivot_put_old;

bool get_background(void) { return background; }
const char *get_redirect_stdout(void) { return redirect_stdout; }
const char *get_redirect_stderr(void) { return redirect_stderr; }
uid_t get_uid(void) { return uid ; }
gid_t get_gid(void) { return gid ; }
int get_nice(void) { return nice_inc; }
const char *get_arg0(void) { return arg0; }
const char *get_root_directory(void) { return root_directory; }
const char *get_working_directory(void) { return working_directory; }
const char *get_pid_env_var(void) { return pid_env_var; }
mode_t get_umask(void) { return file_mode_creation_mask; }
const gid_t *get_groups(void) { return gid_add_index ? gid_add : NULL; }
size_t get_groups_length(void) { return gid_add_index; }

void get_pivot_root(char **new_root, char **put_old)
{
	assert(new_root);
	assert(put_old);

	*new_root = pivot_new_root;
	*put_old = pivot_put_old;
}

void set_background(bool bg) { background = bg; }
void set_redirect_stdout(const char *log) { redirect_stdout = log; }
void set_redirect_stderr(const char *log) { redirect_stderr = log; }
void set_uid(uid_t new_uid) { uid = new_uid; }
void set_gid(gid_t new_gid) { gid = new_gid; }
void set_groups(gid_t new_gid) {
	if (gid_add_index >= GID_ADD_MAX)
		return;
	gid_add[gid_add_index++] = new_gid;
}
void set_nice(int new_nice) { nice_inc = new_nice; }
void set_arg0(const char *new_arg0) { arg0 = new_arg0; }
void set_root_directory(const char *root) { root_directory = root; }
void set_working_directory(char *wd) {
	if (streq(wd, "tmp")) {
		char *tmpl, *linkpath;
		xasprintf(&tmpl, "/tmp/syd-%u-%u-%u-XXXXXX",
			  SYDBOX_API_VERSION, getuid(), getpid());
		free(wd);
		wd = xstrdup(mkdtemp(tmpl));
		xasprintf(&linkpath, "%s/sydbox", wd);
		if (symlink("/dev/sydbox", linkpath) < 0 && syd_debug_get())
			syd_say("Failed to create symbolic link »/dev/sydbox« -> `%s'",
				linkpath);
		free(linkpath);
		free(tmpl);
	}
	working_directory = wd;
}

void set_pid_env_var(const char *var)
{
	if (pid_env_var)
		free(pid_env_var);
	pid_env_var = xstrdup(var);
}

void set_umask(mode_t mode) { file_mode_creation_mask = mode; }

void set_ionice(int c, int d)
{
	if (c == 0)
		d = 0;
	else if (c == 3)
		d = 7;
	c <<= 13; /* class shift */
	ionicec = c;
	ioniced = d;
}

int set_username(const char *name)
{
#if 0
#error can not static link
	struct passwd *p = getpwnam(name);
	if (p) {
		uid = p->pw_uid;
		return 0;
	}
	return -errno;
#endif
	return 0;
}

int set_groupname(const char *name)
{
#if 0
#error can not static link
	struct group *group = getgrnam(name);
	if (group) {
		gid = group->gr_gid;
		return 0;
	}
	return -errno;
#endif
	return 0;
}

void set_pivot_root(const char *new_root, const char *put_old)
{
	if (pivot_new_root)
		free(pivot_new_root);
	pivot_new_root = NULL;
	if (pivot_put_old)
		free(pivot_put_old);
	pivot_put_old = NULL;

	if (new_root)
		pivot_new_root = xstrdup(new_root);
	if (put_old)
		pivot_put_old = xstrdup(put_old);
}

int change_umask(void)
{
	if (!file_mode_creation_mask)
		return 0;
	errno = 0;
	umask(file_mode_creation_mask);
	return -errno;
}

int change_user(void)
{
	if (!uid)
		return 0;
	errno = 0;
	int r_unused SYD_GCC_ATTR((unused));
	r_unused = setuid(uid);
	return -errno;
}

int change_group(void)
{
	if (!gid)
		return 0;
	errno = 0;
	int r_unused SYD_GCC_ATTR((unused));
	r_unused = setgid(gid);
	return -errno;
}

int change_root_directory(void)
{
	if (!root_directory)
		return 0;
	errno = 0;
	if (chroot(root_directory) == -1)
		return -errno;
	errno = 0;
	int r_unused SYD_GCC_ATTR((unused));
	r_unused = chdir("/");
	return -errno;
}

int change_working_directory(void)
{
	if (!working_directory)
		return 0;
	errno = 0;
	int r_unused SYD_GCC_ATTR((unused));
	r_unused = chdir(working_directory);
	return -errno;
}

int change_background(void)
{
	int devnull_fd = -1;
	int tty_fd = -1;

	if (background) {
		devnull_fd = open("/dev/null", O_RDWR);
		if (devnull_fd < 0)
			return -errno;
#ifdef TIOCNOTTY
		tty_fd = open("/dev/tty", O_RDWR);
		if (tty_fd < 0)
			say_errno("open(»/dev/tty«)");
#endif
	}

#ifdef TIOCNOTTY
	if (background && tty_fd >= 0) {
		if (ioctl(tty_fd, TIOCNOTTY, 0) < 0)
			say_errno("ioctl");
		if (close(tty_fd) < 0)
			say_errno("close(»/dev/tty«)");
	}
#endif

	int r = 0;
	int stdin_fd = devnull_fd;
	int stdout_fd = devnull_fd;
	int stderr_fd = devnull_fd;

	if (redirect_stdout &&
	    (stdout_fd = open(redirect_stdout, O_WRONLY | O_CREAT | O_APPEND,
			      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)) < 0) {
		r = -errno;
		goto out;
	}
	if (redirect_stderr &&
	    (stderr_fd = open(redirect_stderr, O_WRONLY | O_CREAT | O_APPEND,
			      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)) < 0) {
		r = -errno;
		goto out;
	}

	if (background && dup2(stdin_fd, STDIN_FILENO) < 0) {
		r = -errno;
		goto out;
	}
	if ((background || redirect_stdout) && dup2(stdout_fd, STDOUT_FILENO) < 0) {
		r = -errno;
		goto out;
	}
	if ((background || redirect_stderr) && dup2(stderr_fd, STDERR_FILENO) < 0)
		r = -errno;

out:
	if (devnull_fd >= 0)
		close(devnull_fd);
	if (stdin_fd >= 0 && stdin_fd != devnull_fd)
		close(stdin_fd);
	if (stderr_fd >= 0 && stderr_fd != devnull_fd)
		close(stderr_fd);
	if (stdout_fd >= 0 && stdout_fd != devnull_fd)
		close(stdout_fd);
	if (r)
		return r;
	if (!background)
		return 0;
	errno = 0;
	setsid();
	return -errno;
}

int change_nice(void)
{
	if (!nice_inc)
		return 0;
	errno = 0;
	int r_unused SYD_GCC_ATTR((unused));
	r_unused = nice(nice_inc);
	return -errno;
}

int change_ionice(void)
{
	if (ionicec == -1)
		return 0;
	errno = 0;
	syscall(__NR_ioprio_set, 1, getpid(), ionicec | ioniced);
	return -errno;
}
