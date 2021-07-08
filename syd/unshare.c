/*
 * libsyd/unshare.c
 *
 * libsyd: Interface for Linux namespaces (containers)
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 *
 * Based in part upon util-linux' unshare which is:
 *   Copyright (C) 2009 Mikhail Gusarov <dottedmag@dottedmag.net>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "config.h"
#include <syd/syd.h>

/***
 * Preparation for import from unshare.c
 ***/
#include "all-io.h"
#define _PATH_PROC_SETGROUPS	"/proc/self/setgroups"

/***
 * START IMPORT from unshare.c
 * TODO: Write tests for these functions!
 ***/
/* synchronize parent and child by pipe */
#define PIPE_SYNC_BYTE	0x06

/* 'private' is kernel default */
#define UNSHARE_PROPAGATION_DEFAULT	(MS_REC | MS_PRIVATE)

/* /proc namespace files and mountpoints for binds */
static struct namespace_file {
	int		type;		/* CLONE_NEW* */
	const char	*name;		/* ns/<type> */
	const char	*target;	/* user specified target for bind mount */
} namespace_files[] = {
	{ .type = CLONE_NEWUSER,  .name = "ns/user" },
	{ .type = CLONE_NEWCGROUP,.name = "ns/cgroup" },
	{ .type = CLONE_NEWIPC,   .name = "ns/ipc"  },
	{ .type = CLONE_NEWUTS,   .name = "ns/uts"  },
	{ .type = CLONE_NEWNET,   .name = "ns/net"  },
	{ .type = CLONE_NEWPID,   .name = "ns/pid_for_children" },
	{ .type = CLONE_NEWNS,    .name = "ns/mnt"  },
	{ .type = CLONE_NEWTIME,  .name = "ns/time_for_children" },
	{ .name = NULL }
};

static int npersists;	/* number of persistent namespaces */

int syd_setgroups_toi(const char *str)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(setgroups_strings); i++)
		if (strcmp(str, setgroups_strings[i]) == 0)
			return i;

	syd_dsay("unsupported --setgroups argument '%s'", str);
	return -EINVAL;
}

int syd_setgroups_control(int action)
{
	const char *file = _PATH_PROC_SETGROUPS;
	const char *cmd;
	int fd;

	if (action < 0 || (size_t) action >= ARRAY_SIZE(setgroups_strings))
		return -EINVAL;
	cmd = setgroups_strings[action];

	fd = open(file, O_WRONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			return -ENOENT;
		int save_errno = errno;
		syd_dsay("cannot open `%s'", file);
		return -save_errno;
	}

	int r = 0;
	if (write_all(fd, cmd, strlen(cmd))) {
		r = -errno;
		syd_say("write failed `%s'", file);
	}
	close(fd);
	return r;
}

int syd_map_id(const char *file, uint32_t from, uint32_t to)
{
	char *buf;
	int fd;

	fd = open(file, O_WRONLY);
	if (fd < 0) {
		syd_dsay("cannot open `%s'", file);
		return -errno;
	}

	if (asprintf(&buf, "%u %u 1", from, to) < 0) {
		close(fd);
		return -ENOMEM;
	}
	int r = 0;
	if (write_all(fd, buf, strlen(buf))) {
		r = -errno;
		syd_dsay("write failed `%s'", file);
	}
	free(buf);
	close(fd);
	return r;
}

long long syd_parse_propagation(const char *str)
{
	size_t i;
	static const struct prop_opts {
		const char *name;
		unsigned long flag;
	} opts[] = {
		{ "slave",	MS_REC | MS_SLAVE },
		{ "private",	MS_REC | MS_PRIVATE },
		{ "shared",     MS_REC | MS_SHARED },
		{ "unchanged",        0 }
	};

	for (i = 0; i < ARRAY_SIZE(opts); i++) {
		if (strcmp(opts[i].name, str) == 0)
			return opts[i].flag;
	}

	syd_dsay("unsupported propagation mode: %s", str);
	return -ENOTSUP;
}

int syd_set_propagation(unsigned long flags)
{
	if (flags == 0)
		return 0;

	if (mount("none", "/", NULL, flags, NULL) != 0) {
		int r = -errno;
		syd_dsay("cannot change root filesystem propagation");
		return r;
	}

	return 0;
}


int set_ns_target(int type, const char *path)
{
	struct namespace_file *ns;

	for (ns = namespace_files; ns->name; ns++) {
		if (ns->type != type)
			continue;
		ns->target = path;
		npersists++;
		return 0;
	}

	return -EINVAL;
}

int syd_bind_ns_files(pid_t pid)
{
	struct namespace_file *ns;
	char src[PATH_MAX];

	int r = 0;
	for (ns = namespace_files; ns->name; ns++) {
		if (!ns->target)
			continue;

		snprintf(src, sizeof(src), "/proc/%u/%s", (unsigned) pid, ns->name);

		if (mount(src, ns->target, NULL, MS_BIND, NULL) != 0) {
			r = -errno;
			syd_dsay("mount `%s' on `%s' failed", src, ns->target);
		}
	}

	return r;
}

ino_t syd_get_mnt_ino(pid_t pid)
{
	struct stat st;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/proc/%u/ns/mnt", (unsigned) pid);

	if (stat(path, &st) != 0) {
		int r = -errno;
		syd_dsay("stat of `%s' failed", path);
		return r;
	}
	return st.st_ino;
}

int syd_settime(time_t offset, clockid_t clk_id)
{
	char buf[sizeof(stringify_value(ULONG_MAX)) * 3];
	int fd, len;

	len = snprintf(buf, sizeof(buf), "%d %ld 0", clk_id, offset);

	int r = 0;
	fd = open("/proc/self/timens_offsets", O_WRONLY);
	if (fd < 0) {
		r = -errno;
		syd_dsay("failed to open /proc/self/timens_offsets");
		return r;
	}

	if (write(fd, buf, len) != len) {
		r = -errno;
		syd_dsay("failed to write to /proc/self/timens_offsets");
	}

	close(fd);

	return r;
}

int syd_bind_ns_files_from_child(pid_t *child, int fds[2])
{
	int r = 0;
	char ch;
	pid_t ppid = getpid();

	ino_t ino = syd_get_mnt_ino(ppid);
	if (ino < 0)
		return ino;

	if (pipe(fds) < 0) {
		r = -errno;
		syd_dsay_errno("pipe failed");
		return r;
	}

	*child = fork();

	switch (*child) {
	case -1:
		r = -errno;
		syd_dsay_errno("fork failed");
		return r;

	case 0:	/* child */
		close(fds[1]);
		fds[1] = -1;

		/* wait for parent */
		if (read_all(fds[0], &ch, 1) != 1 && ch != PIPE_SYNC_BYTE) {
			r = errno;
			syd_dsay_errno("failed to read pipe");
			_exit(r);
		}
		if (syd_get_mnt_ino(ppid) == ino)
			exit(EXIT_FAILURE);
		syd_bind_ns_files(ppid);
		exit(EXIT_SUCCESS);
		break;

	default: /* parent */
		close(fds[0]);
		fds[0] = -1;
		break;
	}

	return 0;
}

#if 0
static uid_t get_user(const char *s, const char *err)
{
	struct passwd *pw;
	char *buf = NULL;
	uid_t ret;

	pw = xgetpwnam(s, &buf);
	if (pw) {
		ret = pw->pw_uid;
		free(pw);
		free(buf);
	} else {
		ret = strtoul_or_err(s, err);
	}

	return ret;
}

static gid_t get_group(const char *s, const char *err)
{
	struct group *gr;
	char *buf = NULL;
	gid_t ret;

	gr = xgetgrnam(s, &buf);
	if (gr) {
		ret = gr->gr_gid;
		free(gr);
		free(buf);
	} else {
		ret = strtoul_or_err(s, err);
	}

	return ret;
}
#endif


/***
 * END OF IMPORT FROM unshare.c
 ***/

int syd_unshare(int namespace_type, int fd_closing)
{
	if (fd_closing <= 0)
		return -EBADF;
	syd_dsay("Unsharing %s namespace.",
		syd_name_namespace(namespace_type));
	if (setns(fd_closing, namespace_type) < 0)
		return -errno;
	return 0;
}

int syd_unshare_pid(int fd)
{
	return syd_unshare(CLONE_NEWPID, fd);
}

int syd_unshare_net(int fd)
{
	return syd_unshare(CLONE_NEWNET, fd);
}

int syd_unshare_ns(int fd)
{
	return syd_unshare(CLONE_NEWNS, fd);
}

int syd_unshare_uts(int fd)
{
	return syd_unshare(CLONE_NEWUTS, fd);
}

int syd_unshare_ipc(int fd)
{
	return syd_unshare(CLONE_NEWIPC, fd);
}

int syd_unshare_usr(int fd)
{
	return syd_unshare(CLONE_NEWUSER, fd);
}

int syd_set_death_sig(int signal)
{
	return prctl(PR_SET_PDEATHSIG, signal, 0, 0, 0) < 0 ? -errno: 0;
}

int syd_pivot_root(const char *new_root, const char *put_old)
{
	if (!new_root || !*new_root)
		return -EINVAL;
	if (!put_old || !*put_old)
		return -EINVAL;
	if (syd_debug_get()) {
		int r;
		bool ok = false;
		if ((r = syd_str_startswith(put_old, new_root, &ok)) < 0)
			return -r;
		if (!ok) {
			syd_say("The new_root is not a prefix of put old");
			return -EINVAL;
		}
	} /* else pivot_root will return EINVAL if prefix check fails. */
	if (syscall(SYS_pivot_root, new_root, put_old) < 0)
		return -errno;
	return 0;
}
