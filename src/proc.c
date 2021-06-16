/*
 * sydbox/proc.c
 *
 * /proc related utilities
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is:
 *   Copyright (C) 2010 Lennart Poettering
 * Distributed under the terms of the GNU Lesser General Public License v2.1 or later
 */

#include "sydconf.h"
#include "proc.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

#include "file.h"
#include "util.h"
#include "toolong.h"

/* Useful macros */
#ifndef MAX
#define MAX(a,b)	(((a) > (b)) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b)	(((a) < (b)) ? (a) : (b))
#endif

static char *proc_deleted(const char *path)
{
	char *r;
	struct stat s;

	/* If the current working directory of a process is removed after the
	 * process is started, /proc/$pid/cwd is a dangling symbolic link and
	 * points to "/path/to/current/working/directory (deleted)".
	 */
	r = strstr(path, " (deleted)");
	if (!r)
		return NULL;
	if (r[sizeof(" (deleted)") - 1] != '\0')
		return NULL;
	if (stat(path, &s) == 0 || errno != ENOENT)
		return NULL;
	return r;
}

/*
 * resolve /proc/$pid/cwd
 */
int proc_cwd(pid_t pid, bool use_toolong_hack, char **buf)
{
	int r;
	char *c, *cwd, *linkcwd;

	assert(pid >= 1);
	assert(buf);

	if (syd_asprintf(&linkcwd, "/proc/%u/cwd", pid) < 0)
		return -ENOMEM;

	r = readlink_alloc(linkcwd, &cwd);
	if (use_toolong_hack && r == -ENAMETOOLONG) {
		if ((r = chdir(linkcwd)) < 0) {
			r = -errno;
			goto out;
		}
		if ((cwd = getcwd_long()) == NULL) {
			r = -ENOMEM;
			goto out;
		}
	} else if (r < 0) {
		goto out;
	}

	if ((c = proc_deleted(cwd)))
		cwd[c - cwd] = '\0';

	*buf = cwd;
	/* r = 0; already so */
out:
	free(linkcwd);
	return r;
}

#if 0
/*
 * resolve /proc/$pid/fd/$dirfd
 */
int proc_fd(pid_t pid, int dfd, char **buf)
{
	int r;
	char *fd, *linkdir;

	assert(pid >= 1);
	assert(dfd >= 0);
	assert(buf);

	if (syd_asprintf(&linkdir, "/proc/%u/fd/%d", pid, dfd) < 0)
		return -ENOMEM;

	r = readlink_alloc(linkdir, &fd);
	free(linkdir);
	if (r >= 0)
		*buf = fd;
	return r;
}

/*
 * read /proc/$pid/cmdline,
 * does not handle kernel threads which can't be traced anyway.
 */
int proc_cmdline(pid_t pid, size_t max_length, char **buf)
{
	char *p, *r, *k;
	int c;
	bool space = false;
	size_t left;
	FILE *f;

	assert(pid >= 1);
	assert(max_length > 0);
	assert(buf);

	if (syd_asprintf(&p, "/proc/%u/cmdline", pid) < 0)
		return -ENOMEM;

	f = fopen(p, "r");
	free(p);

	if (!f)
		return -errno;

	r = syd_malloc(max_length * sizeof(char));
	if (!r) {
		fclose(f);
		return -ENOMEM;
	}

	k = r;
	left = max_length;
	while ((c = getc(f)) != EOF) {
		if (isprint(c)) {
			if (space) {
				if (left <= 4)
					break;

				*(k++) = ' ';
				left--;
				space = false;
			}

			if (left <= 4)
				break;

			*(k++) = (char)c;
			left--;
		}
		else
			space = true;
	}

	if (left <= 4) {
		size_t n = MIN(left - 1, 3U);
		memcpy(k, "...", n);
		k[n] = 0;
	}
	else
		*k = 0;

	fclose(f);
	*buf = r;
	return 0;
}

/*
 * read /proc/$pid/comm
 */
int proc_comm(pid_t pid, char **name)
{
	int r;
	char *p;

	assert(pid >= 1);
	assert(name);

	if (syd_asprintf(&p, "/proc/%u/comm", pid) < 0)
		return -ENOMEM;

	r = read_one_line_file(p, name);
	free(p);

	if (r < 0)
		return r;

	return 0;
}
#endif

bool proc_has_task(pid_t pid, pid_t task)
{
	bool r = false;
	DIR *dir;
	char procdir[sizeof("/proc/%d/task") + sizeof(int) * 3];

	sprintf(procdir, "/proc/%d/task", pid);
	dir = opendir(procdir);

	if (dir == NULL)
		return r;

	struct dirent *de;
	while ((de = readdir(dir)) != NULL) {
		int tid;

		if (de->d_fileno == 0)
			continue;

		tid = atoi(de->d_name);
		if (tid <= 0)
			continue;

		if (tid == task) {
			r = true;
			goto out;
		}
	}

out:
	closedir(dir);
	return r;
}

/* read Tgid: and PPid: from /proc/$pid/status */
int proc_parents(pid_t pid, pid_t *tgid, pid_t *ppid)
{
	char buf[LINE_MAX], *p;
	FILE *f;

	assert(pid >= 1);
	assert(tgid);
	assert(ppid);

	if (syd_asprintf(&p, "/proc/%u/status", pid) < 0)
		return -ENOMEM;

	f = fopen(p, "r");
	free(p);

	if (!f)
		return -errno;

	pid_t ret_tgid = -1, ret_ppid = -1;
	buf[0] = '\0';
	while (fgets(buf, LINE_MAX, f) != NULL) {
		if ((ret_tgid == -1 && startswith(buf, "Tgid:") &&
		     sscanf(buf, "Tgid: %d", &ret_tgid) != 1) ||
		    (ret_ppid == -1 && startswith(buf, "PPid:") &&
		     sscanf(buf, "PPid: %d", &ret_ppid) != 1)) {
			fclose(f);
			return -EINVAL;
		}
		buf[0] = '\0';
	}

	fclose(f);
	if (ret_tgid == -1 || ret_ppid == -1)
		return -EINVAL;

	*tgid = ret_tgid;
	*ppid = ret_ppid;
	return 0;
}

/*
 * read /proc/$pid/stat
 */
int proc_stat(pid_t pid, struct proc_statinfo *info)
{
	char *p;
	FILE *f;

	assert(pid >= 1);
	assert(info);

	if (syd_asprintf(&p, "/proc/%u/stat", pid) < 0)
		return -ENOMEM;

	f = fopen(p, "r");
	free(p);

	if (!f)
		return -errno;

	if (fscanf(f,
		"%d"	/* pid */
		" %32s"	/* comm */
		" %c"	/* state */
		" %d"	/* ppid */
		" %d"	/* pgrp */
		" %d"	/* session */
		" %d"	/* tty_nr */
		" %d"	/* tpgid */
		" %*u"	/* flags */
		" %*u %*u %*u %*u" /* minflt, cminflt, majflt, cmajflt */
		" %*u %*u %*d %*d" /* utime, stime, cutime, cstime */
		" %*d"	/* priority */
		" %ld" /* nice */
		" %ld", /* num_threads */
			&info->pid,
			info->comm,
			&info->state,
			&info->ppid,
			&info->pgrp,
			&info->session,
			&info->tty_nr,
			&info->tpgid,
			&info->nice,
			&info->num_threads) != 10) {
		fclose(f);
		return -EINVAL;
	}

	fclose(f);
	return 0;
}

#if 0
/*
 * read /proc/$pid/environ and set the environment.
 * (call clearenv() beforehand to reset the environment.)
 */
int proc_environ(pid_t pid)
{
	int c, r;
	unsigned i;
	char *p, s[MAX_ARG_STRLEN];
	FILE *f;

	assert(pid >= 1);

	if (syd_asprintf(&p, "/proc/%u/environ", pid) < 0)
		return -ENOMEM;

	f = fopen(p, "r");
	r = -errno;
	free(p);
	if (!f)
		return r;

	r = 0;
	for (i = 0; (c = fgetc(f)) != EOF; i++) {
		if (i >= MAX_ARG_STRLEN) {
			r = -E2BIG;
			break;
		}
		s[i] = c;

		if (c == '\0' && putenv(s) != 0) { /* end of unit */
			r = -ENOMEM;
			break;
		}
	}

	fclose(f);
	errno = r;
	return r;
}
#endif

/* /proc/<PID>/fd/<N> -> socket:[<inode>] */
int proc_socket_inode(pid_t pid, int socket_fd, unsigned long long *inode)
{
	int r;
	char *p;

	assert(pid >= 1);
	assert(socket_fd >= 0);

	if (syd_asprintf(&p, "/proc/%d/fd/%d", pid, socket_fd) < 0)
		return -ENOMEM;

#define PREFIX_LEN 8
	char *l, *link = NULL;
	if ((r = readlink_alloc(p, &link)) < 0)
		goto out;
	else if (r <= PREFIX_LEN) {
		r = -EINVAL;
		goto out;
	}
	r = 0;
	if (strncmp(link, "socket:[", PREFIX_LEN)) {
		r = -EINVAL;
		goto out;
	}
	l = link + PREFIX_LEN;
	if (*l == '\0') {
		r = -EINVAL;
		goto out;
	}

	char *end;
	unsigned long long inode_r;

	errno = 0;
	inode_r = strtoull(l, &end, 10);
	if (end && l == end) {
		r = -EINVAL;
		goto out;
	} else if (errno) {
		r = -errno;
		goto out;
	}
	*inode = inode_r;

out:
	if (link)
		free(link);
	free(p);

	return r;
}

int proc_socket_port(unsigned long long inode, bool ipv4, int *port)
{
	char buf[LINE_MAX];
	FILE *f;
	const char *path = ipv4 ? "/proc/net/tcp" : "/proc/net/tcp6";

	assert(port);

	f = fopen(path, "r");
	if (!f)
		return -errno;

	fgets(buf, LINE_MAX, f); /* skip the header */
	while (fgets(buf, LINE_MAX, f) != NULL) {
		int n;
		unsigned int port_r;
		unsigned long long inode_r;
		n = sscanf(buf, " %*d: "
				"%*x:%x "
				"%*x:%*x "
				"%*x "
				"%*x:%*x "
				"%*x:%*x "
				"%*x "
				"%*x "
				"%*x "
				"%llu ",
		       &port_r, &inode_r);
		if (n != 2 || inode != inode_r)
			continue;
		*port = port_r;
		fclose(f);
		return 0;
	}

	fclose(f);
	return -ESRCH;
}
