/*
 * sydbox/file.c
 *
 * File related utilities
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is
 *   Copyright 2010 Lennart Poettering
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "syd-conf.h"

#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif /* !_GNU_SOURCE */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "file.h"
#include "xfunc.h"

#define NEWLINE "\n\r"

bool empty_line(const char *s)
{
	assert(s != NULL);

	return !!(strcspn(s, NEWLINE) == 0);
}

char *truncate_nl(char *s)
{
	assert(s != NULL);

	s[strcspn(s, NEWLINE)] = '\0';
	return s;
}

const char *filename_ext(const char *s)
{
	const char *ext;

	ext = strrchr(s, '.');
	return ext ? ext + 1 : NULL;
}

int basename_alloc(const char *path, char **buf)
{
	char *c, *bname, *retbuf;

	assert(buf != NULL);

	c = syd_strdup(path);
	if (!c)
		return -ENOMEM;

	bname = basename(c);
	retbuf = syd_strdup(bname);
	free(c);

	if (!retbuf)
		return -ENOMEM;
	*buf = retbuf;
	return 0;
}

ssize_t readlink_copy(const char *path, char *dest, size_t len)
{
	ssize_t n;

	n = readlink(path, dest, len - 1);
	if (n < 0 || n >= (ssize_t)(len - 1)) {
		if (n < 0)
			return -errno;
		else if (n == 0)
			return -ENOENT;
		else
			return -ENAMETOOLONG;
	}
	dest[n] = 0;
	return n;
}

/* readlink() wrapper which:
 * - allocates the string itself.
 * - appends a zero-byte at the end.
 */
ssize_t readlink_alloc(const char *path, char **buf)
{
	size_t l = 100;

	for (;;) {
		char *c;
		ssize_t n;

		c = syd_malloc(l * sizeof(char));
		if (!c)
			return -ENOMEM;

		n = readlink(path, c, l - 1);
		if (n < 0) {
			int ret = -errno;
			free(c);
			return ret;
		}

		if ((size_t)n < l - 1) {
			c[n] = 0;
			*buf = c;
			return n;
		}

		free(c);
		l *= 2;
	}
}

/* readlinkat() wrapper which:
 * - allocates the string itself.
 * - appends a zero-byte at the end.
 */
ssize_t readlinkat_alloc(int dirfd, const char *path, char **buf)
{
	size_t l = 100;

	for (;;) {
		char *c;
		ssize_t n;

		c = syd_malloc(l * sizeof(char));
		if (!c)
			return -ENOMEM;

		n = readlinkat(dirfd, path, c, l - 1);
		if (n < 0) {
			int ret = -errno;
			free(c);
			return ret;
		}

		if ((size_t)n < l - 1) {
			c[n] = 0;
			*buf = c;
			return n;
		}

		free(c);
		l *= 2;
	}
}

int read_one_line_file(const char *fn, char **line)
{
	int r;
	FILE *f;
	char t[LINE_MAX], *c;

	assert(fn);
	assert(line);

	f = fopen(fn, "r");
	if (!f)
		return -errno;

	if (!fgets(t, sizeof(t), f)) {
		r = -errno;
		goto out;
	}

	c = syd_strdup(t);
	if (!c) {
		r = -ENOMEM;
		goto out;
	}

	(void)truncate_nl(c);

	*line = c;
	r = 0;

out:
	(void)fclose(f);
	return r;
}

static inline bool dot_ignore(const char *entry)
{
	if (entry[0] != '.')
		return false;
	if (entry[1] == '\0')
		return true;
	if (entry[1] != '.')
		return false;
	if (entry[2] == '\0')
		return true;
	return false;
}

int empty_dir(const char *dname)
{
#if !defined(SYDBOX_NO_GETDENTS) && defined(__linux__) && defined(SYS_getdents64)
	struct linux_dirent {
		unsigned long long d_ino;
		long long d_off;
		unsigned short d_reclen;
		unsigned char d_type;
		char d_name[];
	} *d;
# define DIRENT_BUF_SIZE 64
	char buf[DIRENT_BUF_SIZE];
	int r, fd, count_read, count_ent;

	fd = open(dname, O_RDONLY|O_DIRECTORY);
	if (fd < 0)
		return -errno;

	r = 0;
	count_ent = 0;
	for (;;) {
		count_read = syscall(SYS_getdents64, fd, buf, DIRENT_BUF_SIZE);
		if (count_read < 0) {
			r = -errno;
			goto out;
		} else if (count_read == 0) { /* end-of-directory */
			break;
		}

		for (int i = 0; i < count_read;) {
			d = (struct linux_dirent *)(buf + i);
			if (++count_ent > 2 || !dot_ignore(d->d_name)) {
				r = -ENOTEMPTY;
				goto out;
			}
			i += d->d_reclen;
		}
	}
out:
	close(fd);
	return r;
# undef DIRENT_BUF_SIZE
#else /* !__linux__ */
	int r;
	DIR *d;
	struct dirent *ent;

	d = opendir(dname);
	if (!d)
		return -errno;

	r = 0;
	for (unsigned n = 0; (ent = readdir(d)) != NULL; n++) {
		if (n > 2 || !dot_ignore(ent->d_name)) {
			r = -ENOTEMPTY;
			break;
		}
	}
	closedir(d);
	return r;
#endif
}

/* reset access and modification time */
int utime_reset(const char *path, const struct stat *st)
{
	if (!st)
		return 0;

	struct timespec ts[2] = {
		{ .tv_sec = st->st_atim.tv_sec, .tv_nsec = st->st_atim.tv_nsec },
		{ .tv_sec = st->st_mtim.tv_sec, .tv_nsec = st->st_mtim.tv_nsec }
	};
	utimensat(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW);
	/* ignore error here (due to possible »noatime« mount option) */
	return 0;
}
