/*
 * sydbox/toolong.c
 *
 * Path (longer than PATH_MAX) handling
 *
 * Copyright (c) 2013, 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon zsh/Src/compat.c which is:
 *	 Copyright (c) 1992-1997 Paul Falstad
 * All rights reserved.
 * SPDX-License-Identifier: ZSH
 *
 * Permission is hereby granted, without written agreement and without
 * license or royalty fees, to use, copy, modify, and distribute this
 * software and to distribute modified versions of this software for any
 * purpose, provided that the above copyright notice and the following
 * two paragraphs appear in all copies of this software.
 *
 * In no event shall Paul Falstad or the Zsh Development Group be liable
 * to any party for direct, indirect, special, incidental, or consequential
 * damages arising out of the use of this software and its documentation,
 * even if Paul Falstad and the Zsh Development Group have been advised of
 * the possibility of such damage.
 *
 * Paul Falstad and the Zsh Development Group specifically disclaim any
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose.  The software
 * provided hereunder is on an "as is" basis, and Paul Falstad and the
 * Zsh Development Group have no obligation to provide maintenance,
 * support, updates, enhancements, or modifications.
 *
 */

#include "sydconf.h"

#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif /* !_GNU_SOURCE */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

int chdir_long(char *dir)
{
	char *s;
	int currdir = -2;

	for (;;) {
		if (!*dir || chdir(dir) == 0) {
#ifdef HAVE_FCHDIR
			if (currdir >= 0)
				close(currdir);
#endif
			return 0;
		}
		if ((errno != ENAMETOOLONG && errno != ENOMEM) ||
		    strlen(dir) < PATH_MAX)
			break;
		for (s = dir + PATH_MAX - 1; s > dir && *s != '/'; s--)
			;
		if (s == dir)
			break;
#ifdef HAVE_FCHDIR
		if (currdir == -2)
			currdir = open(".", O_RDONLY|O_NOCTTY);
#endif
		*s = '\0';
		if (chdir(dir) < 0) {
			*s = '/';
			break;
		}
#ifndef HAVE_FCHDIR
		currdir = -1;
#endif
		*s = '/';
		while (*++s == '/')
			;
		dir = s;
	}
#ifdef HAVE_FCHDIR
	if (currdir >= 0) {
		if (fchdir(currdir) < 0) {
			close(currdir);
			return -2;
		}
		close(currdir);
		return -1;
	}
#endif
	return currdir == -2 ? -1 : -2;
}

char *getcwd_long(void)
{
	char nbuf[PATH_MAX+3];
	char *buf;
	int bufsiz, pos;
	struct stat sbuf;
	ino_t pino;
	dev_t pdev;
	struct dirent *de;
	DIR *dir;
	int dirfd;
	dev_t dev;
	ino_t ino;
	int len;
	int save_errno;

	/* Try stat()'ing and chdir()'ing up */
	bufsiz = PATH_MAX;
	if ((buf = malloc(bufsiz)) == NULL)
		return NULL;

	memset(buf, 0, bufsiz);
	pos = bufsiz - 1;
	buf[pos] = '\0';
	strcpy(nbuf, "../");
	if (0 > stat(".", &sbuf)) {
		free(buf);
		return NULL;
	}

	/* Record the initial inode and device */
	pino = sbuf.st_ino;
	pdev = sbuf.st_dev;

	for (;;) {
		dirfd = open("..", O_RDONLY|O_DIRECTORY);
		if (0 > dirfd)
			break;
		if (0 > fstat(dirfd, &sbuf)) {
			save_errno = errno;
			close(dirfd);
			errno = save_errno;
			break;
		}

		/* Inode and device of current directory */
		ino = pino;
		dev = pdev;
		/* Inode and device of current directory's parent */
		pino = sbuf.st_ino;
		pdev = sbuf.st_dev;

		/* If they're the same, we've reached the root directory. */
		if (ino == pino && dev == pdev) {
			if (!buf[pos])
				buf[--pos] = '/';
			char *s = strdup(buf + pos);
			close(dirfd);
			free(buf);
			chdir_long(s);
			return s;
		}

		/* Search the parent for the current directory. */
		dir = fdopendir(dirfd);
		if (NULL == dir) {
			save_errno = errno;
			close(dirfd);
			errno = save_errno;
			break;
		}

		while ((de = readdir(dir))) {
			char *fn = de->d_name;
			/* Ignore `.' and `..'. */
			if (fn[0] == '.' &&
				(fn[1] == '\0' ||
				 (fn[1] == '.' && fn[2] == '\0')))
				continue;
			if (dev != pdev || (ino_t) de->d_ino == ino) {
				/* Maybe found directory, need to check device & inode */
				strncpy(nbuf + 3, fn, PATH_MAX);
				if (lstat(nbuf, &sbuf) < 0) {
					closedir(dir);
					free(buf);
					return NULL;
				}
				if (sbuf.st_dev == dev && sbuf.st_ino == ino)
					break;
			}
		}
		closedir(dir);
		if (!de)
			break; /* Not found */
		len = strlen(nbuf + 2);
		pos -= len;
		while (pos <= 1) {
			char *temp;
			char *newbuf;
			if ((newbuf = malloc(2 * bufsiz)) == NULL) {
				free(buf);
				return NULL;
			}
			memcpy(newbuf + bufsiz, buf, bufsiz);
			temp = buf;
			buf = newbuf;
			free(temp);
			pos += bufsiz;
			bufsiz *= 2;
		}
		memcpy(buf + pos, nbuf + 2, len);

		if (0 > chdir(".."))
			break;
	}

	if (*buf)
		chdir_long(buf + pos + 1);
	free(buf);
	return NULL;
}
