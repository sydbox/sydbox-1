/* Syd: See Emily Play!
 * Check program for sydbox tests
 * Copyright 2009, 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * parse_octal() is based in part upon busybox which is:
 *   Copyright (C) 2003  Manuel Novoa III  <mjn3@codepoet.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#ifndef EMILY_H
#define EMILY_H 1

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <errno.h>
#include <fcntl.h>
#include <utime.h>
#include <getopt.h>

#include "strtable.h"

#define TEST_ERRNO_INVALID -1
#define TEST_DIRFD_INVALID STDERR_FILENO
#define TEST_DIRFD_NOEXIST 1023

static inline int expect_errno(int real_errno, int expected_errno)
{
	if (real_errno != expected_errno) {
		fprintf(stderr, "errno:%d %s != expected:%d %s\n",
				real_errno, errno_to_string(real_errno),
				expected_errno, errno_to_string(expected_errno));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static inline bool parse_octal(const char *s, mode_t *mode)
{
	char *e;
	unsigned long tmp;

	assert(mode);

	tmp = strtoul(s, &e, 8);
	if (*e || tmp > 07777U) /* Check range and trailing chars */
		return false;

	*mode = tmp;
	return true;
}

static inline int do_close(int fd)
{
	int r;

	for (;;) {
		r = close(fd);
		if (r < 0 && errno == EINTR)
			continue;
		return r;
	}
}

static inline int do_write(int fd, const void *buf, size_t count)
{
	int written;
	const char *p;

	p = (const char *)buf;
	do {
		written = write(fd, p, count);
		if (!written)
			return -1;
		if (written < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p += written;
		count -= written;
	} while (count > 0);

	return written;
}

extern int test_stat(int argc, char **argv);
extern int test_chmod(int argc, char **argv);
extern int test_fchmodat(int argc, char **argv);
extern int test_chown(int argc, char **argv);
extern int test_lchown(int argc, char **argv);
extern int test_fchownat(int argc, char **argv);
extern int test_open(int argc, char **argv);
extern int test_openat(int argc, char **argv);
extern int test_creat(int argc, char **argv);
extern int test_mkdir(int argc, char **argv);
extern int test_mkdirat(int argc, char **argv);

#endif /* !EMILY_H */
