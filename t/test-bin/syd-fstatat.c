/*
 * sydbox/t/tests-bin/syd-fstatat.c
 *
 * Copyright (c) 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "headers.h"

int main(int argc, char *argv[])
{
#ifndef HAVE_NEWFSTATAT
	return ENOSYS;
#else
	int dirfd;
	const char *path;
	struct stat buf;

	if (!strcmp(argv[1], "cwd"))
		dirfd = AT_FDCWD;
	else if (!strcmp(argv[1], "null"))
		dirfd = STDERR_FILENO; /* not a directory */
	else
		dirfd = atoi(argv[1]);
	path = argv[2];

	/* Using fstatat(AT_FDCWD, ...) is not a good idea here as the libc may
	 * actually call the stat() system call instead. */
	errno = 0;
	syscall(SYS_newfstatat, dirfd, path, &buf, 0);
	return errno;
#endif
}
