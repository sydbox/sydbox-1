/*
 * sydbox/pathdecode.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"
#include "pathdecode.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include "pink.h"
#include "xfunc.h"

#include <syd.h>

/* Decode the path at the given index and place it in buf.
 * Handles panic()
 * Returns:
 * -errno : Negated errno indicating error code
 *  0     : Successful run
 */
int path_decode(syd_process_t *current, unsigned arg_index, char **buf)
{
	int r;
	ssize_t count_read;
	long addr;
	char path[SYDBOX_PATH_MAX];

	assert(current);
	assert(buf);

	if ((r = syd_read_argument(current, arg_index, &addr)) < 0)
		return r;

	/* syd_read_string() handles panic() and partial reads */
	count_read = syd_read_string(current, addr, path, SYDBOX_PATH_MAX);
	if (count_read < 0) {
		if (errno == EFAULT) {
			*buf = NULL;
			return 0;
		}
		return -errno;
	}
	*buf = xstrdup(path);
	return 0;
}

/*
 * Resolve the prefix of an at-suffixed function.
 * Handles panic()
 * Returns:
 * -errno : Negated errno indicating error code
 *  0     : Successful run
 */
int path_prefix(syd_process_t *current, unsigned arg_index, char **buf)
{
	int r, fd;
	char *prefix = NULL;

	if ((r = syd_read_argument_int(current, arg_index, &fd)) < 0)
		return r;

	r = 0;
	if (fd == AT_FDCWD) {
		*buf = NULL;
	} else if (fd < 0) {
		*buf = NULL;
		r = -EBADF;
	} else {
		if ((r = syd_proc_fd_path(current->pid, fd, &prefix)) < 0) {
			if (fd > STDERR_FILENO)
				say("readlink /proc/%u/fd/%d failed (errno:%d %s)",
				    current->pid, fd, -r, strerror(-r));
			if (r == -ENOENT)
				r = -EBADF; /* correct errno */
		} else {
			*buf = prefix;
		}
	}

	return r;
}
