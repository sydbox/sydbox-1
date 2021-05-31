/* Syd: See Emily Play!
 * Check program for sydbox tests
 * Copyright 2013 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char **argv)
{
	int r, save_errno;

	if (argc != 2)
		return EXIT_FAILURE;
	r = unlink(argv[1]);
	save_errno = errno;
	if (getenv("UNLINK_EPERM")) {
		if (save_errno == EPERM)
			return EXIT_SUCCESS;
	} else if (r == 0) {
		return EXIT_SUCCESS;
	}
	fprintf(stderr, "unlink-simple failed (errno:%d %s)\n",
		save_errno, strerror(save_errno));
	return EXIT_FAILURE;
}
