/*
 * sydbox/t/tests-bin/syd-mkdir-p.c
 *
 * Copyright (c) 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "headers.h"

int main(int argc, char *argv[])
{
	int expect_errno;
	char *p;

	p = strdup(argv[1]);
	if (!p)
		return ENOMEM;

	for (char *x = p, *y = strchrnul(x, '/');; x = y + 1, y = strchrnul(x, '/')) {
		char c;

		c = *y; *y = 0;
		expect_errno = access(x, F_OK) ? 0 : EEXIST;
		/* fprintf(stderr, "next_dir: %s\n", x); */

		errno = 0;
		(void)mkdir(x, 0700);
		if (errno != expect_errno) {
			/* fprintf(stderr, "mkdir: expected %d, got %d\n", expect_errno, errno); */
			return errno;
		}
		/* fprintf(stderr, "mkdir: OK\n"); */

		errno = 0;
		(void)chdir(x);
		if (errno != 0) {
			/* fprintf(stderr, "mkdir: expected %d, got %d\n", 0, errno); */
			return errno;
		}
		/* fprintf(stderr, "chdir: OK\n"); */

		if (c == '\0')
			break;
	}

	return 0;
}
