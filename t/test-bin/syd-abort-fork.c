/*
 * sydbox/t/tests-bin/syd-abort-fork.c
 *
 * Copyright (c) 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "headers.h"

int main(int argc, char *argv[])
{
	int i, c, s;
	pid_t p;

	c = atoi(getenv("SPAWN_MAX") ? getenv("SPAWN_MAX") : "16");
	if (c < 0 || c > 4096)
		abort();
	for (i = 0; i < c; i++) {
		pid_t pid = fork();
		if (!pid) {
			usleep(4242 + i);
			_exit((i % 127) + 1);
		}
	}

	s = atoi(argv[1]);
	p = getpid();
	errno = 0;

	kill(p, s);

	return errno;
}
