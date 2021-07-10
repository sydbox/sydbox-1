/*
 * sydbox/t/tests-bin/syd-abort.c
 *
 * Copyright (c) 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "headers.h"

int main(int argc, char *argv[])
{
	int s;
	pid_t p;

	s = atoi(argv[1]);
	p = getpid();
	errno = 0;

	kill(p, s);

	return errno;
}
