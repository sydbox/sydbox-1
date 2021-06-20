/*
 * sydbox/t/tests-bin/syd-false-pthread.c
 *
 * Copyright (c) 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "headers.h"

void *thread(void *arg)
{
	usleep(4242);
	pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
	int i, c;

	c = atoi(argv[1]);
	if (c < 0 || c > 4096)
		abort();
	for (i = 0; i < c; i++) {
		pthread_t t;

		pthread_create(&t, NULL, thread, NULL);
		pthread_join(t, NULL);
	}

	return 1;
}
