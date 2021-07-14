/*
 * libsyd/time.c
 *
 * timing utilities
 *
 * Copyright (c) 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "syd.h"
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

struct timespec syd_time_diff(const struct timespec *t1, const struct timespec *t2)
{
	struct timespec diff;

	if ((t2->tv_nsec - t1->tv_nsec) < 0) {
		diff.tv_sec = t2->tv_sec - t1->tv_sec - 1;
		diff.tv_nsec = 1000000000 + t2->tv_nsec - t1->tv_nsec;
	} else {
		diff.tv_sec = t2->tv_sec - t1->tv_sec;
		diff.tv_nsec = t2->tv_nsec - t1->tv_nsec;
	}

	return diff;
}

void syd_time_prof(unsigned loop, ...)
{
	va_list ap;
	syd_time_prof_func_t f;
	struct timespec ts, te, diff;

	va_start(ap, loop);
	for (unsigned i = 0;;i++) {
		f = va_arg(ap, syd_time_prof_func_t);
		if (!f)
			break;

		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
		for (unsigned c = 0; c < loop; c++)
			f();
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &te);
		diff = syd_time_diff(&ts, &te);
		fprintf(stderr, "func %u (loop %u): %ld.%09ld\n",
			i, loop, diff.tv_sec, diff.tv_nsec);
	}
	va_end(ap);
}
