/*
 * syd/check.c -- Syd's utility library checks
 *
 * Copyright (c) 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "check.h"
#include <stdlib.h>
#include <string.h>

char syd_fail_message[SYD_FAIL_MESSAGE_MAX];

static void all_tests(void)
{
	const char *only = getenv("SYD_CHECK");
	const char *skip = getenv("SYD_CHECK_SKIP");

	if (only) {
		if (strstr(only, "file"))
			test_suite_file();
		if (strstr(only, "proc"))
			test_suite_proc();
		if (strstr(only, "sha1"))
			test_suite_sha1();
	} else {
		if (!skip || !strstr(skip, "file"))
			test_suite_file();
		if (!skip || !strstr(skip, "proc"))
			test_suite_proc();
		if (!skip || !strstr(skip, "sha1"))
			test_suite_sha1();
	}
}

int main(int argc, char *argv[])
{
	int r;

	r = seatest_testrunner(argc, argv, all_tests, NULL, NULL);
	return (r != 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
