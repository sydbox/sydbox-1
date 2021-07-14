/*
 * syd/check.h -- Syd's utility library check headers
 *
 * Copyright (c) 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef LIBSYD_CHECK_H
#define LIBSYD_CHECK_H 1

#include "seatest.h"
#include <syd/syd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#define SYD_FAIL_MESSAGE_MAX 1024
extern char syd_fail_message[SYD_FAIL_MESSAGE_MAX];
#define fail_msg(...) \
	do { \
		snprintf(syd_fail_message, SYD_FAIL_MESSAGE_MAX, __VA_ARGS__); \
		seatest_simple_test_result(0, syd_fail_message, __func__, __LINE__); \
	} while (0)
#define assert_true_msg(x, fmt, ...) \
	do { \
		if (!(x)) { \
			fail_msg((fmt), __VA_ARGS__); \
		} \
	} while (0)
#define assert_false_msg(x, fmt, ...) \
	do { \
		if ((x)) { \
			fail_msg((fmt), __VA_ARGS__); \
		} \
	} while (0)

void test_suite_file(void);
void test_suite_proc(void);
void test_suite_sha1(void);

#endif
