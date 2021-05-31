/*
 * Simple implementation of the Test Anything Protocol
 * Copyright 2012, 2013 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef TAP_H
#define TAP_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#if !defined(SPARSE) && defined(__GNUC__) && __GNUC__ >= 3
#define TAP_GNUC_UNUSED		__attribute__((unused))
#endif

static int tap_test_count = 1;

#define DEFINE_TAP_FUNC(func) \
	TAP_GNUC_UNUSED \
	static void tap_##func(const char *fmt, ...) { \
		va_list ap; \
		va_start(ap, fmt); \
		func(fmt, ap); \
		va_end(ap); \
	}

static void bail_out(const char *fmt, va_list ap)
{
	printf("Bail out! ");
	vprintf(fmt, ap);
	fputc('\n', stdout);
}
DEFINE_TAP_FUNC(bail_out)

static void xbail_out(const char *fmt, va_list ap)
{
	bail_out(fmt, ap);
	exit(EXIT_FAILURE);
}
DEFINE_TAP_FUNC(xbail_out)

static void plan(const char *fmt, va_list ap)
{
	printf("1..%u\n", --tap_test_count);
	vprintf(fmt, ap);
	fputc('\n', stdout);
}
DEFINE_TAP_FUNC(plan)

static void comment(const char *fmt, va_list ap)
{
	printf("# ");
	vprintf(fmt, ap);
	fputc('\n', stdout);
}
DEFINE_TAP_FUNC(comment)

static void ok(const char *fmt, va_list ap)
{
	printf("ok %u ", tap_test_count++);
	vprintf(fmt, ap);
	fputc('\n', stdout);
}
DEFINE_TAP_FUNC(ok)

static void not_ok(const char *fmt, va_list ap)
{
	printf("not ok %u ", tap_test_count++);
	vprintf(fmt, ap);
	fputc('\n', stdout);
}
DEFINE_TAP_FUNC(not_ok)

static void todo(const char *fmt, va_list ap)
{
	printf("not ok %u # TODO ", tap_test_count++);
	vprintf(fmt, ap);
	fputc('\n', stdout);
}
DEFINE_TAP_FUNC(todo)

static void skip(const char *fmt, va_list ap)
{
	printf("ok %u # SKIP ", tap_test_count++);
	vprintf(fmt, ap);
	fputc('\n', stdout);
}
DEFINE_TAP_FUNC(skip)

#undef DEFINE_TAP_FUNC

TAP_GNUC_UNUSED
static void *tap_xmalloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (!ptr)
		tap_xbail_out("OOM! (errno:%d %s)", errno, strerror(errno));
	return ptr;
}

TAP_GNUC_UNUSED
static void tap_xfree(void *ptr)
{
	if (!ptr)
		tap_xbail_out("free() called with NULL!");
	free(ptr);
}

#endif /* !TAP_H */
