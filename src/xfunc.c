/*
 * sydbox/xfunc.c
 *
 * Copyright (c) 2010, 2012, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "sydconf.h"
#include "xfunc.h"
#include "dump.h"

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <pinktrace/pink.h>

/* ANSI colour codes */
#define ANSI_NORMAL		"[00;00m"
#define ANSI_MAGENTA		"[00;35m"
#define ANSI_DARK_MAGENTA	"[01;35m"
#define ANSI_GREEN		"[00;32m"
#define ANSI_YELLOW		"[00;33m"
#define ANSI_CYAN		"[00;36m"

/* abort function. */
static void (*abort_func)(int sig);

PINK_GCC_ATTR((noreturn))
static void syd_abort(int how) /* SIGTERM == exit(1), SIGABRT == abort() */
{
	if (abort_func)
		abort_func(SIGTERM);
	switch (how) {
	case SIGABRT:
		abort();
	case SIGTERM:
	default:
		exit(1);
	}
}

void syd_abort_func(void (*func)(int))
{
	abort_func = func;
}

void vsay(const char *fmt, va_list ap)
{
	static int tty = -1;

	if (tty < 0)
		tty = isatty(STDERR_FILENO) == 1 ? 1 : 0;

	if (tty)
		fputs(ANSI_DARK_MAGENTA, stderr);
	if (fmt[0] != ' ')
		fputs(PACKAGE": ", stderr);

	vfprintf(stderr, fmt, ap);

	if (tty)
		fputs(ANSI_NORMAL, stderr);
}

void say(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsay(fmt, ap);
	va_end(ap);

	fputc('\n', stderr);
}

void bug_on(const char *expr, const char *func, const char *file, size_t line,
	    const char *fmt, ...)
{
	va_list ap;

	if (fmt) {
		fprintf(stderr, "BUG: %s:%s/%s:%zu: ", expr, file, func, line);
		va_start(ap, fmt);
		vsay(fmt, ap);
		va_end(ap);
		fputc('\n', stderr);
	}
#ifndef SYDBOX_NDUMP
	dump(DUMP_CLOSE);
#endif
	pause();
	assert_(expr, func, file, line);
}

void warn_on(const char *expr, const char *func, const char *file, size_t line,
	     const char *fmt, ...)
{
	va_list ap;

	if (fmt) {
		fprintf(stderr, "WARN: %s:%s/%s:%zu: ", expr, file, func, line);
		va_start(ap, fmt);
		vsay(fmt, ap);
		va_end(ap);
		fputc('\n', stderr);
	}
	assert_warn_(expr, func, file, line);
}

void assert_warn_(const char *expr, const char *func, const char *file, size_t line)
{
	fprintf(stderr, PACKAGE": Assertion '%s' failed at %s:%zu, function %s()\n",
		expr, file, line, func);

#ifndef SYDBOX_NDUMP
	dump(DUMP_ASSERT, expr, file, line, func);
#endif
}

void assert_(const char *expr, const char *func, const char *file, size_t line)
{
	assert_warn_(expr, func, file, line);
	syd_abort(SIGABRT);
}

void assert_not_reached_(const char *func, const char *file, size_t line)
{
	fprintf(stderr, PACKAGE": Code must not be reached at %s:%zu, function %s()",
		file, line, func);

	syd_abort(SIGABRT);
}

void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsay(fmt, ap);
	va_end(ap);
	fputc('\n', stderr);

	syd_abort(SIGTERM);
}

void die_errno(const char *fmt, ...)
{
	int save_errno = errno;
	va_list ap;

	va_start(ap, fmt);
	vsay(fmt, ap);
	va_end(ap);
	say(" (errno:%d|%s| %s)", save_errno, pink_name_errno(save_errno, 0), strerror(save_errno));

	syd_abort(SIGTERM);
}

void *xmalloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (!ptr)
		die_errno("malloc");

	return ptr;
}

void *xcalloc(size_t nmemb, size_t size)
{
	void *ptr;

	ptr = calloc(nmemb, size);
	if (!ptr)
		die_errno("calloc");

	return ptr;
}

void *xrealloc(void *ptr, size_t size)
{
	void *nptr;

	nptr = realloc(ptr, size);
	if (!nptr)
		die_errno("realloc");

	return nptr;
}

char *xstrdup(const char *src)
{
	char *dest;

	dest = strdup(src);
	if (!dest)
		die_errno("strdup");

	return dest;
}

char *xstrndup(const char *src, size_t n)
{
	char *dest;

	dest = strndup(src, n);
	if (!dest)
		die_errno("strndup");

	return dest;
}

int xasprintf(char **strp, const char *fmt, ...)
{
	int r;
	char *dest;
	va_list ap;

	assert(strp);

	va_start(ap, fmt);
	r = vasprintf(&dest, fmt, ap);
	va_end(ap);

	if (r == -1) {
		errno = ENOMEM;
		die_errno("vasprintf");
	}

	*strp = dest;
	return r;
}

char *xgetcwd(void)
{
	char *cwd;
#ifdef _GNU_SOURCE
	cwd = get_current_dir_name();
#else
	cwd = xmalloc(sizeof(char) * (PATH_MAX + 1));
	cwd = getcwd(cwd, PATH_MAX + 1);
#endif
	if (!cwd)
		die_errno("getcwd");
	return cwd;
}
