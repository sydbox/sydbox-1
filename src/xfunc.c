/*
 * sydbox/xfunc.c
 *
 * Copyright (c) 2010, 2012, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "syd-conf.h"
#include <syd/compiler.h>
#include "xfunc.h"
#include "dump.h"
#include "errno2name.h"
#include "syd-box.h"

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#if IN_SYDBOX
# define in_child()	((sydbox)->in_child)

/* abort function. */
static void (*abort_func)(int sig);

void syd_abort_func(void (*func)(int))
{
	abort_func = func;
}
#else
# define dump(...) /* empty */
#endif

SYD_GCC_ATTR((noreturn))
static void syd_abort(int how) /* SIGTERM == exit(1), SIGABRT == abort() */
{
#if IN_SYDBOX
	if (!in_child() && abort_func)
		abort_func(SIGTERM);
#endif
	switch (how) {
	case SIGABRT:
		abort();
	case SIGTERM:
	default:
		exit(1);
	}
}

void vsay(FILE *fp, const char *fmt, va_list ap, char level)
{
	static int tty = -1;

	if (tty < 0)
		tty = isatty(STDERR_FILENO) == 1 ? 1 : 0;
	if (tty)
		fputs(SYD_WARN, fp);
	if (fmt[0] != ' ')
		fputs("sydb☮x: ", fp);
	switch (level) {
	case 'b':
		fputs("bug: ", fp);
		break;
	case 'f':
		fputs("fatal: ", fp);
		break;
	case 'w':
		fputs("warning: ", fp);
		break;
	default:
		break;
	}
	vfprintf(stderr, fmt, ap);
	if (tty)
		fputs(SYD_RESET, fp);
}

void warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 'w');
	va_end(ap);
	fputc('\n', stderr);
}

void say(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 0);
	va_end(ap);
	fputc('\n', stderr);

	if (secure_getenv("DEBUG")) {
		FILE *f = fopen("sydbox.out", "w");
		if (!f)
			return;
		va_start(ap, fmt);
		vsay(f, fmt, ap, 'd');
		va_end(ap);
		fputc('\n', f);
		fclose(f);
	}
}

void bug_on(const char *expr, const char *func, const char *file, size_t line,
	    const char *fmt, ...)
{
	va_list ap;

	if (fmt) {
		fprintf(stderr, "BUG: %s:%s/%s:%zu: ", expr, file, func, line);
		va_start(ap, fmt);
		vsay(stderr, fmt, ap, 'b');
		va_end(ap);
		fputc('\n', stderr);
	}
#ifndef SYDBOX_NDUMP
	dump(DUMP_CLOSE);
#endif
	assert_(expr, func, file, line);
}

void warn_on(const char *expr, const char *func, const char *file, size_t line,
	     const char *fmt, ...)
{
	va_list ap;

	if (fmt) {
		fprintf(stderr, "WARN: %s:%s/%s:%zu: ", expr, file, func, line);
		va_start(ap, fmt);
		vsay(stderr, fmt, ap, 'w');
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
	vsay(stderr, fmt, ap, 'f');
	va_end(ap);
	fputc('\n', stderr);

	syd_abort(SIGTERM);
}

void say_errno(const char *fmt, ...)
{
	int save_errno = errno;
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 'e');
	va_end(ap);
	say(" (errno:%d|%s %s)", save_errno, errno2name(save_errno),
	    strerror(save_errno));

	errno = save_errno;
}

void die_errno(const char *fmt, ...)
{
	int save_errno = errno;
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 'f');
	va_end(ap);
	say(" (errno:%d|%s %s)", save_errno, errno2name(save_errno),
	    strerror(save_errno));

	syd_abort(SIGTERM);
}

inline void xfree(void *ptr)
{
	if (ptr)
		free(ptr);
}

inline void *syd_malloc(size_t size)
{
	dump(DUMP_ALLOC, size, "malloc");
	return malloc(size);
}

inline void *syd_calloc(size_t nmemb, size_t size)
{
	dump(DUMP_ALLOC, size, "calloc");
	return calloc(nmemb, size);
}

inline void *syd_realloc(void *ptr, size_t size)
{
	dump(DUMP_ALLOC, size, "realloc");
	return realloc(ptr, size);
}

inline char *syd_strdup(const char *src)
{
	dump(DUMP_ALLOC, strlen(src) + 1, "strdup");
	return strdup(src);
}

inline char *syd_strndup(const char *src, size_t n)
{
	dump(DUMP_ALLOC, n, "strndup");
	return strndup(src, n);
}

static inline int syd_vasprintf(const char *name, char **strp, const char *fmt,
				va_list ap)
{
	int r;

	assert(strp);

	r = vasprintf(strp, fmt, ap);
	dump(DUMP_ALLOC, strlen(*strp) + 1, name);
	return r;
}

int syd_asprintf(char **strp, const char *fmt, ...)
{
	int r;
	char *dest;
	va_list ap;

	assert(strp);

	va_start(ap, fmt);
	r = syd_vasprintf("vasprintf", &dest, fmt, ap);
	va_end(ap);

	if (r == -1) {
		errno = ENOMEM;
		die_errno("vasprintf");
	}
	*strp = dest;
	return r;
}

void *xmalloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (!ptr)
		die_errno("malloc");
	dump(DUMP_ALLOC, size, "xmalloc");

	return ptr;
}

void *xcalloc(size_t nmemb, size_t size)
{
	void *ptr;

	ptr = calloc(nmemb, size);
	if (!ptr)
		die_errno("calloc");
	dump(DUMP_ALLOC, size, "xcalloc");

	return ptr;
}

void *xrealloc(void *ptr, size_t size)
{
	void *nptr;

	nptr = realloc(ptr, size);
	if (!nptr)
		die_errno("realloc");
	dump(DUMP_ALLOC, size, "xrealloc");

	return nptr;
}

char *xstrdup(const char *src)
{
	char *dest;

	dest = strdup(src);
	if (!dest)
		die_errno("strdup");
	dump(DUMP_ALLOC, strlen(src) + 1, "xstrdup");

	return dest;
}

char *xstrndup(const char *src, size_t n)
{
	char *dest;

	dest = strndup(src, n);
	if (!dest)
		die_errno("strndup");
	dump(DUMP_ALLOC, n, "xstrndup");

	return dest;
}

int xasprintf(char **strp, const char *fmt, ...)
{
	int r;
	char *dest;
	va_list ap;

	assert(strp);

	va_start(ap, fmt);
	r = syd_vasprintf("vasprintf", &dest, fmt, ap);
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
