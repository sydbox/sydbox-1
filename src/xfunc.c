/*
 * sydbox/xfunc.c
 *
 * Copyright (c) 2010, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v2
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "xfunc.h"

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "log.h"

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
