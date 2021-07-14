/*
 * libsyd/log.c
 *
 * libsyd: Simple Logging API
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include "syd.h"

static bool syd_debug;
static int syd_debug_fd = STDERR_FILENO;
static bool syd_debug_fd_isatty;

static void syd_debug_fd_set_tty(void)
{
	if (syd_debug_fd >= 0)
		syd_debug_fd_isatty = isatty(syd_debug_fd) == 1;
	else
		syd_debug_fd_isatty = false;
}

int syd_vsay(const char *fmt, va_list ap)
{
	if (syd_debug_fd_isatty)
		dprintf(syd_debug_fd, "[0;1;31;91");
	if (fmt[0] != ' ')
		dprintf(syd_debug_fd, "sydb☮x: ");

	int save_errno = 0;
	int r = vdprintf(syd_debug_fd, fmt, ap);
	if (r < 0)
		save_errno = errno;

	if (syd_debug_fd_isatty)
		dprintf(syd_debug_fd, "[0m");

	return r < 0 ? -save_errno : r;
}

int syd_say(const char *fmt, ...)
{
	int r;
	va_list ap;

	va_start(ap, fmt);
	r = syd_vsay(fmt, ap);
	va_end(ap);
	dprintf(syd_debug_fd, "\n");

	return r;
}

int syd_say_errno(const char *fmt, ...)
{
	int r, save_errno = errno;
	va_list ap;

	va_start(ap, fmt);
	r = syd_vsay(fmt, ap);
	va_end(ap);
	syd_say(" (errno:%d|%s %s)",
		save_errno,
		syd_name_errno(save_errno),
		strerror(save_errno));

	return r < 0 ? -save_errno : r;
}

bool syd_debug_get(void)
{
	return syd_debug;
}

void syd_debug_set(const bool val)
{
	syd_debug_fd_set_tty();
	syd_debug = val;
}

int syd_debug_set_fd(const int fd)
{
	if (fd <= 0)
		return -EINVAL;
	syd_debug_fd = fd;
	syd_debug_fd_set_tty();
	return 0;
}
