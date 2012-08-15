/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Based in part upon privoxy which is:
 *   Copyright (c) 2001-2010 the Privoxy team. http://www.privoxy.org/
 *
 * This file is part of Sydbox. sydbox is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2, as published by the Free Software Foundation.
 *
 * sydbox is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include "log.h"
#include "util.h"

/* fatal can't be turned off! */
#define LOG_LEVEL_MINIMUM	LOG_LEVEL_FATAL

/* where to log (default: stderr) */
static FILE *logfp = NULL;
static FILE *logcfp = NULL;

/* logging detail level. */
static int debug = (LOG_LEVEL_FATAL
		| LOG_LEVEL_WARNING
		| LOG_LEVEL_ACCESS_V
		| LOG_LEVEL_INFO);
static int cdebug = (LOG_LEVEL_FATAL
		| LOG_LEVEL_WARNING
		| LOG_LEVEL_ACCESS_V);

static const char *prefix = LOG_DEFAULT_PREFIX;
static const char *suffix = LOG_DEFAULT_SUFFIX;

PINK_GCC_ATTR((format (printf, 4, 0)))
static void log_me(FILE *fp, int level, const char *func, const char *fmt, va_list ap)
{
	int fd, tty;
	const char *p, *s, *l;

	if (fp == NULL)
		return;
	if ((fd = fileno(fp)) < 0)
		return;

	tty = isatty(fd);

	switch (level) {
	case LOG_LEVEL_FATAL:
		p = tty ? ANSI_DARK_MAGENTA : "";
		s = tty ? ANSI_NORMAL : "";
		break;
	case LOG_LEVEL_WARNING:
	case LOG_LEVEL_ACCESS_V:
		p = tty ? ANSI_MAGENTA : "";
		s = tty ? ANSI_NORMAL : "";
		break;
	case LOG_LEVEL_INFO:
		p = tty ? ANSI_YELLOW : "";
		s = tty ? ANSI_NORMAL : "";
	default:
		p = s = "";
		break;
	}

	fprintf(fp, "%s", p);
	if (prefix)
		fprintf(fp, "%s@%lu: ", prefix, time(NULL));
	if (func)
		fprintf(fp, "%s: ", func);
	vfprintf(fp, fmt, ap);
	fprintf(fp, "%s%s", s, suffix ? suffix : "");
}

int log_init(const char *filename)
{
	if (logfp && logfp != stderr)
		fclose(logfp);

	if (logcfp == NULL)
		logcfp = stderr;

	if (filename) {
		logfp = fopen(filename, "a");
		if (logfp == NULL)
			return -errno;
		setbuf(logfp, NULL);
	} else {
		logfp = NULL;
	}

	log_debug_level(debug);
	log_debug_console_level(cdebug);

	return 0;
}

void log_close(void)
{
	if (logfp != NULL)
		fclose(logfp);
	logfp = NULL;
}

int log_console_fd(int fd)
{
	if (logcfp != stderr)
		fclose(logcfp);

	logcfp = fdopen(fd, "a");
	if (!logcfp)
		return -errno;

	return 0;
}

void log_debug_level(int debug_level)
{
	debug = debug_level | LOG_LEVEL_MINIMUM;
}

void log_debug_console_level(int debug_level)
{
	cdebug = debug_level | LOG_LEVEL_MINIMUM;
}

void log_prefix(const char *p)
{
	prefix = p;
}

void log_suffix(const char *s)
{
	suffix = s;
}

void log_msg_va(unsigned level, const char *fmt, va_list ap)
{
	va_list aq;

	if (logcfp != NULL && (level & cdebug)) {
		va_copy(aq, ap);
		log_me(logcfp, level, NULL, fmt, aq);
		va_end(aq);
	}
	if (logfp != NULL && (level & debug)) {
		va_copy(aq, ap);
		log_me(logfp, level, NULL, fmt, aq);
		va_end(aq);
	}
}

void log_msg(unsigned level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_msg_va(level, fmt, ap);
	va_end(ap);
}

void log_msg_va_f(unsigned level, const char *func, const char *fmt, va_list ap)
{
	if (logcfp != NULL && (level & cdebug))
		log_me(logcfp, level, func, fmt, ap);
	if (logfp != NULL && (level & debug))
		log_me(logfp, level, func, fmt, ap);
}

void log_msg_f(unsigned level, const char *func, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_msg_va_f(level, func, fmt, ap);
	va_end(ap);
}
