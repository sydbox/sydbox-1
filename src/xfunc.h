/*
 * sydbox/xfunc.h
 *
 * Copyright (c) 2010, 2012, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef XFUNC_H
#define XFUNC_H 1

#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <syd/compiler.h>

extern void syd_abort_func(void (*func)(int));

/* bug_on & warn_on */
#define BUG_ON(expr) \
	do { \
		if (!(expr)) { \
			bug_on(#expr, __func__, __FILE__, __LINE__, NULL); \
		} \
	} \
	while (0)
#define YELL_ON(expr, ...) \
	do { \
		if (!(expr)) { \
			bug_on(#expr, __func__, __FILE__, __LINE__, __VA_ARGS__); \
		} \
	} \
	while (0)

#define WARN_ON(expr) \
	do { \
		if (!(expr)) \
			warn_on(#expr, __func__, __FILE__, __LINE__, NULL); \
	} \
	while (0)
#define TELL_ON(expr, ...) \
	do { \
		if (!(expr)) \
			warn_on(#expr, __func__, __FILE__, __LINE__, __VA_ARGS__); \
	} \
	while (0)


#define assert_not_reached() assert_not_reached_(__func__, __FILE__, __LINE__)
/* Override assert() from assert.h */
#undef assert
#ifdef NDEBUG
#define assert(expr) do {} while (0)
#else
#define assert(expr) do { BUG_ON(expr); } while (0)
#endif

extern void vsay(FILE *f, const char *fmt, va_list ap, char level)
	SYD_GCC_ATTR((format (printf, 2, 0)))
	SYD_GCC_ATTR((nonnull(1, 2)));
extern void say(const char *fmt, ...)
	SYD_GCC_ATTR((format (printf, 1, 2)));
void say_errno(const char *fmt, ...)
	SYD_GCC_ATTR((format (printf, 1, 2)));
void sayv(const char *fmt, ...)
	SYD_GCC_ATTR((format (printf, 1, 2)));

extern void bug_on(const char *expr,
		   const char *func, const char *file, size_t line,
		   const char *fmt, ...)
	SYD_GCC_ATTR((noreturn, format (printf, 5, 6)));
extern void warn_on(const char *expr,
		    const char *func, const char *file, size_t line,
		    const char *fmt, ...)
	SYD_GCC_ATTR((format (printf, 5, 6)));

extern void assert_warn_(const char *expr, const char *func, const char *file, size_t line);
extern void assert_(const char *expr, const char *func, const char *file, size_t line)
	SYD_GCC_ATTR((noreturn));
extern void assert_not_reached_(const char *func, const char *file, size_t line)
	SYD_GCC_ATTR((noreturn));

extern void die(const char *fmt, ...)
	SYD_GCC_ATTR((noreturn, format (printf, 1, 2)));
extern void die_errno(const char *fmt, ...)
	SYD_GCC_ATTR((noreturn, format (printf, 1, 2)));

extern void *syd_malloc(size_t size)
	SYD_GCC_ATTR((malloc));
extern void *syd_calloc(size_t nmemb, size_t size)
	SYD_GCC_ATTR((malloc));
extern void *syd_realloc(void *ptr, size_t size);

extern char *syd_strdup(const char *src);
extern char *syd_strndup(const char *src, size_t n);

extern int syd_asprintf(char **strp, const char *fmt, ...)
	SYD_GCC_ATTR((format (printf, 2, 3)));

extern void xfree(void *ptr);

extern void *xmalloc(size_t size)
	SYD_GCC_ATTR((malloc));
extern void *xcalloc(size_t nmemb, size_t size)
	SYD_GCC_ATTR((malloc));
extern void *xrealloc(void *ptr, size_t size);

extern char *xstrdup(const char *src);
extern char *xstrndup(const char *src, size_t n);

extern int xasprintf(char **strp, const char *fmt, ...)
	SYD_GCC_ATTR((format (printf, 2, 3)));

extern char *xgetcwd(void);

#endif
