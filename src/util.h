/*
 * sydbox/util.h
 *
 * Copyright (c) 2010, 2011, 2012, 2014, 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is:
 *   Copyright 2010 Lennart Poettering
 * Based in part upon courier which is:
 *   Copyright 1998-2009 Double Precision, Inc
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef UTIL_H
#define UTIL_H 1

#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include "macro.h"
#include "xfunc.h"

extern bool endswith(const char *s, const char *postfix);
extern bool startswith(const char *s, const char *prefix);

extern int safe_atoi(const char *s, int *ret_i);
extern int safe_atou(const char *s, unsigned *ret_u);
extern int safe_atollu(const char *s, long long unsigned *ret_llu);
#if __WORDSIZE == 32
static inline int safe_atolu(const char *s, unsigned long *ret_u) {
	return safe_atou(s, (unsigned *) ret_u);
}
#else
static inline int safe_atolu(const char *s, unsigned long *ret_u) {
	return safe_atollu(s, (unsigned long long *) ret_u);
}
#endif /* __WORDSIZE == 32 */

extern int parse_boolean(const char *s, bool *ret_bool);
extern int parse_pid(const char *s, pid_t *ret_pid);
extern int parse_port(const char *s, unsigned *ret_port);
extern int parse_netmask_ip(const char *addr, unsigned *ret_netmask);
extern int parse_netmask_ipv6(const char *addr, unsigned *ret_netmask);

ssize_t atomic_read(int fd, void *buf, size_t count);
ssize_t atomic_write(int fd, const void *buf, size_t count);

int send_fd(int sock, int fd);

extern int waitpid_nointr(pid_t pid, int *status, int options);
extern int term_sig(int signum);

#define streq(a,b) (strcmp((a),(b)) == 0)
#define streqcase(a,b) (strcasecmp((a),(b)) == 0)

#define DEFINE_STRING_TABLE_LOOKUP(name,type) \
	static inline const char *name##_to_string(type i) { \
		if (i < 0 || i >= (type) ELEMENTSOF(name##_table)) \
			return NULL; \
		return name##_table[i]; \
	} \
	static inline type name##_from_string(const char *s) { \
		type i; \
		unsigned u = 0; \
		assert(s); \
		for (i = 0; i < (type)ELEMENTSOF(name##_table); i++) \
			if (name##_table[i] && streq(name##_table[i], s)) \
				return i; \
		if (safe_atou(s, &u) >= 0 && u < ELEMENTSOF(name##_table)) \
			return (type) u; \
		return (type) -1; \
	}

#endif /* !UTIL_H */
