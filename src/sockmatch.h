/*
 * sydbox/sockmatch.h
 *
 * match socket information
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SOCKMATCH_H
#define SOCKMATCH_H 1

#include "sydconf.h"

#include <stdbool.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/un.h>
#include "pink.h"

#define MATCH_UNIX	"unix:"
#define MATCH_UNIX_ABS	"unix-abstract:"
#define MATCH_INET	"inet:"
#define MATCH_INET6	"inet6:"

#define ALIAS_LOOPBACK	"LOOPBACK@"
#define ALIAS_LOCAL	"LOCAL@"
#define ALIAS_LOCAL6	"LOCAL6@"
#define ALIAS_LOOPBACK6	"LOOPBACK6@"

struct sockinfo {
	char *path; /* resolved UNIX socket address */
	struct pink_sockaddr *addr;
};

struct sockmatch {
	union {
		struct {
			char *path;
			bool abstract;
		} sa_un;

		struct {
			unsigned netmask;
			unsigned port[2];
			struct in_addr addr;
		} sa_in;

		struct {
			unsigned netmask;
			unsigned port[2];
			struct in6_addr addr;
		} sa6;
	} addr;

	/* The actual pattern, useful for removals */
	char *str;

	int family;
};

struct sockinfo *sockinfo_xdup(const struct sockinfo *src);
struct sockmatch *sockmatch_xdup(const struct sockmatch *src);

/* Expand network aliases and unix wildmatch patterns */
int sockmatch_expand(const char *src, char ***buf);

struct sockmatch *sockmatch_new(const struct sockinfo *src);
int sockmatch_parse(const char *src, struct sockmatch **buf);

int sockmatch(const struct sockmatch *haystack, const struct pink_sockaddr *needle);

#define path_abstract(path) ((path)[0] == '\0' && (path)[1] != '\0')

static inline void free_sockinfo(void *data)
{
	struct sockinfo *info = data;

	if (info->path)
		free(info->path);
	free(info->addr);
	free(info);
}

static inline void free_sockmatch(void *data)
{
	struct sockmatch *match = data;

	if (match->str)
		free(match->str);
	if (match->family == AF_UNIX && match->addr.sa_un.path)
		free(match->addr.sa_un.path);
	free(match);
}

#endif
