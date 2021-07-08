/*
 * sydbox/sockmatch.c
 *
 * Match socket information
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon dovecot/src/lib/net.c which is:
 *     Copyright (c) 1999-2018 Dovecot authors
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sockmatch.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h> /* inet_pton() */
#include "pathmatch.h"

struct sockinfo *sockinfo_xdup(const struct sockinfo *src)
{
	struct sockinfo *dest;

	assert(src);

	dest = xmalloc(sizeof(struct sockinfo));
	dest->path = src->path ? xstrdup(src->path) : NULL;

	dest->addr = xmalloc(sizeof(struct pink_sockaddr));
	dest->addr->family = src->addr->family;
	dest->addr->length = src->addr->length;
	memcpy(&dest->addr->u.pad, src->addr->u.pad, sizeof(src->addr->u.pad));

	return dest;
}

struct sockmatch *sockmatch_xdup(const struct sockmatch *src)
{
	struct sockmatch *match;

	match = xmalloc(sizeof(struct sockmatch));

	match->family = src->family;
	match->str = src->str ? xstrdup(src->str) : NULL;
	switch (src->family) {
	case AF_UNIX:
		match->addr.sa_un.abstract = src->addr.sa_un.abstract;
		match->addr.sa_un.path = xstrdup(src->addr.sa_un.path);
		break;
	case AF_INET:
		match->addr.sa_in.netmask = src->addr.sa_in.netmask;
		match->addr.sa_in.port[0] = src->addr.sa_in.port[0];
		match->addr.sa_in.port[1] = src->addr.sa_in.port[1];
		memcpy(&match->addr.sa_in.addr, &src->addr.sa_in.addr,
		       sizeof(struct in_addr));
		break;
	case AF_INET6:
		match->addr.sa6.netmask = src->addr.sa6.netmask;
		match->addr.sa6.port[0] = src->addr.sa6.port[0];
		match->addr.sa6.port[1] = src->addr.sa6.port[1];
		memcpy(&match->addr.sa6.addr, &src->addr.sa6.addr,
		       sizeof(struct in6_addr));
		break;
	default:
		assert_not_reached();
	}

	return match;
}

int sockmatch_expand(const char *src, char ***buf)
{
	const char *port;
	char **list;

	assert(buf);

	if (startswith(src, MATCH_UNIX) || startswith(src, MATCH_UNIX_ABS)) {
		return pathmatch_expand(src, buf);
	} else if (startswith(src, ALIAS_LOOPBACK)) {
		list = xmalloc(sizeof(char *));
		xasprintf(&list[0], "inet:127.0.0.0/8@%s",
			  src + STRLEN_LITERAL(ALIAS_LOOPBACK));
		*buf = list;
		return 1;
	} else if (startswith(src, ALIAS_LOOPBACK6)) {
		list = xmalloc(sizeof(char *));
		xasprintf(&list[0], "inet6:::1@%s",
			  src + STRLEN_LITERAL(ALIAS_LOOPBACK6));
		*buf = list;
		return 1;
	} else if (startswith(src, ALIAS_LOCAL)) {
		port = src + STRLEN_LITERAL(ALIAS_LOCAL);
		list = xmalloc(4 * sizeof(char *));
		xasprintf(&list[0], "inet:127.0.0.0/8@%s", port);
		xasprintf(&list[1], "inet:10.0.0.0/8@%s", port);
		xasprintf(&list[2], "inet:172.16.0.0/12@%s", port);
		xasprintf(&list[3], "inet:192.168.0.0/16@%s", port);
		*buf = list;
		return 4;
	} else if (startswith(src, ALIAS_LOCAL6)) {
		port = src + STRLEN_LITERAL(ALIAS_LOCAL6);
		list = xmalloc(4 * sizeof(char *));
		xasprintf(&list[0], "inet6:::1@%s", port);
		xasprintf(&list[1], "inet6:fe80::/7@%s", port);
		xasprintf(&list[2], "inet6:fc00::/7@%s", port);
		xasprintf(&list[3], "inet6:fec0::/7@%s", port);
		*buf = list;
		return 4;
	} else {
		list = xmalloc(sizeof(char *));
		list[0] = xstrdup(src);
		*buf = list;
		return 1;
	}
	/* not reached */
}

struct sockmatch *sockmatch_new(const struct sockinfo *src)
{
	unsigned port;
	char *sun_path;
	struct sockmatch *match;

	assert(src);
	assert(src->addr);

	match = xmalloc(sizeof(struct sockmatch));
	match->family = src->addr->family;
	match->str = NULL;

	switch (match->family) {
	case AF_UNIX:
		sun_path = src->addr->u.sa_un.sun_path;
		if (path_abstract(sun_path)) {
			/* Abstract UNIX socket */
			match->addr.sa_un.abstract = true;
			match->addr.sa_un.path = xstrdup(sun_path + 1);
		} else {
			/* Non-abstract UNIX socket */
			match->addr.sa_un.abstract = false;
			if (src->path) /* resolved path */
				match->addr.sa_un.path = xstrdup(src->path);
			else
				match->addr.sa_un.path = xstrdup(sun_path);
		}
		break;
	case AF_INET:
		port = ntohs(src->addr->u.sa_in.sin_port);
		match->addr.sa_in.port[0] = port;
		match->addr.sa_in.port[1] = port;
		match->addr.sa_in.netmask = 32;
		memcpy(&match->addr.sa_in.addr, &src->addr->u.sa_in.sin_addr,
		       sizeof(struct in_addr));
		break;
	case AF_INET6:
		port = ntohs(src->addr->u.sa6.sin6_port);
		match->addr.sa6.port[0] = port;
		match->addr.sa6.port[1] = port;
		match->addr.sa6.netmask = 64;
		memcpy(&match->addr.sa6.addr, &src->addr->u.sa6.sin6_addr,
		       sizeof(struct in6_addr));
		break;
	default:
		assert_not_reached();
	}

	return match;
}

static int sockmatch_parse_unix(const char *src, struct sockmatch **buf)
{
	const char *p;
	struct sockmatch *match;

	p = src + STRLEN_LITERAL(MATCH_UNIX);
	if (p[0] == '\0')
		return -EINVAL;

	match = *buf;
	match->family = AF_UNIX;
	match->addr.sa_un.abstract = false;
	match->addr.sa_un.path = xstrdup(p);
	return 0;
}

static int sockmatch_parse_unix_abs(const char *src, struct sockmatch **buf)
{
	const char *p;
	struct sockmatch *match;

	p = src + STRLEN_LITERAL(MATCH_UNIX_ABS);
	if (p[0] == '\0')
		return -EINVAL;

	match = *buf;
	match->family = AF_UNIX;
	match->addr.sa_un.abstract = true;
	match->addr.sa_un.path = xstrdup(p);
	return 0;
}

static int sockmatch_parse_ip(int family, const char *src,
			      struct sockmatch **buf)
{
	int r;
	unsigned port0, port1, netmask;
	const char *p;
	char *ip, *range, *delim, *slash;
	struct sockmatch *match;
	struct in_addr addr;
	struct in6_addr addr6;

	match = *buf;

	switch (family) {
	case AF_INET:
		p = src + STRLEN_LITERAL(MATCH_INET);
		break;
	case AF_INET6:
		p = src + STRLEN_LITERAL(MATCH_INET6);
		break;
	default:
		return -EINVAL;
	}

	if (p[0] == '\0')
		return -EINVAL;

	/* r = 0; */
	ip = xstrdup(p);

	/* Find out port */
	range = strrchr(ip, '@');
	if (range == NULL || range[0] == '\0' || range[1] == '\0') {
		r = -EINVAL;
		goto out;
	}
	ip[range - ip] = '\0';

	/* Delimiter »-« means we have a range of ports,
	 * otherwise it's a unique port.
	 */
	range++; /* skip »@« */
	delim = strchr(range, '-');
	if (!delim) {
		r = parse_port(range, &port0);
		if (r < 0)
			goto out;
		port1 = port0;
	} else {
		range[delim - range] = '\0';
		r = parse_port(range, &port0);
		if (r < 0)
			goto out;
		delim++; /* skip »-« */
		r = parse_port(delim, &port1);
		if (r < 0)
			goto out;
	}

	/* Find out netmask */
	slash = strrchr(ip, '/');
	if (slash) {
		r = safe_atou(slash + 1, &netmask);
		if (r < 0)
			goto out;
		ip[slash - ip] = '\0';
	} else {
		r = parse_netmask_ip(ip, &netmask);
		if (r < 0)
			goto out;
	}

	errno = 0;
	if (family == AF_INET) {
		if (inet_pton(AF_INET, ip, &addr) != 1)
			r = errno ? -errno : -EINVAL;
	} else /* if (family == AF_INET6) */ {
		if (inet_pton(AF_INET6, ip, &addr6) != 1)
			r = errno ? -errno : -EINVAL;
	}
out:
	free(ip);

	if (r == 0) {
		match->family = family;

		match->addr.sa_in.port[0] = port0;
		match->addr.sa_in.port[1] = port1;

		match->addr.sa_in.netmask = netmask;

		if (family == AF_INET)
			match->addr.sa_in.addr = addr;
		else /* if (family == AF_INET6) */
			match->addr.sa6.addr = addr6;
	}

	return r;
}

int sockmatch_parse(const char *src, struct sockmatch **buf)
{
	int r;
	struct sockmatch *match;

	assert(buf);

	match = xmalloc(sizeof(struct sockmatch));

	if (startswith(src, MATCH_UNIX)) {
		r = sockmatch_parse_unix(src, &match);
		if (r < 0)
			goto fail;
	} else if (startswith(src, MATCH_UNIX_ABS)) {
		r = sockmatch_parse_unix_abs(src, &match);
		if (r < 0)
			goto fail;
	} else if (startswith(src, MATCH_INET)) {
		r = sockmatch_parse_ip(AF_INET, src, &match);
		if (r < 0)
			goto fail;
	} else if (startswith(src, MATCH_INET6)) {
		r = sockmatch_parse_ip(AF_INET6, src, &match);
		if (r < 0)
			goto fail;
	} else {
		r = -EAFNOSUPPORT;
		goto fail;
	}

	match->str = xstrdup(src);
	*buf = match;
	return 0;
fail:
	free(match);
	return r;
}

int sockmatch(const struct sockmatch *haystack, const struct pink_sockaddr *needle)
{
	const uint32_t *ip1, *ip2;
	unsigned bits, pmin, pmax, port;

	assert(haystack);
	assert(needle);

	if (needle->family != haystack->family)
		return 0;

	switch (needle->family) {
	case AF_UNIX:
		if (path_abstract(needle->u.sa_un.sun_path))
			/* Abstract UNIX socket */
			return haystack->addr.sa_un.abstract
				&& pathmatch(haystack->addr.sa_un.path,
					     needle->u.sa_un.sun_path + 1);
		/* Non-abstract UNIX socket
		 * This needs path resolving, expect the caller handled this.
		 */
		return 0;
	case AF_INET:
		bits = haystack->addr.sa_in.netmask;
		ip1 = &needle->u.sa_in.sin_addr.s_addr;
		ip2 = &haystack->addr.sa_in.addr.s_addr;
		pmin = haystack->addr.sa_in.port[0];
		pmax = haystack->addr.sa_in.port[1];
		port = ntohs(needle->u.sa_in.sin_port);
		break;
	case AF_INET6:
		bits = haystack->addr.sa6.netmask;
		ip1 = (const void *)&needle->u.sa6.sin6_addr;
		ip2 = (const void *)&haystack->addr.sa6.addr;
		pmin = haystack->addr.sa6.port[0];
		pmax = haystack->addr.sa6.port[1];
		port = ntohs(needle->u.sa6.sin6_port);
		break;
	default:
		return 0;
	}

	unsigned pos, i;
	uint32_t i1, i2, mask;

	/* check first the full 32bit ints */
	for (pos = 0, i = 0; pos + 32 <= bits; pos += 32, i++)
		if (ip1[i] != ip2[i])
			return 0;
	i1 = htonl(ip1[i]);
	i2 = htonl(ip2[i]);

	/* check the last full bytes */
	for (mask = 0xff000000; pos + 8 <= bits; pos += 8, mask >>= 8)
		if ((i1 & mask) != (i2 & mask))
			return 0;

	/* check the last bits, they're reversed in bytes */
	bits -= pos;
	for (mask = 0x80000000 >> (pos % 32); bits > 0; bits--, mask >>= 1)
		if ((i1 & mask) != (i2 & mask))
			return 0;

	return pmin <= port && port <= pmax;
}
