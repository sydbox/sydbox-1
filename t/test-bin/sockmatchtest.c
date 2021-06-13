/*
 * Test sockmatch code.
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdlib.h>
#include "pink.h"
#include "sockmatch.h"
#include "util.h"

#ifndef UNIX_PATH_MAX
# define UNIX_PATH_MAX 108
#endif

int main(int argc, char *argv[])
{
	struct sockmatch *haystack, *needle;

	if (argc != 3 ||
	    sockmatch_parse(argv[1], &haystack) < 0 ||
	    sockmatch_parse(argv[2], &needle) ||
	    haystack->family != needle->family ||
	    haystack->family == AF_UNIX)
		return EINVAL; /* 22 */

	struct pink_sockaddr addr = { .family = needle->family };
	switch (addr.family) {
#if 0
/* TODO: Test abstract UNIX socket path matching, sockmatch expects all AF_UNIX
 * sockets that are passed to it are abstract UNIX sockets and will always return false
 * for non-abstract UNIX sockets.
 */
	case AF_UNIX:
		if (!needle->addr.sa_un.path ||
		    *needle->addr.sa_un.path != '/')
			return EAFNOSUPPORT; /* 97 */
		strncpy(addr.u.sa_un.sun_path,
			needle->addr.sa_un.path,
			UNIX_PATH_MAX);
		break;
#endif
	case AF_INET:
		memcpy(&addr.u.sa_in.sin_addr,
		       &needle->addr.sa_in.addr,
		       sizeof(struct in_addr));
		addr.u.sa_in.sin_port = htons(needle->addr.sa_in.port[0]);
		break;
	case AF_INET6:
		memcpy(&addr.u.sa6.sin6_addr,
		       &needle->addr.sa6.addr,
		       sizeof(struct in6_addr));
		addr.u.sa6.sin6_port = htons(needle->addr.sa6.port[0]);
		break;
	default:
		return EAFNOSUPPORT; /* 97 */
	}

	int r = sockmatch(haystack, &addr);

	free_sockmatch(needle);
	free_sockmatch(haystack);

	return r ? EXIT_SUCCESS : ENOENT /* 2 */;
}
