/*
 * sydbox/pathlookup.c
 *
 * Copyright (c) 2012, 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon strace which is:
 *   Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 *   Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 *   Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 *   Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * Released under the terms of the 3-clause BSD license
 */

#include "sydbox.h"
#include "pathlookup.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Look up path using `PATH' environment variable.
 * Returns 0 on success, -1 on failure.
 */
int path_lookup(const char *filename, char **buf)
{
	struct stat statbuf;
	char pathname[SYDBOX_PATH_MAX];
	size_t filename_len;

	pathname[0] = '\0';
	filename_len = strlen(filename);

	if (filename_len > sizeof(pathname) - 1)
		return -ENAMETOOLONG;
	if (strchr(filename, '/'))
		strcpy(pathname, filename);
#ifdef SYDBOX_USE_DEBUGGING_EXEC
	/*
	 * Debuggers customarily check the current directory
	 * first regardless of the path but doing that gives
	 * security geeks a panic attack.
	 */
	else if (stat(filename, &statbuf) == 0)
		strcpy(pathname, filename);
#endif /* SYDBOX_USE_DEBUGGING_EXEC */
	else {
		const char *path;
		size_t m, n, len;

		for (path = getenv("PATH"); path && *path; path += m) {
			const char *colon = strchr(path, ':');
			if (colon) {
				n = colon - path;
				m = n + 1;
			}
			else
				m = n = strlen(path);
			if (n == 0) {
				if (!getcwd(pathname, SYDBOX_PATH_MAX))
					continue;
				len = strlen(pathname);
			} else if (n > sizeof(pathname) - 1) {
				continue;
			} else {
				strncpy(pathname, path, n);
				len = n;
			}
			if (len && pathname[len - 1] != '/')
				pathname[len++] = '/';
			if (filename_len + len > sizeof(pathname) - 1)
				continue;
			strcpy(pathname + len, filename);
			if (stat(pathname, &statbuf) == 0 &&
			    /* Accept only regular files
			       with some execute bits set.
			       XXX not perfect, might still fail */
			    S_ISREG(statbuf.st_mode) &&
			    (statbuf.st_mode & 0111))
				break;
		}
		if (!path && !*path)
			pathname[0] = '\0';
	}
	if (stat(pathname, &statbuf) < 0) {
		return -errno;
	}

	*buf = strdup(pathname);
	if (*buf == NULL)
		return -ENOMEM;
	return 0;
}
