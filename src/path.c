/*
 * sydbox/path.c
 *
 * Path related utilities
 *
 * Copyright (c) 2012, 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is:
 *   Copyright (C) 2010-2012 Lennart Poettering
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "syd-conf.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "path.h"
#include "xfunc.h"

/* Makes every item in the list an absolute path by prepending
 * the prefix, if specified and necessary */
char *path_make_absolute(const char *p, const char *prefix)
{
	int r;
	char *rc = NULL;

	if (path_is_absolute(p) || !prefix)
		return syd_strdup(p);

	/*
	 * Security: Handle untrusted input safely and only
	 * allow in alphanumeric characters and spaces.
	 * Ensure we never overflow the path buffers by
	 * limiting length to SYDBOX_PATH_MAX.
	 */
	rc = malloc(3072 + 1024 + 1/*slash*/ + 1/*nul byte*/);
	if (!rc)
		return NULL;
	errno = 0;
	if (p && p[0] != '\0')
		r = sscanf(rc, "%3072[^\n]/%1024[^\n]",
			   (char *)prefix,
			   (char *)p);
	else
		r = sscanf(rc, "%4096[^\n]",
			   (char *)prefix);
	if (!errno)
		return rc;
	int save_errno = errno;
	free(rc);
	errno = save_errno;
	return NULL;
}

char *path_kill_slashes(char *path)
{
	char *f, *t;
	bool slash = false;

	/* Removes redundant inner and trailing slashes. Modifies the
	 * passed string in-place.
	 *
	 * ///foo///bar/ becomes /foo/bar
	 */

	for (f = path, t = path; *f != '\0'; f++) {

		if (*f == '/') {
			slash = true;
			continue;
		}

		if (slash) {
			slash = false;
			*(t++) = '/';
		}

		*(t++) = *f;
	}

	/* Special rule, if we are talking of the root directory, a
	trailing slash is good */

	if (t == path && slash)
		*(t++) = '/';

	*t = '\0';
	return path;
}
