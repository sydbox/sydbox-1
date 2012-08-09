/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Based in part upon coreutils which is:
 *   Copyright (C) 1996-2012 Free Software Foundation, Inc.
 *   Distributed under the terms of the GNU General Public License v3 or later
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif /* !_GNU_SOURCE */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "canonicalize.h"
#include "file.h"

/* Imported from coreutils-8.17
 * canonicalize_filename_mode() is slightly modified:
 * - Accepts a buffer as argument and returns -errno.
 */

#define MULTIPLE_BITS_SET(i) (((i) & ((i) - 1)) != 0)

/* In this file, we cannot handle file names longer than PATH_MAX.
   On systems with no file name length limit, use a fallback.  */
#ifndef PATH_MAX
# define PATH_MAX 8192
#endif

/* Return the canonical absolute name of file NAME, while treating
   missing elements according to CAN_MODE.  A canonical name
   does not contain any ".", ".." components nor any repeated file name
   separators ('/') or, depending on other CAN_MODE flags, symlinks.
   Whether components must exist or not depends on canonicalize mode.
   The result is malloc'd.  */

int canonicalize_filename_mode(const char *name, can_mode_t can_mode, char **path)
{
	int linkcount = 0, retval = 0;
	char *rname, *dest, *extra_buf = NULL;
	const char *start;
	const char *end;
	const char *rname_limit;
	size_t extra_len = 0;
	int saved_errno;
	int can_flags = can_mode & ~CAN_MODE_MASK;
	can_mode &= CAN_MODE_MASK;
	bool logical = can_flags & CAN_NOLINKS;

	if (!name || name[0] == '\0' || name[0] != '/')
		return -EINVAL;

	rname = malloc(PATH_MAX * sizeof(char));
	if (!rname)
		return -ENOMEM;
	rname_limit = rname + PATH_MAX;
	rname[0] = '/';
	dest = rname + 1;

	for (start = name; *start; start = end) {
		/* Skip sequence of multiple file name separators.  */
		while (*start == '/')
			++start;

		/* Find end of component */
		for (end = start; *end && *end != '/'; ++end)
			/* void  */;

		if (end - start == 0)
			break;
		else if (end - start == 1 && start[0] == '.')
			/* void */;
		else if (end - start == 2 && start[0] == '.' && start[1] == '.') {
			/* Back up previous component, ignore if at root
			 * already. */
			if (dest > rname + 1) {
				while ((--dest)[-1] != '/')
					/* void */;
			}
		}
		else {
			struct stat st;

			if (dest[-1] != '/')
				*dest++ = '/';

			if (dest + (end - start) >= rname_limit) {
				ptrdiff_t dest_offset = dest - rname;
				size_t new_size = rname_limit - rname;

				if (end - start + 1 > PATH_MAX)
					new_size += end - start + 1;
				else
					new_size += PATH_MAX;

				rname = realloc(rname, new_size);
				if (!rname)
					return -ENOMEM;
				rname_limit = rname + new_size;

				dest = rname + dest_offset;
			}

			dest = memcpy(dest, start, end - start);
			dest += end - start;
			*dest = '\0';

			if (logical && (can_mode == CAN_MISSING)) {
				/* Avoid the stat in this case as it's inconsequential.
				 * i.e. we're neither resolving symlinks or testing
				 * component existence. */
				st.st_mode = 0;
			} else if ((logical ? stat(rname, &st) : lstat(rname, &st)) != 0) {
				saved_errno = errno;
				if (can_mode == CAN_EXISTING)
					goto error;
				if (can_mode == CAN_ALL_BUT_LAST) {
					if (end[strspn(end, "/")] || saved_errno != ENOENT)
						goto error;
					continue;
				}
				st.st_mode = 0;
			}

			if (S_ISLNK(st.st_mode)) {
				char *buf;
				size_t n, len;

				/* Protect against infinite loops */
#ifndef SYDBOX_MAXSYMLINKS
#ifdef MAXSYMLINKS
#define SYDBOX_MAXSYMLINKS MAXSYMLINKS
#else
#define SYDBOX_MAXSYMLINKS 32
#endif
#endif
				if (linkcount++ > SYDBOX_MAXSYMLINKS) {
					if (can_mode == CAN_MISSING)
						continue;
					saved_errno = ELOOP;
					goto error;
				}

				if (readlink_alloc(rname, &buf) < 0) {
					if (can_mode == CAN_MISSING && errno != ENOMEM)
						continue;
					saved_errno = errno;
					goto error;
				}

				n = strlen(buf);
				len = strlen(end);

				if (!extra_len) {
					extra_len = (n + len + 1) > PATH_MAX
						? (n + len + 1)
						: PATH_MAX;
					extra_buf = malloc(extra_len * sizeof(char));
				}
				else if (n + len + 1 > extra_len) {
					extra_len = n + len + 1;
					extra_buf = realloc(extra_buf, extra_len * sizeof(char));
				}

				if (!extra_buf) {
					free(rname);
					return -ENOMEM;
				}

				/* Careful here, end may be a pointer into
				 * extra_buf... */
				memmove(&extra_buf[n], end, len + 1);
				name = end = memcpy(extra_buf, buf, n);

				if (buf[0] == '/')
					dest = rname + 1; /* It's an absolute symlink */
				else {
					/* Back up to previous component,
					 * ignore if at root already. */
					if (dest > rname + 1) {
						while ((--dest)[-1] != '/')
							/* void */;
					}
				}

				free(buf);
			}
			else {
				if (!S_ISDIR(st.st_mode) && *end && (can_mode != CAN_MISSING)) {
					saved_errno = ENOTDIR;
					goto error;
				}
			}
		}
	}

	if (dest > rname + 1 && dest[-1] == '/')
		--dest;
	*dest = '\0';

	if (rname_limit != dest + 1) {
		rname = realloc(rname, dest - rname + 1);
		if (!rname) {
			saved_errno = ENOMEM;
			goto error;
		}
	}

	if (extra_buf)
		free(extra_buf);
	*path = rname;
	return 0;

error:
	retval = -saved_errno;
	if (extra_buf)
		free(extra_buf);
	if (rname)
		free(rname);
	return retval;
}