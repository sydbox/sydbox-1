/*
 * sydbox/path.h
 *
 * Path related utilities
 *
 * Copyright (c) 2012, 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is:
 *   Copyright (C) 2010-2012 Lennart Poettering
 * Distributed under the terms of the GNU Lesser General Public License v2.1 or later
 */

#ifndef PATH_H
#define PATH_H 1

extern char *path_make_absolute(const char *p, const char *prefix);
extern char *path_kill_slashes(char *path);

static inline bool path_is_absolute(const char *p)
{
	return p[0] == '/';
}

#endif /* !PATH_H */
