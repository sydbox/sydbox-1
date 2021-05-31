/*
 * sydbox/bsd-compat.h
 *
 * Copyright (c) 2013, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef BSD_COMPAT_H
#define BSD_COMPAT_H

#define RPATH_EXIST		0 /* all components must exist */
#define RPATH_NOLAST		1 /* all but last component must exist */
#define RPATH_NOFOLLOW		4 /* do not expand symbolic links */
#define RPATH_MASK		(RPATH_EXIST|RPATH_NOLAST)

int realpath_mode(const char * restrict path, unsigned mode, char **buf);

size_t strlcat(char * restrict dst, const char * restrict src, size_t siz);
size_t strlcpy(char * restrict dst, const char * restrict src, size_t siz);

#endif
