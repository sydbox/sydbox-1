/*
 * sydbox/sydconf.h
 *
 * Copyright (c) 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SYDCONF_H
#define SYDCONF_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef SYDBOX_API_VERSION
# error "SYDBOX_API_VERSION is not defined!"
#endif

#include <limits.h>
#include <unistd.h>

#ifndef PAGE_SIZE
# define PAGE_SIZE sysconf(_SC_PAGESIZE)
#endif
#define MAX_ARG_STRLEN (PAGE_SIZE * 32)
#define MAX_ARG_STRINGS 0x7FFFFFFF

/* Configuration */
#ifndef SYDBOX_PATH_MAX
# if defined(PATH_MAX)
#  define SYDBOX_PATH_MAX (PATH_MAX+1)
# elif defined(MAXPATHLEN)
#  define SYDBOX_PATH_MAX (MAXPATHLEN+1)
# else
#  define SYDBOX_PATH_MAX (256+1)
# endif
#endif

#ifndef SYDBOX_MAXSYMLINKS
# if defined(SYMLOOP_MAX)
#  define SYDBOX_MAXSYMLINKS SYMLOOP_MAX
# elif defined(MAXSYMLINKS)
#  define SYDBOX_MAXSYMLINKS MAXSYMLINKS
# else
#  define SYDBOX_MAXSYMLINKS 32
# endif
#endif

#ifndef SYDBOX_FNAME_EXT
# define SYDBOX_FNAME_EXT "syd-"
#endif

#ifndef SYDBOX_API_EXT
# define SYDBOX_API_EXT SYDBOX_FNAME_EXT STRINGIFY(SYDBOX_API_VERSION)
#endif

#ifndef SYDBOX_PROFILE_CHAR
# define SYDBOX_PROFILE_CHAR '@'
#endif

#ifndef SYDBOX_CONFIG_ENV
# define SYDBOX_CONFIG_ENV "SYDBOX_CONFIG"
#endif

#ifndef SYDBOX_MAGIC_PREFIX
# define SYDBOX_MAGIC_PREFIX "/dev/sydbox"
#endif

#ifndef SYDBOX_MAGIC_SET_CHAR
# define SYDBOX_MAGIC_SET_CHAR ':'
#endif

#ifndef SYDBOX_MAGIC_QUERY_CHAR
# define SYDBOX_MAGIC_QUERY_CHAR '?'
#endif

#ifndef SYDBOX_MAGIC_APPEND_CHAR
# define SYDBOX_MAGIC_APPEND_CHAR '+'
#endif

#ifndef SYDBOX_MAGIC_REMOVE_CHAR
# define SYDBOX_MAGIC_REMOVE_CHAR '-'
#endif

#ifndef SYDBOX_MAGIC_EXEC_CHAR
# define SYDBOX_MAGIC_EXEC_CHAR '!'
#endif /* !SYDBOX_MAGIC_EXEC_CHAR */

#ifndef SYDBOX_NO_GETDENTS
# undef SYDBOX_NO_GETDENTS
#endif

#endif
