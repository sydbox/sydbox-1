/*
 * sydbox/sockmap.h
 *
 * save/query socket information
 *
 * Copyright (c) 2013, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SOCKMAP_H
#define SOCKMAP_H 1

#include "sydconf.h"
#include "xfunc.h"
#include "sockmatch.h"
#include "sydhash.h"

struct sockmap {
	UT_hash_handle hh;
	struct sockinfo *info;
	int fd;
};

static inline void sockmap_add(struct sockmap **map, int fd, struct sockinfo *info)
{
	struct sockmap *s = xmalloc(sizeof(struct sockmap));
	s->fd = fd;
	s->info = info;
	HASH_ADD_INT(*map, fd, s);
}

static inline const struct sockinfo *sockmap_find(struct sockmap **map, int fd)
{
	struct sockmap *s;

	if (!*map)
		return NULL;

	HASH_FIND_INT(*map, &fd, s);
	return s ? s->info : NULL;
}

static inline void sockmap_remove(struct sockmap **map, int fd)
{
	struct sockmap *s;

	if (!*map)
		return;

	HASH_FIND_INT(*map, &fd, s);
	if (!s)
		return;
	HASH_DEL(*map, s);
	free_sockinfo(s->info);
	free(s);
}

static inline void sockmap_destroy(struct sockmap **map)
{
	struct sockmap *e, *t;

	if (!*map)
		return;

	HASH_ITER(hh, *map, e, t) {
		if (e->info)
			free_sockinfo(e->info);
		HASH_DEL(*map, e);
		free(e);
	}
	HASH_CLEAR(hh, *map);
}

#endif
