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

#include "syd-conf.h"
#include "xfunc.h"
#include "sc_map.h"
#include "sockmatch.h"

static inline void sockmap_add(struct sc_map_64v *map,
			       unsigned long long inode,
			       struct sockinfo *info)
{
	struct sockinfo *info_old;

	info_old = syd_map_get_64v(map, inode);
	if (sc_map_found(map)) {
		sc_map_del_64v(map, inode);
		if (info_old)
			free_sockinfo(info_old);
	}
	sc_map_put_64v(map, (uint64_t)inode, info);
}

static inline const struct sockinfo *sockmap_find(struct sc_map_64v *map,
						  unsigned long long inode)
{
	if (!map)
		return NULL;

	struct sockinfo *info = syd_map_get_64v(map, inode);
	if (sc_map_found(map))
		return info;
	return NULL;
}

static inline void sockmap_remove(struct sc_map_64v *map,
				  unsigned long long inode)
{
	if (!map)
		return;

	struct sock_info *info = syd_map_get_64v(map, inode);
	if (!sc_map_found(map))
		return;
	sc_map_del_64v(map, inode);
	free_sockinfo(info);
}

static inline void sockmap_destroy(struct sc_map_64v *map)
{
	uint64_t inode;
	struct sockinfo *info;

	if (!map)
		return;

	sc_map_foreach(map, inode, info) {
		sc_map_del_64v(map, inode);
		if (info)
			free_sockinfo(info);
	}
	sc_map_term_64v(map);
}

#endif
