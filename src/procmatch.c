/*
 * sydbox/procmatch.c
 *
 * match & store proc/$pid allowlists efficiently
 *
 * Copyright (c) 2014, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "syd-conf.h"

#include <stdlib.h>

#include "procmatch.h"
#include "pathmatch.h"
#include "sc_map.h"

int procadd(struct syd_map_64s *map, pid_t pid)
{
	syd_map_get_64s(map, pid);
	if (syd_map_found(map))
		return 0;

	char *p;
	xasprintf(&p, "/proc/%u/***", pid);
	syd_map_put_64s(map, pid, p);

	return 1;
}

int procdrop(struct syd_map_64s *map, pid_t pid)
{
	char *p;

	p = (char *)syd_map_del_64s(map, pid);
	if (!syd_map_found(map))
		return 0;
	free(p);

	return 1;
}

int procmatch(struct syd_map_64s *map, const char *path)
{
	pid_t pid;
	const char *match;

	syd_map_foreach(map, pid, match) {
		if (pathmatch(match, path))
			return 1;
	}

	return 0;
}
