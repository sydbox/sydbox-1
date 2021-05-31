/*
 * sydbox/procmatch.c
 *
 * match & store proc/$pid whitelists efficiently
 *
 * Copyright (c) 2014, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydconf.h"

#include <stdlib.h>
#include <stdio.h>

#include "xfunc.h"
#include "procmatch.h"
#include "pathmatch.h"

int procadd(proc_pid_t **pp, pid_t pid)
{
	proc_pid_t *npp;

	HASH_FIND_INT(*pp, &pid, npp);
	if (npp)
		return 0;

	npp = xmalloc(sizeof(proc_pid_t));
	npp->pid = pid;
	sprintf(npp->path, "/proc/%u/***", pid);

	HASH_ADD_INT(*pp, pid, npp);
	return 1;
}

int procdrop(proc_pid_t **pp, pid_t pid)
{
	proc_pid_t *opp = NULL;

	HASH_FIND_INT(*pp, &pid, opp);
	if (!opp)
		return 0;

	HASH_DEL(*pp, opp);
	free(opp);
	return 1;
}

int procmatch(proc_pid_t **pp, const char *path)
{
	proc_pid_t *node, *tmp;

	HASH_ITER(hh, *pp, node, tmp) {
		if (pathmatch(node->path, path))
			return 1;
	}

	return 0;
}
