/*
 * sydbox/procmatch.h
 *
 * match proc/ allowlists efficiently
 *
 * Copyright (c) 2014, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PROCMATCH_H
#define PROCMATCH_H 1

#include <syd/syd.h>

int procadd(struct sc_map_64s *map, pid_t pid);
int procdrop(struct sc_map_64s *map, pid_t pid);
int procmatch(struct sc_map_64s *map, const char *path);

#endif
