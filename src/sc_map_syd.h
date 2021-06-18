/*
 * sydbox/sc_map_syd.h
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SC_MAP_SYD_H
#define SC_MAP_SYD_H

#include "sc_map.h"

#define sc_map_freed(map) \
	((map)->load_fac == 0 &&\
	 (map)->remap == 0 &&\
	 (map)->used == false &&\
	 (map)->found == false)
#endif
