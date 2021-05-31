/*
 * sydbox/sydhash.h
 *
 * Configure uthash.h for sydbox
 *
 * Copyright (c) 2013, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SYDHASH_H
#define SYDHASH_H 1

#include "xfunc.h"
#define uthash_fatal(msg)	die("uthash internal error: %s", (msg))
#define uthash_malloc		xmalloc
#include "uthash.h"

#endif
