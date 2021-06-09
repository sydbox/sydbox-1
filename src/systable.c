/*
 * sydbox/systable.c
 *
 * Copyright (c) 2010, 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"
#include <errno.h>
#include <stdlib.h>
#include "pink.h"
#include "sydhash.h"

struct systable {
	long no;
	sysentry_t entry;
	UT_hash_handle hh;
};

static struct systable *systable[PINK_ABIS_SUPPORTED];

void systable_add_full(long no, short abi, const char *name,
		       sysfunc_t fnotify, sysfunc_t fexit)
{
	struct systable *s;

	s = xmalloc(sizeof(struct systable));
	s->no = no;
	s->entry.name = name;
	s->entry.notify = fnotify;
	s->entry.exit = fexit;

	HASH_ADD_INT(systable[abi], no, s);
}

void systable_init(void)
{
	;
}

void systable_free(void)
{
	for (short abi = 0; abi < PINK_ABIS_SUPPORTED; abi++) {
		struct systable *s, *tmp;
		HASH_ITER(hh, systable[abi], s, tmp) {
			HASH_DEL(systable[abi], s);
			free(s);
		}
		HASH_CLEAR(hh, systable[abi]);
	}
}

void systable_add(const char *name, sysfunc_t fnotify, sysfunc_t fexit)
{
	long no;

	for (short abi = 0; abi < PINK_ABIS_SUPPORTED; abi++) {
		no = pink_lookup_syscall(name, abi);
		if (no != -1)
			systable_add_full(no, abi, name, fnotify, fexit);
	}
}

const sysentry_t *systable_lookup(long no, short abi)
{
	struct systable *s;

	HASH_FIND_INT(systable[abi], &no, s);
	return s ? &(s->entry) : NULL;
}
