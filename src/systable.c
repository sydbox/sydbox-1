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

static struct systable *systable[ABIS_SUPPORTED];

void systable_add_full(long no, uint32_t arch, const char *name,
		       sysfunc_t fnotify, sysfunc_t fexit)
{
	int abi_idx = 0;
	for (size_t i = 0; i < ABIS_SUPPORTED; i++) {
		if (abi[i] == arch) {
			abi_idx = i;
			break;
		}
	}

	struct systable *s = xmalloc(sizeof(struct systable));
	s->no = no;
	s->entry.name = name;
	s->entry.notify = fnotify;
	s->entry.exit = fexit;

	HASH_ADD_INT(systable[abi_idx], no, s);
}

void systable_init(void)
{
	;
}

void systable_free(void)
{
	for (size_t i = 0; i < ABIS_SUPPORTED; i++) {
		struct systable *s, *tmp;
		HASH_ITER(hh, systable[i], s, tmp) {
			HASH_DEL(systable[i], s);
			free(s);
		}
		HASH_CLEAR(hh, systable[i]);
	}
}

void systable_add(const char *name, sysfunc_t fnotify, sysfunc_t fexit)
{
	int no;

	for (size_t i = 0; i < ABIS_SUPPORTED; i++) {
		no = seccomp_syscall_resolve_name_arch(abi[i], name);
		if (no >= 0)
			systable_add_full(no, abi[i], name, fnotify, fexit);
	}
}

const sysentry_t *systable_lookup(long no, uint32_t arch)
{
	struct systable *s;
	size_t abi_idx;

	for (abi_idx = 0; abi_idx < ABIS_SUPPORTED; abi_idx++) {
		if (arch != abi[abi_idx])
			continue;
		HASH_FIND_INT(systable[abi_idx], &no, s);
		return s ? &(s->entry) : NULL;
	}

	return NULL;
}
