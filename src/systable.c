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
#include "sc_map.h"
/*
struct systable {
	long no;
	sysentry_t entry;
};
*/

bool systable_initialised;
struct sc_map_64v systable[ABIS_SUPPORTED];

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

	sysentry_t *entry = xmalloc(sizeof(sysentry_t));
	entry->name = name;
	entry->notify = fnotify;
	entry->exit = fexit;
	sc_map_put_64v(&systable[abi_idx], no, entry);
}

void systable_init(void)
{
	if (systable_initialised)
		return;
	for (size_t i = 0; i < ELEMENTSOF(systable); i++)
		if (!sc_map_init_64v(&systable[i], 0, 0))
			die_errno("sc_map_init_64v");
	systable_initialised = true;
}

void systable_free(void)
{
	if (!systable_initialised)
		return;
	for (size_t i = 0; i < ABIS_SUPPORTED; i++) {
		sysentry_t *entry;
		sc_map_foreach_value(&systable[i], entry)
			if (entry)
				free(entry);
		sc_map_clear_64v(&systable[i]);
		sc_map_term_64v(&systable[i]);
	}
	systable_initialised = false;
}

void systable_add(const char *name, sysfunc_t fnotify, sysfunc_t fexit)
{
	for (size_t i = 0; i < ABIS_SUPPORTED; i++) {
		int no;
		no = seccomp_syscall_resolve_name_arch(abi[i], name);
		if (no >= 0)
			systable_add_full(no, abi[i], name, fnotify, fexit);
	}
}

const sysentry_t *systable_lookup(long no, uint32_t arch)
{
	sysentry_t *entry;
	size_t abi_idx;

	for (abi_idx = 0; abi_idx < ABIS_SUPPORTED; abi_idx++) {
		if (arch != abi[abi_idx])
			continue;
		entry = sc_map_get_64v(&systable[abi_idx], no);
		if (sc_map_found(&systable[abi_idx]))
			return entry;
		return NULL;
	}

	return NULL;
}
