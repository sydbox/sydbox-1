/*
 * sydbox/magic-trace.c
 *
 * Copyright (c) 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"

int magic_set_trace_memory_access(const void *val, syd_process_t *current)
{
	if (PTR_TO_UINT32(val) > SYDBOX_CONFIG_MEMACCESS_MAX)
		return MAGIC_RET_INVALID_VALUE;
	sydbox->config.mem_access = PTR_TO_UINT32(val);
	return MAGIC_RET_OK;
}

int magic_query_trace_memory_access(syd_process_t *current)
{
	return sydbox->config.mem_access;
}

int magic_set_trace_program_checksum(const void *val, syd_process_t *current)
{
	if (PTR_TO_UINT32(val) > 2)
		return MAGIC_RET_INVALID_VALUE;
	sydbox->config.prog_hash = PTR_TO_UINT32(val);
	return MAGIC_RET_OK;
}

int magic_query_trace_program_checksum(syd_process_t *current)
{
	return sydbox->config.prog_hash;
}

int magic_set_trace_use_toolong_hack(const void *val, syd_process_t *current)
{
	sydbox->config.use_toolong_hack = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_trace_use_toolong_hack(syd_process_t *current)
{
	return sydbox->config.use_toolong_hack;
}

int magic_set_trace_magic_lock(const void *val, syd_process_t *current)
{
	int l;
	const char *str = val;
	sandbox_t *box = box_current(current);

	l = lock_state_from_string(str);
	if (l < 0)
		return MAGIC_RET_INVALID_VALUE;

	box->magic_lock = l;
	if (!current)
		return MAGIC_RET_OK;

#if 0
	say("set magic lock to %u<%s> for process:%u<%s,%s,%u-%u>.",
	    l, lock_state_to_string(l),
	    current->pid, current->comm, current->hash,
	    current->ppid, current->tgid);
#endif

	/* Set magic lock for grand ppid and grand tgid too,
	 * so that tools that execute have their parents'
	 * magic sandbox locked as well which is practical
	 * for e.g: pandora sandbox lock. */
	syd_process_t *p;

	pid_t grand_ppid = -1;
	pid_t grand_tgid = -1;
	int pfd = syd_proc_open(current->tgid);
	if (pfd >= 0) {
		syd_proc_parents(pfd, &grand_ppid, &grand_tgid);
		close(pfd);
	}

	p = process_lookup(current->tgid);
	if (p) { box = box_current(p); box->magic_lock = l; }
	p = process_lookup(current->ppid);
	if (p) { box = box_current(p); box->magic_lock = l; }
	if (grand_ppid >= 0) {
		p = process_lookup(grand_ppid);
		if (p) { box = box_current(p); box->magic_lock = l; }
	}
	if (grand_tgid >= 0) {
		p = process_lookup(grand_tgid);
		if (p) { box = box_current(p); box->magic_lock = l; }
	}

	return MAGIC_RET_OK;
}
