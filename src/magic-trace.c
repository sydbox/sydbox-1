/*
 * sydbox/magic-trace.c
 *
 * Copyright (c) 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"

int magic_set_trace_memory_access(const void *val, syd_process_t *current)
{
	if (sydbox->config.mem_access > SYDBOX_CONFIG_MEMACCESS_MAX)
		return MAGIC_RET_INVALID_VALUE;
	sydbox->config.mem_access = PTR_TO_UINT32(val);
	return MAGIC_RET_OK;
}

int magic_query_trace_memory_access(syd_process_t *current)
{
	return sydbox->config.mem_access;
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

	box->magic_lock = (enum lock_state)l;
	return MAGIC_RET_OK;
}
