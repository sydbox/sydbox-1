/*
 * sydbox/magic-restrict.c
 *
 * Copyright (c) 2013, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"

#include "macro.h"

int magic_set_restrict_fcntl(const void *val, syd_process_t *current)
{
	sydbox->config.restrict_file_control = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_restrict_fcntl(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.restrict_file_control);
}

int magic_set_restrict_mmap(const void *val, syd_process_t *current)
{
	sydbox->config.restrict_mmap = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_restrict_mmap(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.restrict_mmap);
}

int magic_set_restrict_shm_wr(const void *val, syd_process_t *current)
{
	sydbox->config.restrict_shared_memory_writable = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_restrict_shm_wr(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.restrict_shared_memory_writable);
}
