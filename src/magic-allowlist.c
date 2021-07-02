/*
 * sydbox/magic-allowlist.c
 *
 * Copyright (c) 2012, 2013, 2014, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"


int magic_set_allowlist_ppd(const void *val, syd_process_t *current)
{
	sydbox->config->allowlist_per_process_directories = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_allowlist_ppd(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config->allowlist_per_process_directories);
}

int magic_set_allowlist_sb(const void *val, syd_process_t *current)
{
	sydbox->config->allowlist_successful_bind = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_allowlist_sb(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config->allowlist_successful_bind);
}

int magic_set_allowlist_usf(const void *val, syd_process_t *current)
{
	sydbox->config->allowlist_unsupported_socket_families = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_allowlist_usf(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config->allowlist_unsupported_socket_families);
}
