/*
 * sydbox/magic-whitelist.c
 *
 * Copyright (c) 2012, 2013, 2014, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"

#include <stdbool.h>
#include <stdlib.h>
#include "pink.h"

#include "macro.h"

int magic_set_whitelist_ppd(const void *val, syd_process_t *current)
{
	sydbox->config.whitelist_per_process_directories = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_whitelist_ppd(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.whitelist_per_process_directories);
}

int magic_set_whitelist_sb(const void *val, syd_process_t *current)
{
	sydbox->config.whitelist_successful_bind = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_whitelist_sb(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.whitelist_successful_bind);
}

int magic_set_whitelist_usf(const void *val, syd_process_t *current)
{
	sydbox->config.whitelist_unsupported_socket_families = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_whitelist_usf(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.whitelist_unsupported_socket_families);
}
