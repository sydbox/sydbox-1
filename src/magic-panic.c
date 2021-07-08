/*
 * sydbox/magic-panic.c
 *
 * Copyright (c) 2012, 2013, 2014, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "syd-box.h"

int magic_set_violation_decision(const void *val, syd_process_t *current)
{
	int d;
	const char *str = val;

	d = violation_decision_from_string(str);
	if (d < 0)
		return MAGIC_RET_INVALID_VALUE;

	sydbox->config.violation_decision = (enum violation_decision)d;
	return MAGIC_RET_OK;
}

int magic_set_violation_exit_code(const void *val, syd_process_t *current)
{
	sydbox->config.violation_exit_code = PTR_TO_INT(val);
	return MAGIC_RET_OK;
}

int magic_set_violation_raise_fail(const void *val, syd_process_t *current)
{
	sydbox->config.violation_raise_fail = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_violation_raise_fail(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.violation_raise_fail);
}

int magic_set_violation_raise_safe(const void *val, syd_process_t *current)
{
	sydbox->config.violation_raise_safe = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_violation_raise_safe(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.violation_raise_safe);
}
