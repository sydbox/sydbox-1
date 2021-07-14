/*
 * sydbox/magic-restrict.c
 *
 * Copyright (c) 2013, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "syd-box.h"

int magic_set_kill(const void *val, syd_process_t *current)
{
	int r;
	unsigned u_val = PTR_TO_UINT(val);

	switch (u_val) {
	case SIGKILL:
	case SIGTERM:
	case SIGCONT:
	case SIGSTOP:
	case SIGHUP:
		break;
	default:
		return MAGIC_RET_INVALID_VALUE;
	}
	if (sydbox->execve_pidfd >= 0 &&
	    (r = syd_pidfd_send_signal(sydbox->execve_pidfd, u_val, NULL, 0)) < 0 &&
	    r != -ESRCH) {
		errno = -r;
		say_errno("syd_pidfd_send_signal");
	}
	return MAGIC_RET_OK;
}

int magic_get_kill(syd_process_t *current)
{
	return MAGIC_BOOL(true);
}

int magic_set_restrict_general(const void *val, syd_process_t *current)
{
	unsigned u_val = PTR_TO_UINT(val);
	if (u_val > 3)
		return MAGIC_RET_INVALID_VALUE;
	sydbox->config.restrict_general = u_val;
	return MAGIC_RET_OK;
}

int magic_query_restrict_general(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.restrict_general > 0);
}

int magic_set_restrict_id(const void *val, syd_process_t *current)
{
	sydbox->config.restrict_id = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_restrict_id(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.restrict_id);
}

int magic_set_restrict_sysinfo(const void *val, syd_process_t *current)
{
	sydbox->config.restrict_sysinfo = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_restrict_sysinfo(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.restrict_sysinfo);
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

int magic_set_restrict_ioctl(const void *val, syd_process_t *current)
{
	sydbox->config.restrict_ioctl = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_restrict_ioctl(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.restrict_ioctl);
}

int magic_set_restrict_shm_wr(const void *val, syd_process_t *current)
{
	sydbox->config.restrict_shm_wr = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_restrict_shm_wr(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.restrict_shm_wr);
}
