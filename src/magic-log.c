/*
 * sydbox/magic-log.c
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "syd-box.h"
#include <ctype.h>

SYD_GCC_ATTR((nonnull(1, 3)))
static int magic_set_log_fd(const void *restrict val,
			    const syd_process_t *restrict current,
			    int *log_fd)
{
	const char *filename = val;

	int fd;
	if (isdigit(filename[0])) {
		fd = atoi(filename);
		if (fd <= 0)
			return MAGIC_RET_INVALID_VALUE;
	} else {
		fd = openat(AT_FDCWD, filename, O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0600);
		if (fd < 0) {
			say_errno("magic_set_log_file");
			return MAGIC_RET_INVALID_VALUE;
		}
	}

	if (*log_fd >= STDERR_FILENO)
		close(*log_fd);
	*log_fd = fd;

	return MAGIC_RET_OK;
}

SYD_GCC_ATTR((nonnull(1)))
int magic_set_log_exec_fd(const void *restrict val, syd_process_t *current)
{
	return magic_set_log_fd(val, current,
				&sydbox->config.fd_log_exec);
}

SYD_GCC_ATTR((nonnull(1)))
int magic_set_log_read_fd(const void *restrict val, syd_process_t *current)
{
	return magic_set_log_fd(val, current,
				&sydbox->config.fd_log_read);
}

SYD_GCC_ATTR((nonnull(1)))
int magic_set_log_write_fd(const void *restrict val, syd_process_t *current)
{
	return magic_set_log_fd(val, current,
				&sydbox->config.fd_log_write);
}

SYD_GCC_ATTR((nonnull(1)))
int magic_set_log_network_bind_fd(const void *restrict val, syd_process_t *current)
{
	return magic_set_log_fd(val, current,
				&sydbox->config.fd_log_network_bind);
}

SYD_GCC_ATTR((nonnull(1)))
int magic_set_log_network_connect_fd(const void *restrict val, syd_process_t *current)
{
	return magic_set_log_fd(val, current,
				&sydbox->config.fd_log_network_connect);
}
