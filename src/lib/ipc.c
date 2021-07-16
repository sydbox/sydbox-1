/*
 * libsyd/about.c
 *
 * libsyd /dev/sydbox Magic IPC API Interface
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "HELPME.h"
#include <syd/syd.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

static inline int syd_stat(const char *path)
{
	struct stat buf;
	return (stat(path, &buf) != 0) ? -errno : 0;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_api(uint8_t *api)
{
	int r;

	if ((r = syd_stat("/dev/sydbox/" syd_str(SYDBOX_API_VERSION))) == 0) {
		*api = SYDBOX_API_VERSION;
		return 0;
	}
	if (r < 0 && r != -ENOENT && r != -EINVAL)
		return r;
	if ((r = syd_stat("/dev/sydbox/2")) == 0) {
		*api = 2;
		return 0;
	}
	if (r < 0 && r != -ENOENT && r != -EINVAL)
		return r;
	if ((r = syd_stat("/dev/sydbox/1")) == 0) {
		*api = 1;
		return 0;
	}
	if (r < 0 && r != -ENOENT && r != -EINVAL)
		return r;
	return 0;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_check(bool *check)
{
	int r;

	if ((r = syd_stat("/dev/sydbox/" syd_str(SYDBOX_API_VERSION)) < 0)) {
		if (r == -ENOENT || r == -EPERM) {
			*check = false;
			return 0;
		}
		return r;
	}
	*check = true;
	return 0;
}

int syd_ipc_lock(void)
{
	return syd_stat("/dev/sydbox/core/trace/magic_lock:on");
}

int syd_ipc_exec_lock(void)
{
	return syd_stat("/dev/sydbox/core/trace/magic_lock:exec");
}

int syd_ipc_use_toolong_hack(bool on)
{
	if (on)
		return syd_stat("/dev/sydbox/core/trace/use_toolong_hack:true");
	else
		return syd_stat("/dev/sydbox/core/trace/use_toolong_hack:false");
}

int syd_ipc_kill(uint8_t signum)
{
	if (signum >= 100)
		return -EINVAL;

	char p[sizeof("/dev/sydbox/kill:") + 3];
	sprintf(p, "/dev/sydbox/kill:%u", signum);
	return syd_stat(p);
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_kill_if_match(const char *pattern, char addrem)
{
	int r;
	char *p;

	if (addrem != '+' || addrem != '-')
		return -EINVAL;
	if (asprintf(&p, "/dev/sydbox/exec/kill_if_match%c%.256s", addrem, pattern) < 0)
		return -errno;

	r = syd_stat(p);
	free(p);
	return r;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_get_exec(bool *on)
{
	int r;

	if ((r = syd_stat("/dev/sydbox/core/sandbox/exec?")) < 0) {
		if (r == -ENOENT) {
			*on = false;
			return 0;
		}
		return r;
	}

	*on = true;
	return 0;
}

int syd_ipc_set_exec(bool on)
{
	if (on)
		return syd_stat("/dev/sydbox/core/sandbox/exec:deny");
	else
		return syd_stat("/dev/sydbox/core/sandbox/exec:allow");
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_get_read(bool *on)
{
	int r;

	if ((r = syd_stat("/dev/sydbox/core/sandbox/read?")) < 0) {
		if (r == -ENOENT) {
			*on = false;
			return 0;
		}
		return r;
	}

	*on = true;
	return 0;
}

int syd_ipc_set_read(bool on)
{
	if (on)
		return syd_stat("/dev/sydbox/core/sandbox/read:deny");
	else
		return syd_stat("/dev/sydbox/core/sandbox/read:allow");
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_get_write(bool *on)
{
	int r;

	if ((r = syd_stat("/dev/sydbox/core/sandbox/write?")) < 0) {
		if (r == -ENOENT) {
			*on = false;
			return 0;
		}
		return r;
	}

	*on = true;
	return 0;
}

int syd_ipc_set_write(bool on)
{
	if (on)
		return syd_stat("/dev/sydbox/core/sandbox/write:deny");
	else
		return syd_stat("/dev/sydbox/core/sandbox/write:allow");
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_get_network(bool *on)
{
	int r;

	if ((r = syd_stat("/dev/sydbox/core/sandbox/network?")) < 0) {
		if (r == -ENOENT) {
			*on = false;
			return 0;
		}
		return r;
	}

	*on = true;
	return 0;
}

int syd_ipc_set_network(bool on)
{
	if (on)
		return syd_stat("/dev/sydbox/core/sandbox/network:deny");
	else
		return syd_stat("/dev/sydbox/core/sandbox/network:allow");
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_allow_exec(const char *pattern, char addrem)
{
	int r;
	char *p;

	if (addrem != '+' || addrem != '-')
		return -EINVAL;
	if (asprintf(&p, "/dev/sydbox/allowlist/exec%c%.256s", addrem, pattern) < 0)
		return -errno;

	r = syd_stat(p);
	free(p);
	return r;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_deny_exec(const char *pattern, char addrem)
{
	int r;
	char *p;

	if (addrem != '+' || addrem != '-')
		return -EINVAL;
	if (asprintf(&p, "/dev/sydbox/denylist/exec%c%.256s", addrem, pattern) < 0)
		return -errno;

	r = syd_stat(p);
	free(p);
	return r;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_allow_read(const char *pattern, char addrem)
{
	int r;
	char *p;

	if (addrem != '+' || addrem != '-')
		return -EINVAL;
	if (asprintf(&p, "/dev/sydbox/allowlist/read%c%.256s", addrem, pattern) < 0)
		return -errno;

	r = syd_stat(p);
	free(p);
	return r;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_deny_read(const char *pattern, char addrem)
{
	int r;
	char *p;

	if (addrem != '+' || addrem != '-')
		return -EINVAL;
	if (asprintf(&p, "/dev/sydbox/denylist/read%c%.256s", addrem, pattern) < 0)
		return -errno;

	r = syd_stat(p);
	free(p);
	return r;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_allow_write(const char *pattern, char addrem)
{
	int r;
	char *p;

	if (addrem != '+' || addrem != '-')
		return -EINVAL;
	if (asprintf(&p, "/dev/sydbox/allowlist/write%c%.256s", addrem, pattern) < 0)
		return -errno;

	r = syd_stat(p);
	free(p);
	return r;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_deny_write(const char *pattern, char addrem)
{
	int r;
	char *p;

	if (addrem != '+' || addrem != '-')
		return -EINVAL;
	if (asprintf(&p, "/dev/sydbox/denylist/write%c%.256s", addrem, pattern) < 0)
		return -errno;

	r = syd_stat(p);
	free(p);
	return r;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_allow_network(const char *pattern, char addrem)
{
	int r;
	char *p;

	if (addrem != '+' || addrem != '-')
		return -EINVAL;
	if (asprintf(&p, "/dev/sydbox/allowlist/network%c%.256s", addrem, pattern) < 0)
		return -errno;

	r = syd_stat(p);
	free(p);
	return r;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_deny_network(const char *pattern, char addrem)
{
	int r;
	char *p;

	if (addrem != '+' || addrem != '-')
		return -EINVAL;
	if (asprintf(&p, "/dev/sydbox/denylist/network%c%.256s", addrem, pattern) < 0)
		return -errno;

	r = syd_stat(p);
	free(p);
	return r;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_filter_exec(const char *pattern, char addrem)
{
	int r;
	char *p;

	if (addrem != '+' || addrem != '-')
		return -EINVAL;
	if (asprintf(&p, "/dev/sydbox/filter/exec%c%.256s", addrem, pattern) < 0)
		return -errno;

	r = syd_stat(p);
	free(p);
	return r;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_filter_read(const char *pattern, char addrem)
{
	int r;
	char *p;

	if (addrem != '+' || addrem != '-')
		return -EINVAL;
	if (asprintf(&p, "/dev/sydbox/filter/read%c%.256s", addrem, pattern) < 0)
		return -errno;

	r = syd_stat(p);
	free(p);
	return r;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_filter_write(const char *pattern, char addrem)
{
	int r;
	char *p;

	if (addrem != '+' || addrem != '-')
		return -EINVAL;
	if (asprintf(&p, "/dev/sydbox/filter/write%c%.256s", addrem, pattern) < 0)
		return -errno;

	r = syd_stat(p);
	free(p);
	return r;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_ipc_filter_network(const char *pattern, char addrem)
{
	int r;
	char *p;

	if (addrem != '+' || addrem != '-')
		return -EINVAL;
	if (asprintf(&p, "/dev/sydbox/filter/network%c%.256s", addrem, pattern) < 0)
		return -errno;

	r = syd_stat(p);
	free(p);
	return r;
}
