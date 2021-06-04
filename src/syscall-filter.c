/*
 * sydbox/syscall-filter.c
 *
 * Simple seccomp based system call filters
 *
 * Copyright (c) 2013, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"

#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>

#if SYDBOX_HAVE_SECCOMP
# include "seccomp_old.h"
#endif

int filter_open(void)
{
	int r;

	if (!sydbox->config.restrict_file_control)
		return 0;

	/* O_ASYNC */
	r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(open),
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ, O_ASYNC, O_ASYNC ));
	if (r < 0)
		return r;

	/* O_DIRECT */
	r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(open),
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ, O_DIRECT, O_DIRECT ));
	if (r < 0)
		return r;

	/* O_SYNC */
	r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(open),
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ, O_SYNC, O_SYNC ));
	if (r < 0)
		return r;

	return 0;
}

int filter_openat(void)
{
	int r;

	if (!sydbox->config.restrict_file_control)
		return 0;

	/* O_ASYNC */
	r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(openat),
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ, O_ASYNC, O_ASYNC ));
	if (r < 0)
		return r;

	/* O_DIRECT */
	r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(openat),
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ, O_DIRECT, O_DIRECT ));
	if (r < 0)
		return r;

	/* O_SYNC */
	r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(openat),
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ, O_SYNC, O_SYNC ));
	if (r < 0)
		return r;

	return 0;
}

int filter_fcntl(void)
{
	int r;

	if (!sydbox->config.restrict_file_control)
		return 0;

	r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fcntl),
			     2,
			     SCMP_A1( SCMP_CMP_EQ, F_SETFL ),
			     SCMP_A2( SCMP_CMP_MASKED_EQ, O_ASYNC, O_ASYNC));
	if (r < 0)
		return r;
	r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fcntl),
			     2,
			     SCMP_A1( SCMP_CMP_EQ, F_SETFL ),
			     SCMP_A2( SCMP_CMP_MASKED_EQ, O_DIRECT, O_DIRECT));
	if (r < 0)
		return r;

#define FCNTL_OK_MAX 11
	int ok[FCNTL_OK_MAX] = { F_GETFL, F_SETFL, F_SETOWN, F_SETLK, F_SETLKW,
		F_SETLK64, F_SETLKW64, F_GETFD, F_SETFD, F_DUPFD, F_DUPFD_CLOEXEC };
	for (unsigned short i = 0; i < FCNTL_OK_MAX; i++) {
		r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl),
				     1,
				     SCMP_A1( SCMP_CMP_EQ, ok[i] ));
		if (r < 0)
			return r;
	}
	return 0;
}

int filter_mmap(void)
{
	if (!sydbox->config.restrict_shared_memory_writable)
		return 0;

	return seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mmap),
				2,
				SCMP_A2( SCMP_CMP_MASKED_EQ,
					 PROT_WRITE, PROT_WRITE ),
				SCMP_A3( SCMP_CMP_MASKED_EQ,
					 MAP_SHARED, MAP_SHARED ));
}

int sys_fallback_mmap(syd_process_t *current)
{
	int r;
	int prot, flags;

	if (!sydbox->config.restrict_shared_memory_writable)
		return 0;

	if ((r = syd_read_argument_int(current, 2, &prot)) < 0)
		return r;
	if ((r = syd_read_argument_int(current, 3, &flags)) < 0)
		return r;

	r = 0;
	if (prot & PROT_WRITE && flags & MAP_SHARED)
		r = deny(current, EPERM);
	return r;
}
