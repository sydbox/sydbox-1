/*
 * sydbox/syscall-filter.c
 *
 * Simple seccomp based system call filters
 *
 * Copyright (c) 2013, 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon Tor's sandbox which is
 *   Copyright (c) 2001 Matej Pfajfar.
 *   Copyright (c) 2001-2004, Roger Dingledine.
 *   Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 *   Copyright (c) 2007-2021, The Tor Project, Inc.
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
			     SCMP_A1( SCMP_CMP_EQ, F_SETFL, F_SETFL),
			     SCMP_A2( SCMP_CMP_MASKED_EQ, O_ASYNC, O_ASYNC));
	if (r < 0)
		return r;
	r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fcntl),
			     2,
			     SCMP_A1( SCMP_CMP_EQ, F_SETFL, F_SETFL),
			     SCMP_A2( SCMP_CMP_MASKED_EQ, O_DIRECT, O_DIRECT));
	if (r < 0)
		return r;

#if 0
#define FCNTL_OK_MAX 11
	int ok[FCNTL_OK_MAX] = { F_GETFL, F_SETFL, F_SETOWN, F_SETLK, F_SETLKW,
		F_SETLK64, F_SETLKW64, F_GETFD, F_SETFD, F_DUPFD, F_DUPFD_CLOEXEC };
	r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fcntl),
			     1,
			     SCMP_A1( SCMP_CMP_MASKED_EQ,
	for (unsigned short i = 0; i < FCNTL_OK_MAX; i++) {
		if (r < 0)
			return r;
	}
#endif
	return 0;
}

static int filter_mmap_restrict_shared(int sys_mmap)
{
	int r;

	if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM),
				  sys_mmap, 2,
				  SCMP_A2( SCMP_CMP_MASKED_EQ,
					   PROT_WRITE, PROT_WRITE ),
				  SCMP_A3( SCMP_CMP_MASKED_EQ,
					   MAP_SHARED, MAP_SHARED ))))
		return r;

	return 0;
}

static int filter_mmap_restrict(int sys_mmap)
{
	int r;

	if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ALLOW,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ),
				  SCMP_CMP(3, SCMP_CMP_EQ, MAP_PRIVATE))))
		return r;
	if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ALLOW,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ, PROT_NONE),
				  SCMP_CMP(3, SCMP_CMP_EQ, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE))))
		return r;
	if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ALLOW,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ,
					   PROT_READ|PROT_WRITE),
				  SCMP_CMP(3, SCMP_CMP_EQ, MAP_PRIVATE|MAP_ANONYMOUS))))
		return r;
	if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ALLOW,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ,
					   PROT_READ|PROT_WRITE),
				  SCMP_CMP(3, SCMP_CMP_EQ,MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK))))
		return r;
	if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ALLOW,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ|PROT_WRITE),
				  SCMP_CMP(3, SCMP_CMP_EQ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE))))
		return r;
	if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ALLOW,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ,
					   PROT_READ|PROT_WRITE),
				  SCMP_CMP(3, SCMP_CMP_EQ,
					   MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS))))
		return r;
	if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ALLOW,
				  sys_mmap, 2,
				  SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ|PROT_EXEC),
				  SCMP_CMP(3, SCMP_CMP_EQ,
					   MAP_PRIVATE|MAP_DENYWRITE))))
		return r;
	if ((r = seccomp_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(EPERM),
				  sys_mmap, 0)))
		return r;
	return 0;
}

int filter_mmap(void)
{
	if (sydbox->config.restrict_shared_memory_writable)
		return filter_mmap_restrict_shared(SCMP_SYS(mmap));
	else if (sydbox->config.restrict_mmap)
		return filter_mmap_restrict(SCMP_SYS(mmap));
	else
		return 0;
}

int filter_mmap2(void)
{
	if (sydbox->config.restrict_shared_memory_writable)
		return filter_mmap_restrict_shared(SCMP_SYS(mmap));
	else if (sydbox->config.restrict_mmap)
		return filter_mmap_restrict(SCMP_SYS(mmap));
	else
		return 0;
}
