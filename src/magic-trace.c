/*
 * sydbox/magic-trace.c
 *
 * Copyright (c) 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"

#include <stdbool.h>
#include <stdlib.h>
#include "pink.h"

#include "macro.h"

int magic_set_trace_follow_fork(const void *val, syd_process_t *current)
{
	bool v = PTR_TO_BOOL(val);
	if (!v && sydbox->config.use_seccomp) {
		say("can not disable follow_fork with use_seccomp enabled!");
		return MAGIC_RET_OK;
	}
	sydbox->config.follow_fork = v;
	return MAGIC_RET_OK;
}

int magic_query_trace_follow_fork(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.follow_fork);
}

int magic_set_trace_exit_kill(const void *val, syd_process_t *current)
{
#if PINK_HAVE_OPTION_EXITKILL
	sydbox->config.exit_kill = PTR_TO_BOOL(val);
#else
	say("PTRACE_O_EXITKILL not supported, ignoring magic");
#endif
	return MAGIC_RET_OK;
}

int magic_query_trace_exit_kill(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.exit_kill);
}

int magic_set_trace_use_ptrace(const void *val, syd_process_t *current)
{
#if SYDBOX_HAVE_SECCOMP
	sydbox->config.use_ptrace = PTR_TO_BOOL(val);
#else
	say("seccomp support not enabled, ignoring magic");
#endif
	return MAGIC_RET_OK;
}

int magic_query_trace_use_ptrace(syd_process_t *current)
{
#if SYDBOX_HAVE_SECCOMP
	return sydbox->config.use_ptrace;
#else
	return MAGIC_RET_NOT_SUPPORTED;
#endif
}

int magic_set_trace_use_seccomp(const void *val, syd_process_t *current)
{
#if PINK_ARCH_AARCH64 || PINK_ARCH_ARM
	return MAGIC_RET_OK;
#else
	bool v = PTR_TO_BOOL(val);
	sydbox->config.use_seccomp = PTR_TO_BOOL(val);
	if (v)
		sydbox->config.follow_fork = true;
	return MAGIC_RET_OK;
#endif
}

int magic_query_trace_use_seccomp(syd_process_t *current)
{
	return sydbox->config.use_seccomp;
}

int magic_set_trace_use_notify(const void *val, syd_process_t *current)
{
	sydbox->config.use_notify = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_trace_use_notify(syd_process_t *current)
{
	return sydbox->config.use_notify;
}

int magic_set_trace_use_seize(const void *val, syd_process_t *current)
{
#if PINK_HAVE_SEIZE && PINK_HAVE_INTERRUPT && PINK_HAVE_LISTEN
	sydbox->config.use_seize = PTR_TO_BOOL(val);
#else
	say("PTRACE_SEIZE not supported, ignoring magic");
#endif
	return MAGIC_RET_OK;
}

int magic_query_trace_use_seize(syd_process_t *current)
{
#if PINK_HAVE_SEIZE && PINK_HAVE_INTERRUPT && PINK_HAVE_LISTEN
	return sydbox->config.use_seize;
#else
	return MAGIC_RET_NOT_SUPPORTED;
#endif
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
