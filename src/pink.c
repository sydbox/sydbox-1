/*
 * sydbox/pink.c
 *
 * pinktrace wrapper functions
 *
 * Copyright (c) 2013, 2014, 2015, 2018 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"
#include "pink.h"
#include "syd.h"
#include <errno.h>
#include <string.h>

#define SYD_RETURN_IF_KILLED(current) do { \
	if (current->flags & SYD_KILLED) { \
		return 0; \
	}} while (0)

static int syd_check(syd_process_t *current, int retval, const char *func_name, size_t line_count)
{
	if (retval == -ESRCH) {
		remove_process_node(current);
	} else if (retval < 0) {
		say("pink: %s:%zu failed for pid:%u", func_name, line_count, current->pid);
		return panic(current);
	}
	return retval;
}
#define SYD_CHECK(current, retval) syd_check((current), (retval), __func__, __LINE__)

int syd_trace_step(syd_process_t *current, int sig)
{
	int r;
	enum syd_step step;

	SYD_RETURN_IF_KILLED(current);

	step = current->trace_step == SYD_STEP_NOT_SET
	       ? sydbox->trace_step
	       : current->trace_step;

	switch (step) {
	case SYD_STEP_SYSCALL:
		r = pink_trace_syscall(current->pid, sig);
		break;
	case SYD_STEP_RESUME:
		r = pink_trace_resume(current->pid, sig);
		break;
	default:
		assert_not_reached();
	}

	return SYD_CHECK(current, r);
}

int syd_trace_listen(syd_process_t *current)
{
	int r;

	SYD_RETURN_IF_KILLED(current);

	r = pink_trace_listen(current->pid);

	return SYD_CHECK(current, r);
}

int syd_trace_detach(syd_process_t *current, int sig)
{
	int r;

	SYD_RETURN_IF_KILLED(current);

	if (sydbox->config.use_seccomp) {
		/*
		 * Careful! Detaching here would cause the untraced
		 * process' observed system calls to return -ENOSYS.
		 */
		r = 0;
	} else {
		r = pink_trace_detach(current->pid, sig);
	}

	r = SYD_CHECK(current, r);
	if (r >= 0)
		bury_process(current);
	return r;
}

int syd_trace_kill(syd_process_t *current, int sig)
{
	int r;

	SYD_RETURN_IF_KILLED(current);

	r = pink_trace_kill(current->pid, -1, sig);

	r = SYD_CHECK(current, r);
	if (r >= 0)
		bury_process(current);
	return r;
}

int syd_trace_setup(syd_process_t *current)
{
	int r;
	int opts = sydbox->trace_options;

	assert(current);

	r = pink_trace_setup(current->pid, opts);

	return SYD_CHECK(current, r);
}

int syd_trace_geteventmsg(syd_process_t *current, unsigned long *data)
{
	int r;

	SYD_RETURN_IF_KILLED(current);

	r = pink_trace_geteventmsg(current->pid, data);

	return SYD_CHECK(current, r);
}

int syd_regset_fill(syd_process_t *current)
{
	int r;

	assert(current);

	r = pink_regset_fill(current->pid, current->regset);
	if (r == 0) {
		pink_read_abi(current->pid, current->regset, &current->abi);
		return 0;
	}
	return SYD_CHECK(current, r);
}

int syd_read_syscall(syd_process_t *current, long *sysnum)
{
	int r;

	SYD_RETURN_IF_KILLED(current);
	BUG_ON(sysnum);

	r = pink_read_syscall(current->pid, current->regset, sysnum);

	return SYD_CHECK(current, r);
}

int syd_read_retval(syd_process_t *current, long *retval, int *error)
{
	int r;

	SYD_RETURN_IF_KILLED(current);

	r = pink_read_retval(current->pid, current->regset, retval, error);

	return SYD_CHECK(current, r);
}

int syd_read_argument(syd_process_t *current, unsigned arg_index, long *argval)
{
	int r;

	SYD_RETURN_IF_KILLED(current);
	BUG_ON(argval);

	r = pink_read_argument(current->pid, current->regset, arg_index, &current->args[arg_index]);
	if (!r) /* success */
		*argval = current->args[arg_index];

	return SYD_CHECK(current, r);
}

int syd_read_argument_int(syd_process_t *current, unsigned arg_index, int *argval)
{
	int r;
	long arg_l;

	SYD_RETURN_IF_KILLED(current);
	BUG_ON(argval);

	r = pink_read_argument(current->pid, current->regset, arg_index, &arg_l);
	if (r == 0) {
		*argval = (int)arg_l;
		return 0;
	}
	return SYD_CHECK(current, r);
}

ssize_t syd_read_string(syd_process_t *current, long addr, char *dest, size_t len)
{
	int r;
	ssize_t rlen;

	SYD_RETURN_IF_KILLED(current);

	errno = 0;
	rlen = pink_read_string(current->pid, current->regset, addr, dest, len);
	if (rlen < 0 && errno == EFAULT) { /* NULL pointer? */
		return -1;
	} else if (rlen >= 0 && (size_t)rlen <= len) { /* partial read? */
		errno = 0;
		dest[rlen] = '\0';
	}

	r = SYD_CHECK(current, -errno);
	return r == 0 ? rlen : r;
}

int syd_read_socket_argument(syd_process_t *current, bool decode_socketcall,
			     unsigned arg_index, unsigned long *argval)
{
	int r;

	SYD_RETURN_IF_KILLED(current);
	BUG_ON(argval);

	r = pink_read_socket_argument(current->pid, current->regset,
				      decode_socketcall,
				      arg_index, argval);
	return SYD_CHECK(current, r);
}

int syd_read_socket_subcall(syd_process_t *current, bool decode_socketcall,
			    long *subcall)
{
	int r;

	SYD_RETURN_IF_KILLED(current);

	r = pink_read_socket_subcall(current->pid, current->regset,
				     decode_socketcall, subcall);
	return SYD_CHECK(current, r);
}

int syd_read_socket_address(syd_process_t *current, bool decode_socketcall,
			    unsigned arg_index, int *fd,
			    struct pink_sockaddr *sockaddr)
{
	int r;

	SYD_RETURN_IF_KILLED(current);
	BUG_ON(sockaddr);

	r = pink_read_socket_address(current->pid, current->regset,
				     decode_socketcall,
				     arg_index, fd, sockaddr);
	return SYD_CHECK(current, r);
}

int syd_write_syscall(syd_process_t *current, long sysnum)
{
	int r;

	SYD_RETURN_IF_KILLED(current);

	r = pink_write_syscall(current->pid, current->regset, sysnum);

	return SYD_CHECK(current, r);
}

int syd_write_retval(syd_process_t *current, long retval, int error)
{
	int r;

	SYD_RETURN_IF_KILLED(current);

	r = pink_write_retval(current->pid, current->regset, retval, error);

	return SYD_CHECK(current, r);
}
