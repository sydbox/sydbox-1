/*
 * sydbox/psyscall_syd.c
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "psyscall_syd.h"

#include <asm/unistd.h>
#include <sys/mman.h>

void *palloc(pid_t pid, size_t size)
{
	return (void *)psyscall(pid, __NR_mmap, 0, size,
				PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
}

int pprctl(pid_t pid, int option, unsigned long arg2, unsigned long arg3,
	   unsigned long arg4, unsigned long arg5)
{
	return psyscall(pid, __NR_prctl, option, arg2, arg3, arg4, arg5);
}
