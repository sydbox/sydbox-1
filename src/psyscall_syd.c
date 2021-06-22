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
