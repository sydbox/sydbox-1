/*
 * sydbox/psyscall_syd.h
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PSYSCALL_SYD_H
#define PSYSCALL_SYD_H

#include <stddef.h>
#include <sys/types.h>

/* Inject a system call to the given process. */
long psyscall(pid_t pid, long number, ...);

/* Allocate memory from the given processes address space */
void *palloc(pid_t pid, size_t size);

#endif
