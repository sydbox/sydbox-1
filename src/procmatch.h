/*
 * sydbox/procmatch.h
 *
 * match proc/ whitelists efficiently
 *
 * Copyright (c) 2014, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PROCMATCH_H
#define PROCMATCH_H 1

#include "sydhash.h"

struct proc_pid {
	pid_t pid;
	char path[sizeof("/proc/%u/***") + sizeof(int)*3 + /*paranoia:*/11];
	UT_hash_handle hh;
};
typedef struct proc_pid proc_pid_t;

int procadd(proc_pid_t **pp, pid_t pid);
int procdrop(proc_pid_t **pp, pid_t pid);
int procmatch(proc_pid_t **pp, const char *path);

#endif
