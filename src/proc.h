/*
 * sydbox/proc.h
 *
 * /proc related utilities
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is:
 *   Copyright (C) 2010 Lennart Poettering
 * Distributed under the terms of the GNU Lesser General Public License v2.1 or later
 */

#ifndef PROC_H
#define PROC_H 1

#include <stdbool.h>
#include <sys/types.h>

struct proc_statinfo {
	int pid;
	int ppid;
	int pgrp;
	int session;
	int tty_nr;
	int tpgid;
	long nice;
	long num_threads;
	char state;
	char comm[32];
};

int syd_proc_stat(int pfd, struct proc_statinfo *info);
int syd_proc_cwd(int pfd_cwd, bool use_toolong_hack, char **buf);

int syd_proc_socket_inode(int pfd_fd, int socket_fd, unsigned long long *inode);
int syd_proc_socket_port(unsigned long long inode, bool ipv4, int *port);

#if 0
int proc_fd(pid_t pid, int dfd, char **buf);
int proc_cmdline(pid_t pid, size_t max_length, char **buf);
int proc_comm(pid_t pid, char **name);

int proc_environ(pid_t pid);
#endif

#endif /* !PROC_H */
