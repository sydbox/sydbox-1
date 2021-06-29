/*
 * sydbox/daemon.c
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef DAEMON_H
#define DAEMON_H

#include <sys/types.h>
#include <sys/stat.h>

bool get_background(void);
const char *get_redirect_stdout(void);
const char *get_redirect_stderr(void);
uid_t get_uid(void);
gid_t get_gid(void);
int get_nice(void);
const char *get_startas(void);
const char *get_root_directory(void);
const char *get_working_directory(void);
mode_t get_umask(void);

void set_background(bool bg);
void set_redirect_stdout(const char *log);
void set_redirect_stderr(const char *log);
void set_uid(uid_t new_uid);
void set_gid(gid_t new_gid);
void set_nice(int new_nice);
void set_startas(const char *new_startas);
void set_root_directory(const char *cwd);
void set_working_directory(char *cwd);
void set_umask(mode_t mode);
void set_ionice(int c, int d);
int set_username(const char *name);
int set_groupname(const char *name);

int change_umask(void);
int change_user(void);
int change_group(void);
int change_root_directory(void);
int change_working_directory(void);
int change_background(void);
int change_nice(void);
int change_ionice(void);

#endif
