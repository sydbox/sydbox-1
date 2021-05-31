/*
 * sydbox/toolong.h
 *
 * Path (longer than PATH_MAX) handling
 *
 * Copyright (c) 2013, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef TOOLONG_H
#define TOOLONG_H

int chdir_long(char *dir);
char *getcwd_long(void);

#endif
