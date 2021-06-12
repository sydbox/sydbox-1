/*
 * sydbox/errno2name.h
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon strace/tests/errno2name.c which is:
 *   Copyright (c) 2016 Dmitry V. Levin <ldv@strace.io>
 *   Copyright (c) 2016-2021 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ERRNO2NAME_H
#define ERRNO2NAME_h 1

const char *errno2name(int err_no);

#endif
