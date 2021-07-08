/*
 * sydbox/pathdecode.h
 *
 * Copyright (c) 2012, 2013, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PATHDECODE_H
#define PATHDECODE_H 1

#include <stdint.h>
#include "syd-box.h"

int path_decode(syd_process_t *current, uint8_t arg_index, char **buf);
int path_prefix(syd_process_t *current, uint8_t arg_index, char **buf);

#endif
