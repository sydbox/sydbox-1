/*
 * sydbox/arch.h
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef ARCH_H
#define ARCH_H 1

#include "util.h"
#include <seccomp.h>

int32_t arch_from_string(const char *arch);
const char *arch_to_string(uint32_t arch);

#endif
