/*
 * sydbox/compiler.h
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SYD_COMPILER_H
#define SYD_COMPILER_H

#if !defined(SPARSE) && defined(__GNUC__) && __GNUC__ >= 3
#define SYD_GCC_ATTR(x)     __attribute__(x)
#define SYD_GCC_LIKELY(x)   __builtin_expect(!!(x), 1)
#define SYD_GCC_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
/** Macro for GCC attributes */
#define SYD_GCC_ATTR(x) /* empty */
/** GCC builtin_expect macro */
#define SYD_GCC_LIKELY(x)   (x)
/** GCC builtin_expect macro */
#define SYD_GCC_UNLIKELY(x) (x)
#endif

/** @} */
#endif
