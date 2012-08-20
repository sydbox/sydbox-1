/*
 * sydbox/macro.h
 *
 * Copyright (c) 2011 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is:
 *   Copyright 2010 Lennart Poettering
 */

#ifndef MACRO_H
#define MACRO_H 1

#include <stdbool.h>
#include <string.h>

#define PTR_TO_BOOL(p) ((bool) (uintptr_t) (p))
#define BOOL_TO_PTR(u) ((void*) (uintptr_t) (u))

#define PTR_TO_UINT(p) ((unsigned int) ((uintptr_t) (p)))
#define UINT_TO_PTR(u) ((void*) ((uintptr_t) (u)))

#define PTR_TO_UINT32(p) ((uint32_t) ((uintptr_t) (p)))
#define UINT32_TO_PTR(u) ((void*) ((uintptr_t) (u)))

#define PTR_TO_ULONG(p) ((unsigned long) ((uintptr_t) (p)))
#define ULONG_TO_PTR(u) ((void*) ((uintptr_t) (u)))

#define PTR_TO_INT(p) ((int) ((intptr_t) (p)))
#define INT_TO_PTR(u) ((void*) ((intptr_t) (u)))

#define TO_INT32(p) ((int32_t) ((intptr_t) (p)))
#define INT32_TO_PTR(u) ((void*) ((intptr_t) (u)))

#define PTR_TO_LONG(p) ((long) ((intptr_t) (p)))
#define LONG_TO_PTR(u) ((void*) ((intptr_t) (u)))

#define ELEMENTSOF(x) (sizeof(x)/sizeof((x)[0]))

#define STRLEN_LITERAL(s) (sizeof((s)) - 1)
#define STRCMP_LITERAL(s,l) (strncmp((s), (l), sizeof((l)) - 1))

#define STRINGIFY(s) STRINGIFY_(s)
#define STRINGIFY_(s) #s

#endif /* !MACRO_H */
