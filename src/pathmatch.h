/*
 * sydbox/pathmatch.h
 *
 * Copyright (c) 2012, 2013, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PATHMATCH_H
#define PATHMATCH_H 1

#include <stdbool.h>
#include "util.h"

#define WILD3_SUFFIX "/***"

enum no_wildcard {
	NO_WILDCARD_LITERAL,
	NO_WILDCARD_PREFIX,
};
static const char *const no_wildcard_table[] = {
	[NO_WILDCARD_LITERAL] = "literal",
	[NO_WILDCARD_PREFIX] = "prefix"
};
DEFINE_STRING_TABLE_LOOKUP(no_wildcard, int)

void pathmatch_set_case(bool case_sensitive);
bool pathmatch_get_case(void);

void pathmatch_set_no_wildcard(enum no_wildcard no_wild);
enum no_wildcard pathmatch_get_no_wildcard(void);

int pathmatch_expand(const char *pattern, char ***buf);
bool pathmatch(const char *pattern, const char *text);

#endif
